/*
 * Copyright (C) 2013 Fujitsu.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <string.h>

#include "kerncompat.h"
#include "list.h"
#include "ctree.h"
#include "extent-cache.h"
#include "disk-io.h"
#include "volumes.h"
#include "transaction.h"
#include "crc32c.h"
#include "utils.h"
#include "version.h"
#include "recover-chunk.h"
#include "extent-cache.h"

BTRFS_SETGET_STACK_FUNCS(stack_dev_extent_chunk_objectid,
			  struct btrfs_dev_extent, chunk_objectid, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_extent_chunk_offset,
			  struct btrfs_dev_extent, chunk_offset, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_extent_length, struct btrfs_dev_extent,
			  length, 64);

static inline unsigned long chunk_record_size(int num_stripes)
{
	BUG_ON(num_stripes == 0);
	return sizeof(struct chunk_record) +
		sizeof(struct stripe) * num_stripes;
}

static inline struct block_group_record *cache_bg_entry(
		struct cache_extent *cache)
{
	if (!cache)
		return NULL;
	return container_of(cache, struct block_group_record, cache);
}

static inline struct chunk_record *cache_chunk_entry(
		struct cache_extent *cache)
{
	if (!cache)
		return NULL;
	return container_of(cache, struct chunk_record, cache);
}

static inline struct dev_extent_record *cache_devext_entry(
		struct cache_dev_extent *cache)
{
	if (!cache)
		return NULL;
	return container_of(cache, struct dev_extent_record, cache);
}

inline struct result_record *cache_result_entry(
		struct cache_extent *cache)
{
	if (!cache)
		return NULL;
	return container_of(cache, struct result_record, cache);
}

static inline struct cache_extent *rb_cache_entry(struct rb_node *node)
{
	return rb_entry(node, struct cache_extent, rb_node);
}

static inline struct cache_dev_extent *rb_devext_entry(struct rb_node *node)
{
	return container_of(node, struct cache_dev_extent, node);
}

#define FREE_CACHE_BASED_TREE(name, record_type)			\
static void free_##name##_tree(struct cache_tree *tree)			\
{									\
	struct cache_extent *n;						\
	struct record_type *entry;					\
	for (n = find_first_cache_extent(tree, 0); n;			\
	     n = find_first_cache_extent(tree, 0)) {			\
		entry = cache_##name##_entry(n);			\
		remove_cache_extent(tree, n);				\
		free(entry);						\
	}								\
}
FREE_CACHE_BASED_TREE(bg, block_group_record);
FREE_CACHE_BASED_TREE(chunk, chunk_record);

static void free_devext_tree(struct dev_extent_tree *devext_tree)
{
	struct rb_node *n;
	struct cache_dev_extent *cache_entry;
	struct dev_extent_record *devext_entry;
	for (n = rb_first(&devext_tree->root); n;
	     n = rb_first(&devext_tree->root)) {
		cache_entry = rb_devext_entry(n);
		devext_entry = cache_devext_entry(cache_entry);
		remove_cache_dev_extent(devext_tree, cache_entry);
		free(devext_entry);
	}

}
struct recover_control *init_recover_control()
{
	struct recover_control *rc;

	rc = malloc(sizeof(struct recover_control));
	if (!rc)
		return NULL;

	memset(rc, 0, sizeof(struct recover_control));
	cache_tree_init(&rc->bg);
	cache_tree_init(&rc->chunk);
	dev_extent_tree_init(&rc->devext);

	return rc;
}

int free_recover_control(struct recover_control *rc)
{
	if (!rc)
		return -1;

	free_bg_tree(&rc->bg);
	free_chunk_tree(&rc->chunk);
	free_devext_tree(&rc->devext);
	free(rc);

	return 0;
}

struct block_group_record *find_bg_record(struct cache_tree *tree, u64 start,
					  u64 size)
{
	struct cache_extent *cache_entry;
	cache_entry = find_cache_extent(tree, start, size);
	return cache_bg_entry(cache_entry);
}

int insert_bg_record(struct cache_tree *tree, struct btrfs_item *item,
		     struct btrfs_block_group_item *data, u64 gen)
{
	int ret = 0;
	struct block_group_record *bg_entry;
	struct block_group_record *bg_find_entry;

	bg_entry = malloc(sizeof(struct block_group_record));
	if (!bg_entry)
		return -ENOMEM;
	bg_entry->objectid = btrfs_disk_key_objectid(&item->key);
	bg_entry->type = btrfs_disk_key_type(&item->key);
	bg_entry->offset = btrfs_disk_key_offset(&item->key);
	bg_entry->generation = gen;
	bg_entry->flags = btrfs_block_group_flags(data);
	bg_entry->cache.start = bg_entry->objectid;
	bg_entry->cache.size = bg_entry->offset;

	bg_find_entry = find_bg_record(tree, bg_entry->objectid,
			bg_entry->offset);
	if (bg_find_entry) {
		/*check the generation and replace if needed*/
		if (bg_find_entry->generation > bg_entry->generation)
			goto free_out;
		/*FIXME:need better method to deal with duplicant generation*/
		if (bg_find_entry->generation == bg_entry->generation) {
			ret = -EIO;
			goto free_out;
		}
		/*newer generation found, replace*/
		rb_replace_node(&bg_find_entry->cache.rb_node,
				&bg_entry->cache.rb_node,
				&tree->root);
		free(bg_find_entry);
		goto out;
	}
	/*new record, add*/
	ret = insert_cache_extent(tree, &bg_entry->cache);
	if (ret < 0)
		goto free_out;
	goto out;
free_out:
	free(bg_entry);
out:
	return ret;
}

struct chunk_record *find_chunk_record(struct cache_tree *tree,
		u64 start, u64 size)
{
	struct cache_extent *cache_entry;
	cache_entry = find_cache_extent(tree, start, size);
	return cache_chunk_entry(cache_entry);
}

int insert_chunk_record(struct cache_tree *tree, struct btrfs_item *item,
		struct btrfs_chunk *data, u64 gen)
{
	int ret = 0;
	int i;
	struct chunk_record *chunk_entry;
	struct chunk_record *chunk_find_entry;
	struct btrfs_stripe *stripe;

	chunk_entry = malloc(chunk_record_size(
				btrfs_stack_chunk_num_stripes(data)));
	if (!chunk_entry)
		return -ENOMEM;
	chunk_entry->objectid = btrfs_disk_key_objectid(&item->key);
	chunk_entry->type = btrfs_disk_key_type(&item->key);
	chunk_entry->offset = btrfs_disk_key_offset(&item->key);
	chunk_entry->generation = gen;
	chunk_entry->length = btrfs_stack_chunk_length(data);
	chunk_entry->owner = btrfs_stack_chunk_owner(data);
	chunk_entry->stripe_len = btrfs_stack_chunk_stripe_len(data);
	chunk_entry->type_flags = btrfs_stack_chunk_type(data);
	chunk_entry->io_width = btrfs_stack_chunk_io_width(data);
	chunk_entry->io_align = btrfs_stack_chunk_io_align(data);
	chunk_entry->sector_size = btrfs_stack_chunk_sector_size(data);
	chunk_entry->num_stripes = btrfs_stack_chunk_num_stripes(data);
	chunk_entry->sub_stripes = btrfs_stack_chunk_sub_stripes(data);
	for (i = 0, stripe = &data->stripe; i < chunk_entry->num_stripes;
	     i++, stripe++) {
		chunk_entry->stripes[i].devid = btrfs_stack_stripe_devid(
				stripe + i);
		chunk_entry->stripes[i].offset = btrfs_stack_stripe_offset(
				stripe + i);
		memcpy(&chunk_entry->stripes[i].dev_uuid,
				(stripe + i)->dev_uuid, BTRFS_UUID_SIZE);
	}
	chunk_entry->cache.start = chunk_entry->offset;
	chunk_entry->cache.size = chunk_entry->length;

	chunk_find_entry = find_chunk_record(tree, chunk_entry->offset,
			chunk_entry->length);
	if (chunk_find_entry) {
		if (chunk_find_entry->generation > chunk_entry->generation)
			goto free_out;
		/*FIXME:need better method to deal with duplicant generation*/
		if (chunk_find_entry->generation == chunk_entry->generation) {
			ret = -EIO;
			goto free_out;
		}
		rb_replace_node(&chunk_find_entry->cache.rb_node,
				&chunk_entry->cache.rb_node,
				&tree->root);
		goto out;
	}
	ret = insert_cache_extent(tree, &chunk_entry->cache);
	if (ret < 0)
		goto free_out;
	goto out;
free_out:
	free(chunk_entry);
out:
	return ret;
}

struct dev_extent_record *find_devext_record(struct dev_extent_tree *tree,
		u64 devno, u64 offset)
{
	struct cache_dev_extent *cache_entry;
	cache_entry = lookup_cache_dev_extent(tree, devno, offset, 1);
	return cache_devext_entry(cache_entry);
}

int insert_devext_record(struct dev_extent_tree *tree, struct btrfs_item *item,
		struct btrfs_dev_extent *data, u64 gen)
{
	int ret = 0;
	struct dev_extent_record *devext_entry;
	struct dev_extent_record *devext_find_entry;

	devext_entry = malloc(sizeof(struct dev_extent_record));
	if (!devext_entry)
		return -ENOMEM;

	devext_entry->objectid = btrfs_disk_key_objectid(&item->key);
	devext_entry->type = btrfs_disk_key_type(&item->key);
	devext_entry->offset = btrfs_disk_key_offset(&item->key);
	devext_entry->generation = gen;
	devext_entry->chunk_objecteid = btrfs_stack_dev_extent_chunk_objectid(
			data);
	devext_entry->chunk_offset = btrfs_stack_dev_extent_chunk_offset(
			data);
	devext_entry->length = btrfs_stack_dev_extent_length(data);
	devext_entry->cache.devid = devext_entry->objectid;
	devext_entry->cache.offset = devext_entry->offset;
	devext_find_entry = find_devext_record(tree, devext_entry->objectid,
			devext_entry->offset);
	INIT_LIST_HEAD(&devext_entry->list);
	if (devext_find_entry) {
		if (devext_find_entry->generation > devext_entry->generation)
			goto free_out;
		/*FIXME:need better method ot deal with duplicant generation*/
		if (devext_find_entry->generation == devext_entry->generation) {
			ret = -EIO;
			goto free_out;
		}
		rb_replace_node(&devext_find_entry->cache.node,
				&devext_entry->cache.node,
				&tree->root);
		free(devext_find_entry);
		goto out;
	}
	ret = insert_cache_dev_extent(tree, &devext_entry->cache);
	if (ret < 0)
		goto free_out;
	goto out;
free_out:
	free(devext_entry);
out:
	return ret;
}

struct result_record *find_result_item(struct cache_tree *tree,
		u64 start, u64 size)
{
	struct cache_extent *cache_entry;
	cache_entry = find_cache_extent(tree, start, size);
	return cache_result_entry(cache_entry);
}

static void __update_devext_list(struct dev_extent_record *dest,
		struct dev_extent_record *src)
{
	struct dev_extent_record *cur;
	int found = 0;
	list_for_each_entry(cur, &dest->list, list) {
		if (cur->objectid == src->objectid &&
		    cur->chunk_offset == src->chunk_offset) {
			found = 1;
			break;
		}
	}
	if (!found)
		list_add(&src->list, &dest->list);
}

static int __check_devext_full(struct result_record *rec)
{
	u16 n = 1;
	struct list_head *cur;

	if (!rec->devext)
		return 0;

	list_for_each(cur, &rec->devext->list)
		n++;

	if (n == rec->chunk->num_stripes)
		return 1;

	return 0;
}

int update_result_record(struct cache_tree *tree, struct result_record *data)
{
	int ret = 0;
	struct result_record *result_entry;
	struct result_record *dest;

	result_entry = find_result_item(tree, data->start, data->size);
	if (result_entry) {
		/*update the existing one*/
		if (!(result_entry->recover_flags & RECOVER_CHUNK) &&
		    data->recover_flags & RECOVER_CHUNK)
			result_entry->chunk = data->chunk;

		if (data->recover_flags & RECOVER_DEVEXT) {
			if (!result_entry->devext)
				result_entry->devext = data->devext;
			else
				__update_devext_list(result_entry->devext,
						     data->devext);
		}

		if (!(result_entry->recover_flags & RECOVER_BG) &&
		    (data->recover_flags & RECOVER_BG))
			result_entry->bg = data->bg;

		result_entry->recover_flags |= data->recover_flags;
		if (__check_devext_full(result_entry))
			result_entry->recover_flags |= RECOVER_DEVEXT_FULL;

		return 0;
	}
	dest = malloc(sizeof(struct result_record));
	if (!dest)
		return -ENOMEM;
	memset(dest, 0, sizeof(struct result_record));

	dest->start = data->start;
	dest->size = data->size;

	dest->cache.start = dest->start;
	dest->cache.size = dest->size;
	if (data->recover_flags & RECOVER_CHUNK && data->chunk)
		dest->chunk = data->chunk;
	if (data->recover_flags & RECOVER_DEVEXT && data->devext)
		dest->devext = data->devext;
	if (data->recover_flags & RECOVER_BG && data->bg)
		dest->bg = data->bg;
	dest->recover_flags = data->recover_flags;
	if (__check_devext_full(dest))
		dest->recover_flags |= RECOVER_DEVEXT_FULL;
	ret = insert_cache_extent(tree, &dest->cache);
	if (ret < 0)
		goto free_out;
	return 0;
free_out:
	free(dest);
	return ret;
}

void print_bg_tree(struct cache_tree *tree)
{
	struct cache_extent *n;
	struct block_group_record *entry;
	for (n = find_first_cache_extent(tree, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_bg_entry(n);
		printf("start:\t%llu\n", entry->objectid);
		printf("length:\t%llu\n", entry->offset);
		printf("flags:\t%llu\n", entry->flags);
		printf("\n");
	}
}

void print_stripe(struct stripe *data)
{
	printf("stripe devid:\t%llu\n", data->devid);
	printf("stripe offset:\t%llu\n", data->offset);
	printf("\n");
}

void print_chunk_tree(struct cache_tree *tree)
{
	struct cache_extent *n;
	struct chunk_record *entry;
	int i;
	for (n = find_first_cache_extent(tree, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_chunk_entry(n);
		printf("start:\t%llu\n", entry->offset);
		printf("length:\t%llu\n", entry->length);
		printf("type:\t%llu\n", entry->type_flags);
		printf("num_stripes:\t%u\n", entry->num_stripes);
		printf("\n");
		printf("stripe data:\n");
		for (i = 0; i < entry->num_stripes; i++)
			print_stripe(&entry->stripes[i]);
	}
}

void print_devext_tree(struct dev_extent_tree *tree)
{
	struct cache_dev_extent *n;
	struct dev_extent_record *entry;
	for (n = find_first_cache_dev_extent(tree, 0); n;
	     n = next_cache_dev_extent(n)) {
		entry = cache_devext_entry(n);
		printf("devid:\t%llu\n", entry->objectid);
		printf("start:\t%llu\n", entry->offset);
		printf("chunk_offset:\t%llu\n", entry->chunk_offset);
		printf("length:\t%llu\n", entry->length);
		printf("\n");
	}
}

void print_rc(struct recover_control *rc)
{
	struct list_head *cur;
	struct btrfs_device *dev;

	printf("===================================\n");
	printf("recover control data:\n");
	printf("silent:\t%d\n", rc->silent);
	printf("sectorsize:\t%d\n", rc->sectorsize);
	printf("leafsize:\t%d\n", rc->leafsize);
	printf("generation:\t%llu\n", rc->generation);
	printf("chunk_root_generation:\t%llu\n", rc->chunk_root_generation);
	printf("\n");
	printf("===================================\n");

	printf("devices list:\n");
	list_for_each(cur, &rc->fs_devices->devices) {
		dev = list_entry(cur, struct btrfs_device, dev_list);
		printf("device path:\t%s\n", dev->name);
	}

	printf("\n");
	printf("===================================\n");
	printf("block group item data:\n");
	print_bg_tree(&rc->bg);
	printf("\n");
	printf("===================================\n");
	printf("chunk data:\n");
	print_chunk_tree(&rc->chunk);
	printf("\n");
	printf("===================================\n");
	printf("device extent data:\n");
	print_devext_tree(&rc->devext);
}

/*The real chunk rebuild should go here */
int __check_scan_result(struct recover_control *rc)
{
	struct cache_extent *n;
	struct result_record *entry;

	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		if (!((entry->recover_flags & RECOVER_CHUNK) &&
		      (entry->recover_flags & RECOVER_BG) &&
		      (entry->recover_flags & RECOVER_DEVEXT_FULL))) {
			printf("Not enough data for recover chunk:\n");
			printf("chunk start:\t%llu:\n", entry->start);
			printf("chunk size:\t%llu:\n", entry->size);
			return -1;
		}
	}
	return 0;
}
int check_scan_result(struct recover_control *rc)
{
	int ret = 0;
	struct cache_extent *ce;
	struct cache_dev_extent *cde;
	struct chunk_record *chunk;
	struct block_group_record *bg;
	struct dev_extent_record *devext;
	struct result_record dest;

	for (ce = find_first_cache_extent(&rc->chunk, 0); ce;
	     ce = next_cache_extent(ce)) {
		memset(&dest, 0, sizeof(struct result_record));
		chunk = cache_chunk_entry(ce);
		dest.start = chunk->offset;
		dest.size = chunk->length;
		dest.recover_flags |= RECOVER_CHUNK;
		dest.chunk = chunk;
		dest.cache.start = chunk->offset;
		dest.cache.size = chunk->length;

		ret = update_result_record(&rc->result, &dest);
		if (ret < 0)
			return ret;
	}

	for (cde = find_first_cache_dev_extent(&rc->devext, 0); cde;
	     cde = next_cache_dev_extent(cde)) {
		memset(&dest, 0, sizeof(struct result_record));
		devext = cache_devext_entry(cde);
		dest.start = devext->offset;
		dest.size = devext->length;
		dest.recover_flags |= RECOVER_DEVEXT;
		dest.devext = devext;
		dest.cache.start = devext->chunk_offset;
		dest.cache.size = devext->length;

		ret = update_result_record(&rc->result, &dest);
		if (ret < 0)
			return ret;
	}

	for (ce = find_first_cache_extent(&rc->bg, 0); ce;
	     ce = next_cache_extent(ce)) {
		memset(&dest, 0, sizeof(struct result_record));
		bg = cache_bg_entry(ce);
		dest.start = bg->objectid;
		dest.size = bg->offset;
		dest.recover_flags |= RECOVER_BG;
		dest.bg = bg;
		dest.cache.start = bg->objectid;
		dest.cache.size = bg->offset;

		ret = update_result_record(&rc->result, &dest);
		if (ret < 0)
			return ret;
	}
	return __check_scan_result(rc);
}

void print_result(struct recover_control *rc)
{
	u64 result_nr = 0;
	u64 confirmed = 0;
	u64 unsure = 0;
	struct cache_extent *n;
	struct result_record *entry;

	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n))
		result_nr++;

	printf("Total number of chunks:\t%lld\n", result_nr);
	printf("===========================\n");
	printf("result data:\n");
	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		printf("chunk start:\t%llu\n", entry->start);
		printf("chunk len:\t%llu\n", entry->size);
		printf("recover flags:\t%u\n", entry->recover_flags);
		printf("\n");
		if ((entry->recover_flags & RECOVER_CHUNK) &&
		    (entry->recover_flags & RECOVER_DEVEXT_FULL) &&
		    (entry->recover_flags & RECOVER_BG))
			confirmed++;
		else
			unsure++;
	}
	printf("Confirmed chunks:\t%lld\n", confirmed);
	printf("Unsure chunks:\t%lld\n", unsure);
}
