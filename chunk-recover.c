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

#include "kerncompat.h"
#include "list.h"
#include "radix-tree.h"
#include "ctree.h"
#include "extent-cache.h"
#include "disk-io.h"
#include "volumes.h"
#include "transaction.h"
#include "crc32c.h"
#include "utils.h"
#include "version.h"
#include "recover-chunk.h"

BTRFS_SETGET_STACK_FUNCS(stack_header_nritems, struct btrfs_header,
			  nritems, 32);
BTRFS_SETGET_STACK_FUNCS(stack_header_generation, struct btrfs_header,
			  generation, 64);

static void print_device(struct recover_control *rc)
{
	struct list_head *cur;
	struct list_head *head;
	struct btrfs_device *dev;
	char str[37];

	printf("device list:\n");
	head = &rc->fs_devices->devices;
	list_for_each(cur, head) {
		dev = list_entry(cur, struct btrfs_device, dev_list);
		uuid_unparse(dev->uuid, str);
		printf("devid:%llu, name:%s, uuid:%s\n",
		       dev->devid, dev->name, str);
	}
	printf("\n");
}

static int result_is_empty(struct recover_control *rc)
{
	if (rc->result.root.rb_node)
		return 0;
	else
		return 1;
}

static int match_one_result(struct btrfs_trans_handle *trans,
		struct recover_control *rc, struct btrfs_root *root,
		struct result_record *result)
{
	int ret = 0;
	int i;
	int slot;
	u64 offset;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct btrfs_root *dev_root;
	/*struct btrfs_chunk *chunk;*/
	struct stripe *stripe;
	struct btrfs_dev_extent *dev_extent;
	struct extent_buffer *l;
	struct chunk_record *citem;

	dev_root = root->fs_info->dev_root;
	offset = result->start;
	citem = result->chunk;
	for (i = 0; i < citem->num_stripes; i++) {
		stripe = &citem->stripes[i];
		key.objectid = stripe->devid;
		key.offset = stripe->offset;
		key.type = BTRFS_DEV_EXTENT_KEY;

		path = btrfs_alloc_path();
		if (!path)
			return -ENOMEM;
		btrfs_init_path(path);
		ret = btrfs_search_slot(trans, dev_root, &key, path, 0, 0);
		if (ret) {
			btrfs_release_path(root, path);
			return ret;
		}
		l = path->nodes[0];
		slot = path->slots[0];
		dev_extent = btrfs_item_ptr(l, slot, struct btrfs_dev_extent);
		if (offset != btrfs_dev_extent_chunk_offset(l, dev_extent)) {
			printf("device tree unmatch with chunks\n"
			       "dev_extent[%llu, %llu], chunk[%llu, %llu]\n",
			       btrfs_dev_extent_chunk_offset(l, dev_extent),
			       btrfs_dev_extent_length(l, dev_extent),
			       offset, citem->length);
			btrfs_release_path(root, path);
			ret = -1;
			return ret;
		}
		btrfs_release_path(root, path);
	}
	return ret;
}

static int match_results(struct btrfs_trans_handle *trans,
		struct recover_control *rc,
		struct btrfs_root *root)
{
	int ret = 0;
	struct cache_extent *n;
	struct result_record *entry;
	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		ret = match_one_result(trans, rc, root, entry);
		if (ret)
			return ret;
	}
	return ret;
}

static int extract_extent_tree(struct recover_control *rc, int fd, u64 bytenr)
{
	struct btrfs_header *header;
	struct btrfs_item *item;
	struct btrfs_block_group_item *bg_item;
	char *buf;
	char *start;
	int ret = 0;
	int i;
	u32 nritems;
	u32 offset;
	u64 generation;

	buf = malloc(rc->leafsize);
	if (!buf)
		return -ENOMEM;

	if (pread64(fd, buf, rc->leafsize, bytenr) != rc->leafsize) {
		ret = -EIO;
		goto out;
	}

	header = (struct btrfs_header *)buf;
	nritems = btrfs_stack_header_nritems(header);
	start = buf + sizeof(struct btrfs_header);
	offset = 0;
	generation = btrfs_stack_header_generation(header);
	for (i = 0; i < nritems; i++) {
		item = (struct btrfs_item *)(start + offset);
		if (btrfs_disk_key_type(&item->key) ==
				BTRFS_BLOCK_GROUP_ITEM_KEY) {
			bg_item = (typeof(bg_item))start + item->offset;
			ret = insert_bg_record(&rc->bg, item, bg_item,
					       generation);
			if (ret < 0)
				goto out;
		}
		offset += sizeof(struct btrfs_item);
	}
out:
	free(buf);
	return ret;
}

static int extract_chunk_tree(struct recover_control *rc, int fd, u64 bytenr)
{
	struct btrfs_header *header;
	struct btrfs_item *item;
	struct btrfs_chunk *chunk;
	char *buf;
	char *start;
	int ret = 0;
	int i;
	u32 nritems;
	u32 offset = 0;
	u64 generation;

	buf = malloc(rc->leafsize);
	if (!buf)
		return -ENOMEM;
	if (pread64(fd, buf, rc->leafsize, bytenr) != rc->leafsize) {
		ret = -EIO;
		goto out;
	}
	header = (struct btrfs_header *) buf;
	nritems = btrfs_stack_header_nritems(header);
	start = buf + sizeof(struct btrfs_header);
	offset = 0;
	generation = btrfs_stack_header_generation(header);

	for (i = 0; i < nritems; i++) {
		item = (struct btrfs_item *) (start + offset);
		if (btrfs_disk_key_type(&item->key) == BTRFS_CHUNK_ITEM_KEY) {
			chunk = (typeof(chunk))start + item->offset;
			ret = insert_chunk_record(&rc->chunk, item, chunk,
						  generation);
			if (ret < 0)
				goto out;
		}
		offset += sizeof(struct btrfs_item);
	}
out:
	free(buf);
	return ret;
}

static int extract_dev_tree(struct recover_control *rc, int fd, u64 bytenr)
{
	struct btrfs_header *header;
	struct btrfs_item *item;
	struct btrfs_dev_extent *dev_extent;
	char *buf;
	char *start;
	int ret = 0;
	int i;
	u32 nritems;
	u32 offset = 0;
	u64 generation;

	buf = malloc(rc->leafsize);
	if (!buf)
		return -ENOMEM;

	ret = pread64(fd, buf, rc->leafsize, bytenr);
	if (ret != rc->leafsize) {
		ret = -EIO;
		goto out;
	}

	header = (struct btrfs_header *) buf;
	nritems = btrfs_stack_header_nritems(header);
	start = buf + sizeof(struct btrfs_header);
	offset = 0;
	generation = btrfs_stack_header_generation(header);
	for (i = 0; i < nritems; i++) {
		item = (struct btrfs_item *) (start + offset);
		if (btrfs_disk_key_type(&item->key) == BTRFS_DEV_EXTENT_KEY) {
			dev_extent = (typeof(dev_extent))start + item->offset;
			ret = insert_devext_record(&rc->devext, item,
						   dev_extent, generation);
			if (ret < 0)
				goto out;
		}
		offset += sizeof(struct btrfs_item);
	}
	ret = 0;
out:
	free(buf);
	return ret;
}

static int scan_one_device_needed_data(struct recover_control *rc,
				       int fd)
{
	int ret = 0;
	char *buf;
	char csum_result[BTRFS_CSUM_SIZE];
	u64 crc;
	u64 bytenr;
	u64 sectorsize;
	struct btrfs_header *header;
	struct btrfs_super_block *sb;

	sectorsize = rc->sectorsize;
	buf = malloc(sectorsize);
	if (!buf)
		return -ENOMEM;

	sb = malloc(sizeof(struct btrfs_super_block));
	if (!sb) {
		free(buf);
		return -ENOMEM;
	}

	ret = btrfs_read_dev_super(fd, sb, BTRFS_SUPER_INFO_OFFSET);
	if (ret) {
		ret = -ENOENT;
		goto out;
	}

	bytenr = 0;
	while (1) {
		ret = 0;
		memset(buf, 0, sectorsize);
		if (pread64(fd, buf, sectorsize, bytenr) < sectorsize)
			break;

		header = (struct btrfs_header *)buf;
		if (!memcpy(header->fsid, rc->fs_devices->fsid,
			    BTRFS_FSID_SIZE)) {
			bytenr += rc->sectorsize;
			continue;
		}
		crc = ~(u32)0;
		crc = btrfs_csum_data(NULL, (char *)(buf + BTRFS_CSUM_SIZE),
				crc, rc->leafsize - BTRFS_CSUM_SIZE);
		btrfs_csum_final(crc, csum_result);
		if (!memcmp(header->csum, csum_result, BTRFS_CSUM_SIZE)) {
			bytenr += rc->sectorsize;
			continue;
		}

		if (header->level != 0)
			goto next_node;

		switch (header->owner) {
		case BTRFS_EXTENT_TREE_OBJECTID:
			/* different tree use different generation */
			if (header->generation > rc->generation)
				break;
			ret = extract_extent_tree(rc, fd, bytenr);
			if (ret < 0)
				goto out;
			break;
		case BTRFS_CHUNK_TREE_OBJECTID:
			if (header->generation > rc->chunk_root_generation)
				break;
			ret = extract_chunk_tree(rc, fd, bytenr);
			if (ret < 0)
				goto out;
			break;
		case BTRFS_DEV_TREE_OBJECTID:
			if (header->generation > rc->generation)
				break;
			ret = extract_dev_tree(rc, fd, bytenr);
			if (ret < 0)
				goto out;
			break;
		}
next_node:
		bytenr += rc->leafsize;
		continue;
	}
out:
	free(sb);
	free(buf);
	return ret;
}

static int scan_devices(struct recover_control *rc)
{
	int ret = 0;
	int fd;
	struct list_head *cur;
	struct btrfs_device *dev;
	if (!rc)
		return -EFAULT;
	list_for_each(cur, &rc->fs_devices->devices) {
		dev = list_entry(cur, struct btrfs_device, dev_list);
		fd = open(dev->name, O_RDONLY, 0600);
		if (!fd)
			return -ENOENT;
		ret = scan_one_device_needed_data(rc, fd);
		close(fd);
		if (ret)
			return ret;
	}
	return ret;
}

static int map_one_chunk(struct btrfs_root *root, struct result_record *result)
{
	int ret = 0;
	int i;
	u64 devid;
	u8 uuid[BTRFS_UUID_SIZE];
	u16 num_stripes;
	struct btrfs_mapping_tree *map_tree;
	struct map_lookup *map;
	struct stripe *stripe;
	/*struct btrfs_chunk *chunk;*/
	struct chunk_record *citem = result->chunk;

	map_tree = &root->fs_info->mapping_tree;
	num_stripes = result->chunk->num_stripes;
#define map_lookup_size(n) (sizeof(struct map_lookup) + \
			    (sizeof(struct btrfs_bio_stripe) * (n)))
	map = malloc(map_lookup_size(num_stripes));
	if (!map)
		return -ENOMEM;
	map->ce.start = result->start;
	map->ce.size = result->size;
	map->num_stripes = num_stripes;
	map->io_width = citem->io_width;
	map->io_align = citem->io_align;
	map->sector_size = citem->sector_size;
	map->stripe_len = citem->stripe_len;
	map->type = citem->type_flags;
	map->sub_stripes = citem->sub_stripes;

	for (i = 0, stripe = citem->stripes; i < num_stripes; i++, stripe++) {
		devid = stripe->devid;
		memcpy(uuid, stripe->dev_uuid, BTRFS_UUID_SIZE);
		map->stripes[i].physical = stripe->offset;
		map->stripes[i].dev = btrfs_find_device(root, devid,
							uuid, NULL);
		if (!map->stripes[i].dev) {
			kfree(map);
			return -EIO;
		}
	}

	ret = insert_cache_extent(&map_tree->cache_tree, &map->ce);
	return ret;
}

static int map_chunks(struct recover_control *rc, struct btrfs_root *root)
{
	int ret = 0;
	struct cache_extent *n;
	struct result_record *entry;

	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		ret = map_one_chunk(root, entry);
		if (ret)
			return ret;
	}
	return ret;
}

static int __remove_chunk_extent_item(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      u64 start, u64 offset)
{
	int ret;
	struct btrfs_key key;
	struct btrfs_path *path;

	root = root->fs_info->extent_root;
	key.objectid = start;
	key.offset = offset;
	key.type = BTRFS_EXTENT_ITEM_KEY;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret < 0)
		goto err;
	else if (ret > 0) {
		ret = 0;
		goto err;
	} else
		ret = btrfs_del_item(trans, root, path);

err:
	btrfs_free_path(path);
	return ret;
}

static int remove_chunk_extent_item(struct btrfs_trans_handle *trans,
				    struct recover_control *rc,
				    struct btrfs_root *root)
{
	int ret = 0;
	struct cache_extent *n;
	struct result_record *entry;
	u64 start;
	u64 end;
	u64 sectorsize;

	sectorsize = rc->sectorsize;
	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		if (!(entry->recover_flags & RECOVER_CHUNK))
			continue;
		if (!(entry->chunk->type_flags & BTRFS_BLOCK_GROUP_SYSTEM))
			continue;
		start = entry->start;
		end = entry->start + entry->size;
		while (start < end) {
			ret = __remove_chunk_extent_item(trans, root, start,
					sectorsize);
			if (ret)
				return ret;
			start += sectorsize;
		}
	}
	return ret;
}

static int reset_block_group(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     u64 bytenr, u64 num_bytes)
{
	int ret = 0;
	struct btrfs_block_group_cache *cache;
	struct btrfs_fs_info *info;
	u64 byte_in_group;
	u64 total;
	u64 start;
	u64 end;

	info = root->fs_info;
	total = num_bytes;
	while (total) {
		cache = btrfs_lookup_block_group(info, bytenr);
		if (!cache)
			return -1;

		start = cache->key.objectid;
		end = start + cache->key.offset - 1;
		set_extent_bits(&info->block_group_cache, start, end,
				EXTENT_DIRTY, GFP_NOFS);

		byte_in_group = bytenr - cache->key.objectid;
		num_bytes =  min(total, cache->key.offset - byte_in_group);

		set_extent_dirty(&info->free_space_cache, bytenr,
				 bytenr + num_bytes - 1, GFP_NOFS);

		btrfs_set_block_group_used(&cache->item, 0);
		total -= num_bytes;
		bytenr += num_bytes;
	}

	return ret;
}

static int clean_sys_block_group_info(struct btrfs_trans_handle *trans,
				      struct recover_control *rc,
				      struct btrfs_root *root)
{
	int ret = 0;
	struct cache_extent *n;
	struct result_record *entry;

	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		if (!(entry->recover_flags & RECOVER_BG))
			continue;
		if (!(entry->chunk->type_flags & BTRFS_BLOCK_GROUP_SYSTEM))
			continue;
		ret = reset_block_group(trans, root, entry->start, entry->size);
		if (ret)
			return ret;
	}
	return ret;
}


static int __reset_chunk_root(struct btrfs_trans_handle *trans,
			      struct recover_control *rc,
			      struct btrfs_root *root)
{
	int ret;
	u64 min_devid;
	struct list_head *head;
	struct list_head *cur;
	struct btrfs_super_block *super_copy;
	struct btrfs_device *dev;
	struct extent_buffer *cow;
	struct btrfs_disk_key disk_key;

	ret = 0;
	min_devid = 1;
	head = &rc->fs_devices->devices;
	list_for_each(cur, head) {
		dev = list_entry(cur, struct btrfs_device, dev_list);
		if (min_devid > dev->devid)
			min_devid = dev->devid;
	}
	disk_key.objectid = BTRFS_DEV_ITEMS_OBJECTID;
	disk_key.type = BTRFS_DEV_ITEM_KEY;
	disk_key.offset = min_devid;

	cow = btrfs_alloc_free_block(trans, root, root->sectorsize,
				     BTRFS_CHUNK_TREE_OBJECTID,
				     &disk_key, 0, 0, 0);
	btrfs_set_header_bytenr(cow, cow->start);
	btrfs_set_header_generation(cow, trans->transid);
	btrfs_set_header_nritems(cow, 0);
	btrfs_set_header_level(cow, 0);
	btrfs_set_header_backref_rev(cow, BTRFS_MIXED_BACKREF_REV);
	btrfs_set_header_owner(cow, BTRFS_CHUNK_TREE_OBJECTID);
	write_extent_buffer(cow, root->fs_info->fsid,
			(unsigned long)btrfs_header_fsid(cow),
			BTRFS_FSID_SIZE);

	write_extent_buffer(cow, root->fs_info->chunk_tree_uuid,
			(unsigned long)btrfs_header_chunk_tree_uuid(cow),
			BTRFS_UUID_SIZE);

	root->node = cow;
	btrfs_mark_buffer_dirty(cow);

	super_copy = root->fs_info->super_copy;
	btrfs_set_super_chunk_root(super_copy, cow->start);
	btrfs_set_super_chunk_root_generation(super_copy, trans->transid);
	btrfs_set_super_chunk_root_level(super_copy, 0);

	return ret;
}

static int __rebuild_device_items(struct btrfs_trans_handle *trans,
				  struct recover_control *rc,
				  struct btrfs_root *root)
{
	int ret = 0;
	struct list_head *cur;
	struct list_head *head;
	struct btrfs_device *dev;
	struct btrfs_key key;
	struct btrfs_dev_item *dev_item;

	head = &rc->fs_devices->devices;
	list_for_each(cur, head) {
		dev = list_entry(cur, struct btrfs_device, dev_list);

		key.objectid = BTRFS_DEV_ITEMS_OBJECTID;
		key.type = BTRFS_DEV_ITEM_KEY;
		key.offset = dev->devid;

		dev_item = malloc(sizeof(struct btrfs_dev_item));
		if (!dev_item)
			return -ENOMEM;

		btrfs_set_stack_device_generation(dev_item, 0);
		btrfs_set_stack_device_type(dev_item, dev->type);
		btrfs_set_stack_device_id(dev_item, dev->devid);
		btrfs_set_stack_device_total_bytes(dev_item, dev->total_bytes);
		btrfs_set_stack_device_bytes_used(dev_item, dev->bytes_used);
		btrfs_set_stack_device_io_align(dev_item, dev->io_align);
		btrfs_set_stack_device_io_width(dev_item, dev->io_width);
		btrfs_set_stack_device_sector_size(dev_item, dev->sector_size);
		memcpy(dev_item->uuid, dev->uuid, BTRFS_UUID_SIZE);
		memcpy(dev_item->fsid, dev->fs_devices->fsid, BTRFS_UUID_SIZE);

		ret = btrfs_insert_item(trans, root, &key,
					dev_item, sizeof(*dev_item));
	}

	return ret;
}

static int __rebuild_chunk_items(struct btrfs_trans_handle *trans,
				 struct recover_control *rc,
				 struct btrfs_root *root)
{
	int ret = 0;
	int i;
	struct btrfs_key key;
	struct btrfs_chunk *chunk = NULL;
	struct btrfs_root *chunk_root;
	struct btrfs_stripe *stripe;
	struct cache_extent *n;
	struct result_record *entry;
	struct chunk_record *citem;
	chunk_root = root->fs_info->chunk_root;

	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		citem = entry->chunk;
		chunk = malloc(btrfs_chunk_item_size(citem->num_stripes));
		if (!chunk)
			return -ENOMEM;
		btrfs_set_stack_chunk_length(chunk, citem->length);
		btrfs_set_stack_chunk_owner(chunk, citem->owner);
		btrfs_set_stack_chunk_stripe_len(chunk, citem->stripe_len);
		btrfs_set_stack_chunk_type(chunk, citem->type_flags);
		btrfs_set_stack_chunk_io_align(chunk, citem->io_align);
		btrfs_set_stack_chunk_io_width(chunk, citem->io_width);
		btrfs_set_stack_chunk_sector_size(chunk, citem->sector_size);
		btrfs_set_stack_chunk_num_stripes(chunk, citem->num_stripes);
		btrfs_set_stack_chunk_sub_stripes(chunk, citem->sub_stripes);
		for (i = 0, stripe = &chunk->stripe; i < citem->num_stripes;
		     i++, stripe++) {
			btrfs_set_stack_stripe_devid(stripe,
					citem->stripes[i].devid);
			btrfs_set_stack_stripe_offset(stripe,
					citem->stripes[i].devid);
			memcpy(stripe->dev_uuid, &citem->stripes[i].dev_uuid,
					BTRFS_UUID_SIZE);
		}
		key.objectid = BTRFS_FIRST_CHUNK_TREE_OBJECTID;
		key.type = BTRFS_CHUNK_ITEM_KEY;
		key.offset = entry->start;

		ret = btrfs_insert_item(trans, chunk_root, &key, chunk,
				btrfs_chunk_item_size(chunk->num_stripes));
		if (ret)
			return ret;
	}
	return ret;
}

static int rebuild_chunk_tree(struct btrfs_trans_handle *trans,
			      struct recover_control *rc,
			      struct btrfs_root *root)
{
	int ret = 0;

	root = root->fs_info->chunk_root;

	ret = __reset_chunk_root(trans, rc, root);
	if (ret)
		return ret;

	ret = __rebuild_device_items(trans, rc, root);
	if (ret)
		return ret;

	ret = __rebuild_chunk_items(trans, rc, root);

	return ret;
}

static int rebuild_sys_array(struct recover_control *rc,
			     struct btrfs_root *root)
{
	int ret = 0;
	int i;
	u16 num_stripes;
	struct btrfs_chunk *chunk = NULL;
	struct btrfs_key key;
	struct btrfs_stripe *stripe;
	struct result_record *entry;
	struct chunk_record *citem;
	struct cache_extent *n;

	btrfs_set_super_sys_array_size(root->fs_info->super_copy, 0);

	for (n = find_first_cache_extent(&rc->result, 0); n;
	     n = next_cache_extent(n)) {
		entry = cache_result_entry(n);
		if (!(entry->bg->flags & BTRFS_BLOCK_GROUP_SYSTEM))
			continue;
		num_stripes = entry->chunk->num_stripes;
		chunk = malloc(btrfs_chunk_item_size(num_stripes));
		if (!chunk)
			return -ENOMEM;
		citem = entry->chunk;

		btrfs_set_stack_chunk_length(chunk, citem->length);
		btrfs_set_stack_chunk_owner(chunk, citem->owner);
		btrfs_set_stack_chunk_stripe_len(chunk, citem->stripe_len);
		btrfs_set_stack_chunk_type(chunk, citem->type_flags);
		btrfs_set_stack_chunk_io_align(chunk, citem->io_align);
		btrfs_set_stack_chunk_io_width(chunk, citem->io_width);
		btrfs_set_stack_chunk_sector_size(chunk, citem->sector_size);
		btrfs_set_stack_chunk_num_stripes(chunk, citem->num_stripes);
		btrfs_set_stack_chunk_sub_stripes(chunk, citem->sub_stripes);
		for (i = 0, stripe = &chunk->stripe; i < num_stripes;
		     i++, stripe++) {
			btrfs_set_stack_stripe_devid(stripe,
					citem->stripes[i].devid);
			btrfs_set_stack_stripe_offset(stripe,
					citem->stripes[i].devid);
			memcpy(&stripe->dev_uuid, &citem->stripes[i].dev_uuid,
					BTRFS_UUID_SIZE);
		}
		key.objectid = BTRFS_FIRST_CHUNK_TREE_OBJECTID;
		key.type = BTRFS_CHUNK_ITEM_KEY;
		key.offset = entry->start;

		ret = btrfs_add_system_chunk(NULL, root, &key, chunk,
				btrfs_chunk_item_size(num_stripes));
		if (ret)
			goto free_out;
		free(chunk);
		chunk = NULL;
	}
free_out:
	if (chunk)
		free(chunk);
	return ret;

}

static struct btrfs_root *open_ctree_with_broken_chunk(
				struct recover_control *rc,
				const char *path,
				int writes)
{
	int ret;
	u32 sectorsize;
	u32 nodesize;
	u32 leafsize;
	u32 blocksize;
	u32 stripesize;
	u64 generation;
	u64 sb_bytenr;
	u64 features;
	struct btrfs_key key;
	struct btrfs_root *tree_root = malloc(sizeof(struct btrfs_root));
	struct btrfs_root *extent_root = malloc(sizeof(struct btrfs_root));
	struct btrfs_root *chunk_root = malloc(sizeof(struct btrfs_root));
	struct btrfs_root *dev_root = malloc(sizeof(struct btrfs_root));
	struct btrfs_root *csum_root = malloc(sizeof(struct btrfs_root));
	struct btrfs_fs_info *fs_info = malloc(sizeof(struct btrfs_fs_info));
	struct btrfs_fs_devices *fs_devices = NULL;
	struct btrfs_super_block *disk_super = NULL;

	fs_devices = rc->fs_devices;
	sb_bytenr = BTRFS_SUPER_INFO_OFFSET;

	memset(fs_info, 0, sizeof(struct btrfs_fs_info));
	/*fs_info->rc = rc;*/
	fs_info->tree_root = tree_root;
	fs_info->extent_root = extent_root;
	fs_info->chunk_root = chunk_root;
	fs_info->dev_root = dev_root;
	fs_info->csum_root = csum_root;

	extent_io_tree_init(&fs_info->extent_cache);
	extent_io_tree_init(&fs_info->free_space_cache);
	extent_io_tree_init(&fs_info->block_group_cache);
	extent_io_tree_init(&fs_info->pinned_extents);
	extent_io_tree_init(&fs_info->pending_del);
	extent_io_tree_init(&fs_info->extent_ins);

	cache_tree_init(&fs_info->fs_root_cache);
	cache_tree_init(&fs_info->mapping_tree.cache_tree);

	mutex_init(&fs_info->fs_mutex);
	fs_info->fs_devices = fs_devices;
	INIT_LIST_HEAD(&fs_info->dirty_cowonly_roots);
	INIT_LIST_HEAD(&fs_info->space_info);

	__setup_root(4096, 4096, 4096, 4096, tree_root,
		     fs_info, BTRFS_ROOT_TREE_OBJECTID);

	ret = btrfs_open_devices(fs_devices, O_RDWR);

	fs_info->super_bytenr = sb_bytenr;
	fs_info->super_copy = malloc(sizeof(struct btrfs_super_block));
	if (!fs_info->super_copy) {
		ret = -ENOMEM;
		goto out;
	}

	disk_super = fs_info->super_copy;
	ret = btrfs_read_dev_super(fs_devices->latest_bdev,
				   disk_super, sb_bytenr);
	if (ret) {
		fprintf(stderr, "No valid btrfs found\n");
		ret = -ENOENT;
		goto out;
	}

	memcpy(fs_info->fsid, &disk_super->fsid, BTRFS_FSID_SIZE);

	features = btrfs_super_incompat_flags(disk_super) &
		   ~BTRFS_FEATURE_INCOMPAT_SUPP;
	if (features) {
		fprintf(stderr,
			"couldn't open because of unsupported option features (%Lx).\n",
			features);
		ret = -ENOTSUP;
		goto out;
	}

	features = btrfs_super_incompat_flags(disk_super);
	if (!(features & BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF)) {
		features |= BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF;
		btrfs_set_super_incompat_flags(disk_super, features);
	}

	features = btrfs_super_compat_ro_flags(disk_super) &
		~BTRFS_FEATURE_COMPAT_RO_SUPP;
	if (writes && features) {
		fprintf(stderr,
			"couldn't open RDWR because of unsupported option features (%Lx).\n",
			features);
		ret = -ENOTSUP;
		goto out;
	}

	nodesize = btrfs_super_nodesize(disk_super);
	leafsize = btrfs_super_leafsize(disk_super);
	sectorsize = btrfs_super_sectorsize(disk_super);
	stripesize = btrfs_super_stripesize(disk_super);
	tree_root->nodesize = nodesize;
	tree_root->leafsize = leafsize;
	tree_root->sectorsize = sectorsize;
	tree_root->stripesize = stripesize;

	ret = rebuild_sys_array(rc, tree_root);
	if (ret)
		goto out;

	ret = map_chunks(rc, tree_root);
	if (ret)
		goto out;

	blocksize = btrfs_level_size(tree_root,
				     btrfs_super_chunk_root_level(disk_super));
	generation = btrfs_super_chunk_root_generation(disk_super);
	__setup_root(nodesize, leafsize, sectorsize, stripesize,
		     chunk_root, fs_info, BTRFS_CHUNK_TREE_OBJECTID);

	blocksize = btrfs_level_size(tree_root,
				     btrfs_super_root_level(disk_super));
	generation = btrfs_super_generation(disk_super);

	tree_root->node = read_tree_block(tree_root,
					  btrfs_super_root(disk_super),
					  blocksize, generation);
	if (!tree_root->node) {
		ret = -EIO;
		goto out;
	}

	read_extent_buffer(tree_root->node, fs_info->chunk_tree_uuid,
		(unsigned long)btrfs_header_chunk_tree_uuid(tree_root->node),
		BTRFS_UUID_SIZE);

	ret = find_and_setup_root(tree_root, fs_info,
				  BTRFS_EXTENT_TREE_OBJECTID, extent_root);
	if (ret)
		goto out;
	extent_root->track_dirty = 1;

	ret = find_and_setup_root(tree_root, fs_info,
				  BTRFS_DEV_TREE_OBJECTID, dev_root);
	if (ret)
		goto out;
	dev_root->track_dirty = 1;

	ret = find_and_setup_root(tree_root, fs_info,
				  BTRFS_CSUM_TREE_OBJECTID, csum_root);
	if (ret)
		goto out;
	csum_root->track_dirty = 1;

	ret = find_and_setup_log_root(tree_root, fs_info, disk_super);
	if (ret)
		goto out;

	fs_info->generation = generation + 1;
	btrfs_read_block_groups(fs_info->tree_root);

	key.objectid = BTRFS_FS_TREE_OBJECTID;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	fs_info->fs_root = btrfs_read_fs_root(fs_info, &key);

	fs_info->data_alloc_profile = (u64)-1;
	fs_info->metadata_alloc_profile = (u64)-1;
	fs_info->system_alloc_profile = fs_info->metadata_alloc_profile;

	return fs_info->fs_root;
out:
	return ERR_PTR(ret);
}

static int close_ctree_with_broken_chunk(struct recover_control *rc,
					 struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info;

	if (!rc || !root)
		return -1;

	fs_info = root->fs_info;

	btrfs_free_block_groups(fs_info);
	free_fs_roots(fs_info);

	if (fs_info->extent_root->node)
		free_extent_buffer(fs_info->extent_root->node);
	if (fs_info->tree_root->node)
		free_extent_buffer(fs_info->tree_root->node);
	if (fs_info->chunk_root->node)
		free_extent_buffer(fs_info->chunk_root->node);
	if (fs_info->dev_root->node)
		free_extent_buffer(fs_info->dev_root->node);
	if (fs_info->csum_root->node)
		free_extent_buffer(fs_info->csum_root->node);

	if (fs_info->log_root_tree) {
		if (fs_info->log_root_tree->node)
			free_extent_buffer(fs_info->log_root_tree->node);
		free(fs_info->log_root_tree);
	}

	extent_io_tree_cleanup(&fs_info->extent_cache);
	extent_io_tree_cleanup(&fs_info->free_space_cache);
	extent_io_tree_cleanup(&fs_info->block_group_cache);
	extent_io_tree_cleanup(&fs_info->pinned_extents);
	extent_io_tree_cleanup(&fs_info->pending_del);
	extent_io_tree_cleanup(&fs_info->extent_ins);

	free(fs_info->tree_root);
	free(fs_info->extent_root);
	free(fs_info->chunk_root);
	free(fs_info->dev_root);
	free(fs_info->csum_root);
	free(fs_info->super_copy);
	free(fs_info);

	return 0;
}

static int recover_prepare(struct recover_control *rc,
			   char *path, int silent)
{
	int ret;
	int fd;
	u64 total_devs;
	struct btrfs_super_block *sb;
	struct btrfs_fs_devices *fs_devices;

	ret = 0;
	fd = open(path, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		fprintf(stderr, "open %s\n error", path);
		return -1;
	}

	rc->fd = fd;
	rc->silent = silent;

	sb = malloc(sizeof(struct btrfs_super_block));
	if (!sb) {
		return -ENOMEM;
		goto fail_close_fd;
	}

	ret = btrfs_read_dev_super(fd, sb, BTRFS_SUPER_INFO_OFFSET);
	if (ret) {
		fprintf(stderr, "read super block error\n");
		free(sb);
		goto fail_free_sb;
	}

	rc->sectorsize = btrfs_super_sectorsize(sb);
	rc->leafsize = btrfs_super_leafsize(sb);
	rc->generation = btrfs_super_generation(sb);
	rc->chunk_root_generation = btrfs_super_chunk_root_generation(sb);

	/* if seed, the result of scanning below will be partial */
	if (btrfs_super_flags(sb) & BTRFS_SUPER_FLAG_SEEDING) {
		fprintf(stderr, "this device is seed device\n");
		ret = -1;
		goto fail_free_sb;
	}

	ret = btrfs_scan_one_device(fd, path, &fs_devices,
				    &total_devs, BTRFS_SUPER_INFO_OFFSET);
	if (ret)
		goto fail_free_sb;

	if (total_devs != 1) {
		ret = btrfs_scan_for_fsid(fs_devices, total_devs, 1);
		if (ret)
			goto fail_free_sb;
	}

	rc->fs_devices = fs_devices;

	if (!rc->silent)
		print_device(rc);

fail_free_sb:
	free(sb);
fail_close_fd:
	close(fd);
	return ret;
}

static int recover_finish(struct recover_control *rc)
{
	if (rc && rc->fd)
		close(rc->fd);

	free_recover_control(rc);
	return 0;
}

static int btrfs_chunk_tree_check(char *path, int silent)
{
	int ret = 0;
	struct recover_control *rc = NULL;

	rc = init_recover_control();
	if (!rc)
		return -ENOMEM;

	ret = recover_prepare(rc, path, silent);
	if (ret) {
		fprintf(stderr, "recover prepare error\n");
		goto fail_free_rc;
	}

	ret = scan_devices(rc);
	if (ret) {
		fprintf(stderr, "scan devices error\n");
		goto fail_free_rc;
	}

	ret = check_scan_result(rc);
	if (ret) {
		fprintf(stderr, "check results error\n");
		goto fail_free_rc;
	}

	if (result_is_empty(rc)) {
		ret = -1;
		goto fail_free_rc;
	} else
		print_result(rc);

fail_free_rc:
	recover_finish(rc);
	return ret;
}

static int btrfs_chunk_tree_recover(char *path, int silent)
{
	int ret = 0;
	struct btrfs_root *root = NULL;
	struct btrfs_trans_handle *trans;
	struct recover_control *rc = NULL;

	rc = init_recover_control();
	if (!rc)
		return -ENOMEM;

	ret = recover_prepare(rc, path, silent);
	if (ret) {
		fprintf(stderr, "recover prepare error\n");
		goto fail_free_rc;
	}

	ret = scan_devices(rc);
	if (ret) {
		fprintf(stderr, "scan chunk headers error\n");
		goto fail_free_rc;
	}

	ret = check_scan_result(rc);
	if (ret) {
		fprintf(stderr, "check chunk error\n");
		goto fail_free_rc;
	}

	if (result_is_empty(rc)) {
		fprintf(stderr, "no chunk recoverable error\n");
		goto fail_free_rc;
	} else
		print_result(rc);

	root = open_ctree_with_broken_chunk(rc, path, O_RDWR);
	if (IS_ERR(root)) {
		fprintf(stderr, "open with broken chunk error\n");
		ret = PTR_ERR(root);
		goto fail_close_ctree;
	}

	ret = match_results(NULL, rc, root);
	if (ret) {
		fprintf(stderr, "match chunk error\n");
		goto fail_close_ctree;
	}

	trans = btrfs_start_transaction(root, 1);
	ret = remove_chunk_extent_item(trans, rc, root);
	BUG_ON(ret);

	ret = clean_sys_block_group_info(trans, rc, root);
	BUG_ON(ret);

	ret = rebuild_chunk_tree(trans, rc, root);
	BUG_ON(ret);
	btrfs_commit_transaction(trans, root);

fail_close_ctree:
	close_ctree_with_broken_chunk(rc, root);
fail_free_rc:
	recover_finish(rc);
	return ret;
}

static void print_usage(void)
{
	fprintf(stderr, "usage:btrfs-recover-chunk [options] dev\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "\t -c --check stripe header after scan dev\n");
	fprintf(stderr, "\t -s --silent mode\n");
	fprintf(stderr, "%s\n", BTRFS_BUILD_VERSION);
	exit(1);
}
int main(int argc, char *argv[])
{
	int ret = 0;
	int silent = 0;
	char *file;
	int check = 0;

	while (1) {
		int c = getopt(argc, argv, "sc");
		if (c < 0)
			break;
		switch (c) {
		case 's':
			silent  = 1;
			break;
		case 'c':
			check = 1;
			break;
		default:
			print_usage();
		}
	}

	argc = argc - optind;
	if (argc == 0)
		print_usage();

	file = argv[optind];

	ret = check_mounted(file);
	if (ret) {
		fprintf(stderr, "the device is busy\n");
		return ret;
	}

	if (silent)
		printf("slient mode enable\n");
	if (check) {
		ret = btrfs_chunk_tree_check(file, silent);
		if (ret)
			printf("some stripe header invalid\n");
		else
			printf("all stripe headers valid\n");
	} else {
		ret = btrfs_chunk_tree_recover(file, silent);
		if (ret)
			printf("rebuild chunk tree fail\n");
		else
			printf("rebuild chunk tree success\n");
	}

	return ret;
}
