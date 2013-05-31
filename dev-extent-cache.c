/*
 * Copyright (C) 2012 Fujitsu.  All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include "kerncompat.h"
#include "dev-extent-cache.h"

struct cache_dev_extent_search_range {
	u64 devid;
	u64 offset;
	u64 size;
};

void dev_extent_tree_init(struct dev_extent_tree *tree)
{
	tree->root = RB_ROOT;
}

static int device_extent_compare_range(struct rb_node *node, void *data)
{
	struct cache_dev_extent_search_range *range;
	struct cache_dev_extent *dev_extent;

	range = (struct cache_dev_extent_search_range *)data;
	dev_extent = rb_entry(node, struct cache_dev_extent, node);

	if (range->devid > dev_extent->devid)
		return 1;
	else if (range->devid < dev_extent->devid)
		return -1;
	else if (range->offset >= dev_extent->offset + dev_extent->size)
		return 1;
	else if (range->offset + range->size <= dev_extent->offset)
		return -1;
	else
		return 0;
}

static int device_extent_compare_node(struct rb_node *node1,
				      struct rb_node *node2)
{
	struct cache_dev_extent *dev_extent;
	struct cache_dev_extent_search_range range;

	dev_extent = rb_entry(node2, struct cache_dev_extent, node);
	range.devid = dev_extent->devid;
	range.offset = dev_extent->offset;
	range.size = dev_extent->size;

	return device_extent_compare_range(node1, (void *)&range);
}

int insert_cache_dev_extent(struct dev_extent_tree *tree,
			    struct cache_dev_extent *pe)
{
	return rb_insert(&tree->root, &pe->node, device_extent_compare_node);
}

struct cache_dev_extent *lookup_cache_dev_extent(struct dev_extent_tree *tree,
						 u64 devid, u64 offset,
						 u64 size)
{
	struct rb_node *node;
	struct cache_dev_extent *entry;
	struct cache_dev_extent_search_range range;

	range.devid = devid;
	range.offset = offset;
	range.size = size;
	node = rb_search(&tree->root, (void *)&range,
			 device_extent_compare_range, NULL);
	if (!node)
		return NULL;

	entry = rb_entry(node, struct cache_dev_extent, node);
	return entry;
}

struct cache_dev_extent *
find_first_cache_dev_extent(struct dev_extent_tree *tree, u64 devid)
{
	struct rb_node *node;
	struct rb_node *next;
	struct cache_dev_extent *entry;
	struct cache_dev_extent_search_range range;

	range.devid = devid;
	range.offset = 0;
	range.size = 1;
	node = rb_search(&tree->root, (void *)&range,
			 device_extent_compare_range, &next);
	if (!node)
		node = next;
	if (!node)
		return NULL;

	entry = rb_entry(node, struct cache_dev_extent, node);
	return entry;
}

struct cache_dev_extent *prev_cache_dev_extent(struct cache_dev_extent *pe)
{
	struct rb_node *node = rb_prev(&pe->node);

	if (!node)
		return NULL;
	return rb_entry(node, struct cache_dev_extent, node);
}

struct cache_dev_extent *next_cache_dev_extent(struct cache_dev_extent *pe)
{
	struct rb_node *node = rb_next(&pe->node);

	if (!node)
		return NULL;
	return rb_entry(node, struct cache_dev_extent, node);
}

void remove_cache_dev_extent(struct dev_extent_tree *tree,
			     struct cache_dev_extent *pe)
{
	rb_erase(&pe->node, &tree->root);
}
