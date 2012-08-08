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

#ifndef __PENDING_DEV_EXTENT__
#define __PENDING_DEV_EXTENT__
#include "kerncompat.h"
#include "rbtree.h"

struct dev_extent_tree {
	struct rb_root root;
};

struct cache_dev_extent {
	struct rb_node rb_node;
	u64 devno;
	u64 offset;
};

void dev_extent_tree_init(struct dev_extent_tree *tree);
void remove_cache_dev_extent(struct dev_extent_tree *tree,
			  struct cache_dev_extent *pe);
struct cache_dev_extent *find_first_cache_dev_extent(
				struct dev_extent_tree *tree, u64 devno);
struct cache_dev_extent *prev_cache_dev_extent(struct cache_dev_extent *pe);
struct cache_dev_extent *next_cache_dev_extent(struct cache_dev_extent *pe);
struct cache_dev_extent *find_cache_dev_extent(struct dev_extent_tree *tree,
					   u64 devno, u64 offset);
int insert_cache_dev_extent(struct dev_extent_tree *tree,
				u64 devno, u64 offset);
int insert_existing_cache_dev_extent(struct dev_extent_tree *tree,
				struct cache_dev_extent *pe);

static inline int dev_extent_tree_empty(struct dev_extent_tree *tree)
{
	return RB_EMPTY_ROOT(&tree->root);
}

static inline void free_cache_dev_extent(struct cache_dev_extent *pe)
{
	free(pe);
}

struct cache_dev_extent *alloc_pending_dev_extent(u64 devno, u64 offset);

#endif
