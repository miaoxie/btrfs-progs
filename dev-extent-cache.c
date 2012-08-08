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

void dev_extent_tree_init(struct dev_extent_tree *tree)
{
	tree->root.rb_node = NULL;
}

static struct rb_node *tree_insert(struct rb_root *root, u64 devno,
				   u64 offset, struct rb_node *node)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cache_dev_extent *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct cache_dev_extent, rb_node);

		if (devno == entry->devno) {
			if (offset < entry->offset)
				p = &(*p)->rb_left;
			else if (offset > entry->offset)
				p = &(*p)->rb_right;
			else
				return parent;
		} else {
			if (devno < entry->devno)
				p = &(*p)->rb_left;
			else if (devno > entry->devno)
				p = &(*p)->rb_right;
			else
				return parent;
		}
	}

	entry = rb_entry(parent, struct cache_dev_extent, rb_node);
	rb_link_node(node, parent, p);
	rb_insert_color(node, root);
	return NULL;
}

static struct rb_node *__tree_search(struct rb_root *root, u64 devno,
				     u64 offset, struct rb_node **prev_ret)
{
	struct rb_node *n = root->rb_node;
	struct rb_node *prev = NULL;
	struct cache_dev_extent *entry;
	struct cache_dev_extent *prev_entry = NULL;

	while (n) {
		entry = rb_entry(n, struct cache_dev_extent, rb_node);
		prev = n;
		prev_entry = entry;

		if (devno == entry->devno) {
			if (offset < entry->offset)
				n = n->rb_left;
			else if (offset > entry->offset)
				n = n->rb_right;
			else
				return n;
		} else {
			if (devno < entry->devno)
				n = n->rb_left;
			else if (devno > entry->devno)
				n = n->rb_right;
			else
				return n;
		}
	}
	if (!prev_ret)
		return NULL;

	while (prev && devno >= prev_entry->devno + prev_entry->offset) {
		prev = rb_next(prev);
		prev_entry = rb_entry(prev, struct cache_dev_extent, rb_node);
	}
	*prev_ret = prev;
	return NULL;
}

struct cache_dev_extent *alloc_cache_dev_extent(u64 devno, u64 offset)
{
	struct cache_dev_extent *pe = malloc(sizeof(*pe));

	if (!pe)
		return pe;
	pe->devno = devno;
	pe->offset = offset;
	return pe;
}

int insert_existing_cache_dev_extent(struct dev_extent_tree *tree,
				 struct cache_dev_extent *pe)
{
	struct rb_node *found;

	found = tree_insert(&tree->root, pe->devno, pe->offset, &pe->rb_node);
	if (found)
		return -EEXIST;

	return 0;
}

int insert_cache_dev_extent(struct dev_extent_tree *tree, u64 devno, u64 offset)
{
	struct cache_dev_extent *pe = alloc_cache_dev_extent(devno, offset);
	int ret;
	ret = insert_existing_cache_dev_extent(tree, pe);
	if (ret)
		free(pe);
	return ret;
}

struct cache_dev_extent *find_cache_dev_extent(struct dev_extent_tree *tree,
					   u64 devno, u64 offset)
{
	struct rb_node *prev;
	struct rb_node *ret;
	struct cache_dev_extent *entry;
	ret = __tree_search(&tree->root, devno, offset, &prev);
	if (!ret)
		return NULL;

	entry = rb_entry(ret, struct cache_dev_extent, rb_node);
	return entry;
}

struct cache_dev_extent *find_first_cache_dev_extent(
				struct dev_extent_tree *tree, u64 devno)
{
	struct rb_node *prev;
	struct rb_node *ret;
	struct cache_dev_extent *entry;

	ret = __tree_search(&tree->root, devno, 1, &prev);
	if (!ret)
		ret = prev;
	if (!ret)
		return NULL;
	entry = rb_entry(ret, struct cache_dev_extent, rb_node);
	return entry;
}

struct cache_dev_extent *prev_cache_dev_extent(struct cache_dev_extent *pe)
{
	struct rb_node *node = rb_prev(&pe->rb_node);

	if (!node)
		return NULL;
	return rb_entry(node, struct cache_dev_extent, rb_node);
}

struct cache_dev_extent *next_cache_dev_extent(struct cache_dev_extent *pe)
{
	struct rb_node *node = rb_next(&pe->rb_node);

	if (!node)
		return NULL;
	return rb_entry(node, struct cache_dev_extent, rb_node);
}

void remove_cache_dev_extent(struct dev_extent_tree *tree,
				 struct cache_dev_extent *pe)
{
	rb_erase(&pe->rb_node, &tree->root);
}
