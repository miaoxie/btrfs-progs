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

#ifndef __PENDING_CHUNK__
#define __PENDING_CHUNK__
#include "kerncompat.h"
#include "volumes.h"
#include "list.h"
#include "ctree.h"
#include "rbtree.h"
#include "dev-extent-cache.h"
#include "extent-cache.h"

#define REC_UNCHECKED	0
#define REC_CHECKED	1

struct result_record *cache_result_entry(
		struct cache_extent *cache);
struct block_group_record {
	struct cache_extent cache;
	int state;

	u64 objectid;
	u8  type;
	u64 offset;
	u64 generation;

	u64 flags;
};

struct dev_record {
	struct rb_node node;
	u64 devid;

	int state;

	u64 objectid;
	u8  type;
	u64 offset;
	u64 generation;

	u64 total_byte;
	u64 byte_used;
};

struct stripe {
	u64 devid;
	u64 offset;
	u8 dev_uuid[BTRFS_UUID_SIZE];
};

struct chunk_record {
	struct cache_extent cache;
	int state;

	u64 objectid;
	u8  type;
	u64 offset;
	u64 generation;

	u64 length;
	u64 owner;
	u64 stripe_len;
	u64 type_flags;
	u32 io_align;
	u32 io_width;
	u32 sector_size;
	u16 num_stripes;
	u16 sub_stripes;
	struct stripe stripes[0];
};

struct dev_extent_record {
	struct cache_dev_extent cache;
	struct list_head list;
	int state;

	u64 objectid;
	u8  type;
	u64 offset;
	u64 generation;

	u64 chunk_objecteid;
	u64 chunk_offset;
	u64 length;
};

#define RECOVER_CHUNK		(1<<0)
#define RECOVER_BG		(1<<1)
#define RECOVER_DEVEXT		(1<<2)
#define RECOVER_DEVEXT_FULL	(1<<3)
struct result_record {
	struct cache_extent cache;
	int recover_flags;

	u64 start;
	u64 size;

	struct chunk_record *chunk;
	struct block_group_record *bg;
	struct dev_extent_record *devext;
};

struct recover_control {
	int fd;
	int silent;
	u32 sectorsize;
	u32 leafsize;
	u64 generation;
	u64 chunk_root_generation;
	struct btrfs_fs_devices *fs_devices;
	struct cache_tree bg;
	struct cache_tree chunk;
	struct dev_extent_tree devext;
	struct cache_tree result;
};

struct recover_control *init_recover_control();
int free_recover_control(struct recover_control *rc);
void print_rc(struct recover_control *rc);

int check_scan_result(struct recover_control *rc);
void print_result(struct recover_control *rc);

int insert_bg_record(struct cache_tree *tree, struct btrfs_item *item,
		struct btrfs_block_group_item *data, u64 gen);
int insert_chunk_record(struct cache_tree *tree, struct btrfs_item *item,
		struct btrfs_chunk *data, u64 gen);
int insert_devext_record(struct dev_extent_tree *tree, struct btrfs_item *item,
		struct btrfs_dev_extent *data, u64 gen);
#endif
