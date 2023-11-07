// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "block_meta.h"
#include "osmem.h"

#define ALIGNMENT 8
#define MMAP_TRESHOLD (128 << 10) /* 128 kb */

#define ALIGN(x) ((typeof(x))(((long)(x) + (ALIGNMENT - 1)) & -ALIGNMENT))

static struct block_meta *small_pool;
static struct block_meta *large_pool;

static inline void *get_payload(struct block_meta *bm)
{
	return ALIGN(bm + 1);
}

void merge_blocks(struct block_meta *left, struct block_meta *right)
{
	/* Skip node `right`. */
	right->next->prev = left;
	left->next = right->next;
	if (right == small_pool) {
		small_pool = right->next;
	}

	void *payload_end = get_payload(right) + right->size;
	left->size = payload_end - get_payload(left);
}

void split_block(struct block_meta *block, size_t size)
{
	void *space_to_split = get_payload(block);
	struct block_meta *new_block = ALIGN(space_to_split + size);
	void *new_payload = get_payload(new_block);

	if (space_to_split + block->size <= new_payload) {
		/* No place for new block. */
		return;
	}

	new_block->status = STATUS_MAPPED;
	new_block->size = (void *)space_to_split + block->size - new_payload;

	new_block->next = block->next;
	new_block->prev = block;

	block->next->prev = new_block;
	block->next = new_block;

	block->size = (void *)new_block - space_to_split;
}

struct block_meta *new_small_block(size_t size)
{
	if (!small_pool) {
		/* Preallocate heap for fewer future brk calls. */
		void *prev_brk = sbrk(MMAP_TRESHOLD);
		DIE(prev_brk == (void *)-1, "fail brk() preallocation");

		small_pool = prev_brk;
		small_pool->next = small_pool;
		small_pool->prev = small_pool;
		small_pool->status = STATUS_MAPPED;
		small_pool->size = MMAP_TRESHOLD - sizeof(struct block_meta);
	}

	struct block_meta *iter = small_pool;
	struct block_meta *best_block = NULL;
	do {
		/* Skip allocated blocks. */
		if (iter->status == STATUS_ALLOC) {
			iter = iter->next;
			continue;
		}

		/* Try to merge current block with the blocks to the right (the
		 * left ones are already traversed so they can't be merged). */
		while (iter->next != small_pool) {
			if (iter->next->status == STATUS_ALLOC) {
				break;
			}

			merge_blocks(iter, iter->next);
		}

		/* Skip the block as it still is to small. */
		if (iter->size < size) {
			iter = iter->next;
			continue;
		}

		/* Find the best fit a.k.a. the smallest free
		 * block that can accomodate the size. */
		if (best_block) {
			if (iter->size < best_block->size) {
				best_block = iter;
			}
		} else {
			best_block = iter;
		}

		iter = iter->next;
	} while (iter != small_pool);

	if (best_block) {
		best_block->status = STATUS_ALLOC;
		split_block(best_block, size);
		return best_block;
	}

	struct block_meta *last_block = small_pool->prev;
	if (last_block->status == STATUS_ALLOC) {
		/* If the last block is occupied, extend
		 * the brk to accomodate for the new block. */

		void *brk_end = get_payload(last_block) + last_block->size;

		struct block_meta *new_block = ALIGN(brk_end);
		void *new_payload = get_payload(new_block);

		size_t needed_space = (int)ALIGN(size) + new_payload - brk_end;
		DIE(sbrk(needed_space) == (void *)-1, "fail brk() extension");

		new_block->size = ALIGN(size);
		new_block->status = STATUS_ALLOC;

		new_block->prev = last_block;
		new_block->next = last_block->next;
		new_block->prev->next = new_block;
		new_block->next->prev = new_block;

		return new_block;
	}

	/* If the last block is free, extend the
	 * brk to include the size needed. */
	size_t needed_space = ALIGN(size - last_block->size);
	DIE(sbrk(needed_space) == (void *)-1, "fail brk() extension");
	last_block->size = ALIGN(size);
	last_block->status = STATUS_ALLOC;
	return last_block;
}

struct block_meta *new_large_block(size_t size)
{
	size_t actual_size = ALIGN(size + ALIGN(sizeof(struct block_meta)));
	void *ptr = mmap(NULL, actual_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE(ptr == MAP_FAILED, "fail mmap()");

	struct block_meta *block = ALIGN(ptr);
	block->status = STATUS_ALLOC;
	block->size = actual_size;

	if (large_pool) {
		block->next = large_pool;
		block->prev = large_pool->prev;

		large_pool->prev->next = block;
		large_pool->prev = block;
	} else {
		large_pool = block;
		block->next = block;
		block->prev = block;
	}

	return block;
}

void delete_large_block(struct block_meta *block)
{
	if (block == large_pool) {
		if (block->next == block) {
			/* This is the last block in the list. */
			large_pool = NULL;
		} else {
			large_pool = block->next;
		}
	}

	block->prev->next = block->next;
	block->next->prev = block->prev;
	DIE(munmap(block, block->size) != 0, "fail munmap()");
}

void *os_malloc(size_t size)
{
	if (!size) {
		return NULL;
	}

	if (size < MMAP_TRESHOLD) {
		return get_payload(new_small_block(size));
	}

	return get_payload(new_large_block(size));
}

void free_small(void *ptr)
{
	if (!small_pool) {
		return;
	}

	struct block_meta *block = small_pool;
	do {
		if (get_payload(block) == ptr) {
			block->status = STATUS_FREE;
			return;
		}

		block = block->next;
	} while (block != small_pool);
}

void free_large(void *ptr)
{
	if (!large_pool) {
		return;
	}

	struct block_meta *block = large_pool;
	do {
		if (get_payload(block) == ptr) {
			delete_large_block(block);
			return;
		}

		block = block->next;
	} while (block != large_pool);
}

void os_free(void *ptr)
{
	if (!ptr) {
		return;
	}

	free_small(ptr);
	free_large(ptr);
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t bytes_count = nmemb * size;
	void *ptr = os_malloc(bytes_count);
	if (ptr) {
		memset(ptr, 0, bytes_count);
	}

	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr) {
		return malloc(size);
	}

	if (!size) {
		free(ptr);
		return NULL;
	}

	struct block_meta *block = small_pool;
	do {
		/* TODO: Implement os_realloc */
		block = block->next;
	} while (block != small_pool);

	block = large_pool;
	do {
		if (get_payload(block) == ptr) {
			struct block_meta *new_block = new_large_block(size);
			void *new_payload = get_payload(new_block);

			memcpy(new_payload, ptr, block->size);
			delete_large_block(block);
			return new_payload;
		}

		block = block->next;
	} while (block != large_pool);
	return NULL;
}
