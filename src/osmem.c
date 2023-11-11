// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "block_meta.h"
#include "osmem.h"

#define ALIGNMENT 8
#define MMAP_TRESHOLD (128 << 10) /* 128 kb */

#define ALIGN(x) ((typeof(x))(((long)(x) + (ALIGNMENT - 1)) & -ALIGNMENT))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

static struct block_meta *small_pool;
static struct block_meta *large_pool;

static inline void *get_payload(struct block_meta *bm);
static inline size_t needed_size(size_t size);

static struct block_meta *new_small_block(size_t size);
static struct block_meta *new_large_block(size_t size);

static void delete_large_block(struct block_meta *block);

static void free_small(void *ptr);
static void free_large(void *ptr);

static void *realloc_small(void *ptr, size_t size);
static void *realloc_large(void *ptr, size_t size);

void *os_malloc(size_t size)
{
	if (!size)
		return NULL;

	if (size < MMAP_TRESHOLD)
		return get_payload(new_small_block(size));
	return get_payload(new_large_block(size));
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	free_small(ptr);
	free_large(ptr);
}

void *os_calloc(size_t nmemb, size_t size)
{
	const size_t bytes_count = nmemb * size;

	if (!bytes_count)
		return NULL;

	const size_t treshold = getpagesize();
	void *ptr;

	if (needed_size(bytes_count) < treshold)
		ptr = new_small_block(bytes_count);
	else
		ptr = new_large_block(bytes_count);

	if (ptr) {
		ptr = get_payload(ptr);
		memset(ptr, 0, bytes_count);
	}

	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (!size) {
		os_free(ptr);
		return NULL;
	}

	void *retaddr = realloc_small(ptr, size);

	if (retaddr)
		return retaddr;
	return realloc_large(ptr, size);
}

/** Get the payload of block `bm` (the next aligned address). */
static inline void *get_payload(struct block_meta *bm)
{
	return ALIGN(bm + 1);
}

/** Get the size needed to accomodate `size` bytes. */
static inline size_t needed_size(size_t size)
{
	return ALIGN(size + ALIGN(sizeof(struct block_meta)));
}

/** Merge block `rigth` into `left`. */
static void merge_blocks(struct block_meta *left, struct block_meta *right)
{
	void *payload_end = get_payload(right) + right->size;

	/* Skip node `right`. */
	right->next->prev = left;
	left->next = right->next;
	if (right == small_pool)
		small_pool = right->next;

	left->size = payload_end - get_payload(left);
}

/** Merge current block with its right neighbours as many times as possible. */
static void fold_merge(struct block_meta *block)
{
	while (block->next != small_pool) {
		if (block->next->status == STATUS_ALLOC)
			break;

		merge_blocks(block, block->next);
	}
}

/** Shrink the block to the requested `size`,
 * splitting it and creating a new block if possible.
 */
static void split_block(struct block_meta *block, size_t size)
{
	void *space_to_split = get_payload(block);

	struct block_meta *new_block = ALIGN(space_to_split + size);
	void *new_payload = get_payload(new_block);

	if (space_to_split + block->size <= new_payload) {
		/* No place for new block. */
		return;
	}

	new_block->status = STATUS_FREE;
	new_block->size = (void *)space_to_split + block->size - new_payload;

	new_block->next = block->next;
	new_block->prev = block;

	block->next->prev = new_block;
	block->next = new_block;

	block->size = (void *)new_block - space_to_split;
}

/** Preallocate heap for fewer future brk calls. */
static void preallocate_heap(void)
{
	void *prev_brk = sbrk(MMAP_TRESHOLD);

	DIE(prev_brk == (void *)-1, "fail brk() preallocation");

	small_pool = prev_brk;
	small_pool->next = small_pool;
	small_pool->prev = small_pool;
	small_pool->status = STATUS_FREE;
	small_pool->size = ALIGN(MMAP_TRESHOLD - ALIGN(sizeof(struct block_meta)));
}

/** Find the best block that can accomodate `size` bytes. */
static struct block_meta *find_best_block(size_t size)
{
	struct block_meta *iter = small_pool;
	struct block_meta *best_block = NULL;

	do {
		/* Skip allocated blocks. */
		if (iter->status == STATUS_ALLOC) {
			iter = iter->next;
			continue;
		}

		fold_merge(iter);
		/* Skip the block as it still is to small. */
		if (iter->size < size) {
			iter = iter->next;
			continue;
		}

		/* Find the best fit a.k.a. the smallest
		 * free block that can accomodate the size.
		 */
		if (best_block) {
			if (iter->size < best_block->size)
				best_block = iter;
		} else {
			best_block = iter;
		}

		iter = iter->next;
	} while (iter != small_pool);

	return best_block;
}

/** Create a new small block of `size`. */
static struct block_meta *new_small_block(size_t size)
{
	if (!small_pool)
		preallocate_heap();

	struct block_meta *best_block = find_best_block(size);

	if (best_block) {
		best_block->status = STATUS_ALLOC;
		split_block(best_block, size);
		return best_block;
	}

	struct block_meta *last_block = small_pool->prev;

	if (last_block->status == STATUS_ALLOC) {
		/* If the last block is occupied, extend
		 * the brk to accomodate for the new block.
		 */
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

	/* If the last block is free, extend
	 * the brk to include the size needed.
	 */
	size_t needed_space = ALIGN(size - last_block->size);

	DIE(sbrk(needed_space) == (void *)-1, "fail brk() extension");
	last_block->size = ALIGN(size);
	last_block->status = STATUS_ALLOC;
	return last_block;
}

/** Create a new large block of `size`. */
static struct block_meta *new_large_block(size_t size)
{
	size_t actual_size = ALIGN(size + ALIGN(sizeof(struct block_meta)));
	void *ptr = mmap(NULL, actual_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(ptr == MAP_FAILED, "fail mmap()");

	struct block_meta *block = ALIGN(ptr);

	block->status = STATUS_MAPPED;
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

/** Delete the large `block`. */
static void delete_large_block(struct block_meta *block)
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

/** Free the small block with `ptr`. */
static void free_small(void *ptr)
{
	struct block_meta *block = small_pool;

	if (!small_pool)
		return;

	do {
		if (get_payload(block) == ptr) {
			block->status = STATUS_FREE;
			return;
		}

		block = block->next;
	} while (block != small_pool);
}

/** Free the large block with `ptr`. */
static void free_large(void *ptr)
{
	struct block_meta *block = large_pool;

	if (!large_pool)
		return;

	do {
		if (get_payload(block) == ptr) {
			delete_large_block(block);
			return;
		}

		block = block->next;
	} while (block != large_pool);
}

/** Move the `prev_payload` of size `prev_size` into `new_block`. */
static void *move_into_new_block(void *prev_payload, size_t prev_size,
								 struct block_meta *new_block)
{
	void *new_payload = get_payload(new_block);

	memcpy(new_payload, prev_payload, prev_size);
	free_small(prev_payload);
	return new_payload;
}

/** Find the small block that contains `ptr` with the new `size`. */
static void *realloc_small(void *ptr, size_t size)
{
	struct block_meta *iter = small_pool;

	if (!small_pool)
		return NULL;

	do {
		void *payload = get_payload(iter);

		if (payload == ptr) {
			if (iter->status == STATUS_FREE)
				return NULL;

			if (iter->size >= size) {
				/* Shrink the block. */
				split_block(iter, size);
				return ptr;
			}

			if (size > MMAP_TRESHOLD) {
				/* If the new size is larger than the treshold,
				 * allocate a new large block and copy the data.
				 */
				return move_into_new_block(ptr, iter->size,
										   new_large_block(size));
			}

			if (iter->next == small_pool) {
				/* If this is the last block, extend the brk. */
				size_t needed_space = ALIGN(size - iter->size);

				DIE(sbrk(needed_space) == (void *)-1, "fail brk() extension");
				iter->size = ALIGN(size);
				return ptr;
			}

			fold_merge(iter);
			/* If the merged block is large enough, split it. */
			if (iter->size >= size) {
				split_block(iter, size);
				return ptr;
			}

			/* If the merged block is still not large enough,
			 * allocate a new block and copy the data.
			 */
			return move_into_new_block(ptr, iter->size, new_small_block(size));
		}

		iter = iter->next;
	} while (iter != small_pool);

	return NULL;
}

/** Realloc the large block that contains `ptr` with the new `size`. */
static void *realloc_large(void *ptr, size_t size)
{
	struct block_meta *iter = large_pool;

	if (!large_pool)
		return NULL;

	do {
		if (get_payload(iter) == ptr) {
			struct block_meta *new_ptr = os_malloc(size);

			memcpy(new_ptr, ptr, MIN(iter->size, size));
			delete_large_block(iter);
			return new_ptr;
		}

		iter = iter->next;
	} while (iter != large_pool);

	return NULL;
}
