// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "block_meta.h"
#include "osmem.h"

#define MMAP_TRESHOLD (128 << 10) /* 128 kb */

static struct block_meta *small_pool;
static struct block_meta *large_pool;

static inline void *align(void *addr)
{
	return (void *)((long)(addr + (8 - 1)) & -8);
}

static inline void *get_payload(struct block_meta *bm)
{
	return align(bm + 1);
}

struct block_meta *split_block(struct block_meta *block, size_t size)
{
	void *space_to_split = get_payload(block);
	struct block_meta *new_block = align(space_to_split + size);
	new_block->status = STATUS_MAPPED;
	new_block->size = size;

	new_block->next = block->next;
	new_block->prev = block;

	if (new_block->next) {
		block->next->prev = new_block;
	}
	block->next = new_block;

	block->size = (void *)new_block - space_to_split;

	return new_block;
}

void *malloc_small(size_t size)
{
	if (!small_pool) {
		/* Preallocate heap for fewer future brk calls. */
		void *prev_brk = sbrk(MMAP_TRESHOLD);
		DIE(prev_brk == (void *)-1, "fail brk() preallocation");

		small_pool = prev_brk;
		small_pool->next = NULL;
		small_pool->prev = NULL;
		small_pool->status = STATUS_MAPPED;
		small_pool->size = MMAP_TRESHOLD - sizeof(struct block_meta);
	}

	struct block_meta *iter = small_pool;
	while (iter->next) {
		/* Skip allocated blocks or blocks to small for this size. */
		if (iter->size < size || iter->status == STATUS_ALLOC) {
			iter = iter->next;
			continue;
		}

		iter->status = STATUS_ALLOC;

		void *payload = get_payload(iter);
		void *payload_end = payload + iter->size;

		size_t remaining = payload_end - payload;
		if (remaining <= sizeof(struct block_meta)) {
			/* No place for new block. */
			return payload;
		}

		/* Split the block to create a new one with the free space. */

		struct block_meta *new_block = split_block(iter, size);
		return get_payload(new_block);
	}

	if (iter->status == STATUS_ALLOC) {
		/* If the last block is occupied, extend
		 * the brk to accomodate for the new block. */

		void *brk_end = get_payload(iter) + iter->size;

		struct block_meta *new_block = align(brk_end);
		void *new_payload = get_payload(new_block);

		size_t needed_space = (void *)new_block + size - brk_end;
		DIE(sbrk(needed_space) == (void *)-1, "fail brk() extension");

		iter->next = new_block;
		new_block->next = NULL;
		new_block->prev = iter;
		new_block->size = size;
		new_block->status = STATUS_ALLOC;

		return new_payload;
	}

	/* If the last block is free, extend the
	 * brk to include the size needed. */
	void *payload = get_payload(iter);
	size_t needed_space = size - iter->size;
	DIE(sbrk(needed_space) == (void *)-1, "fail brk() extension");
	iter->size = size;
	return payload;
}

void *malloc_large(size_t size)
{

	size_t actual_size = size + align(sizeof(struct block_meta));
	void *ptr = mmap(NULL, actual_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE(ptr == MAP_FAILED, "fail mmap()");

	struct block_meta *bm = align(ptr);
	bm->status = STATUS_ALLOC;
	bm->size = actual_size;
	bm->next = NULL;

	struct block_meta *last_block = large_pool;
	if (!last_block) {
		bm->prev = NULL;
		large_pool = bm;
		return get_payload(bm);
	}

	while (last_block->next) {
		last_block = last_block->next;
	}

	last_block->next = bm;
	bm->prev = last_block;
	return get_payload(bm);
}

void *os_malloc(size_t size)
{
	if (!size) {
		return NULL;
	}

	if (size < MMAP_TRESHOLD) {
		return malloc_small(size);
	}

	return malloc_large(size);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	(void)ptr;
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

	/* TODO: Implement os_realloc */
	return NULL;
}
