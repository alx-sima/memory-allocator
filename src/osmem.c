// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <unistd.h>

#include "block_meta.h"
#include "osmem.h"

#define MMAP_TRESHOLD (128 << 10) /* 128 kb */

static struct block_meta *small_pool;

static inline void *align(void *addr)
{
	return (void *)((long)(addr + (8 - 1)) & -8);
}

void *malloc_small(size_t size)
{
	if (!small_pool) {
		/* Preallocate heap for fewer future brk calls. */
		void *prev_brk = sbrk(MMAP_TRESHOLD);
		DIE((long)prev_brk < 0, "fail brk() preallocation");

		small_pool = prev_brk;
		small_pool->next = NULL;
		small_pool->prev = NULL;
		small_pool->status = STATUS_MAPPED;
		small_pool->size = MMAP_TRESHOLD - sizeof(struct block_meta);

		return align(small_pool + 1);
	}

	struct block_meta *iter = small_pool;
	while (iter) {
		/* Skip allocated blocks or blocks to small for this size. */
		if (iter->size < size || iter->status == STATUS_ALLOC) {
			iter = iter->next;
			continue;
		}

		iter->status = STATUS_ALLOC;

		void *payload = align(iter + 1);
		void *payload_end = payload + iter->size;

		size_t remaining = payload_end - payload;
		if (remaining <= sizeof(struct block_meta)) {
			/* No place for new block. */
			return payload;
		}

		/* Split the block to create a new one with the free space. */

		struct block_meta *new_block = align(payload + size);
		new_block->status = STATUS_FREE;

		new_block->next = iter->next;
		new_block->prev = iter;
		if (iter->next) {
			iter->next->prev = new_block;
		}
		iter->next = new_block;

		new_block->size = payload_end - align(new_block + 1);
		iter->size = (void *)new_block - payload;

		return payload;
	}

	/* TODO: extend brk if not enough space */
	return NULL;
}

void *os_malloc(size_t size)
{
	if (!size) {
		return NULL;
	}

	if (size < MMAP_TRESHOLD) {
		return malloc_small(size);
	}

	/* TODO: Implement allocation of large chunks */
	return NULL;
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
