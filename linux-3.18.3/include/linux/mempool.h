/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/wait.h>

struct kmem_cache;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

/* 内存池，用于拥有该内存池的"拥有者"进行内存储备，只有在常规情况下分配不到内存的时候才会使用自己的内存池 */
typedef struct mempool_s {
	spinlock_t lock;
	/* 最大元素个数，也是初始个数 */
	int min_nr;		/* nr of elements at *elements */
	/* 当前元素个数 */
	int curr_nr;		/* Current nr of elements at *elements */
	/* 指向一个数组，数组中保存指向元素指针，当调用alloc方法后，指针才会有效 */
	void **elements;

	/* 内存池的拥有者的私有数据结构，当元素是slab中的对象时，这里保存的是slab缓存描述符 */
	void *pool_data;
	/* 当元素是slab中的对象时，会使用方法mempool_alloc_slab()和mempool_free_slab() */
	/* 分配一个元素的方法 */
	mempool_alloc_t *alloc;
	/* 释放一个元素的方法 */
	mempool_free_t *free;
	/* 当内存池为空时使用的等待队列 */
	wait_queue_head_t wait;
} mempool_t;

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);
extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data,
			gfp_t gfp_mask, int nid);

extern int mempool_resize(mempool_t *pool, int new_min_nr, gfp_t gfp_mask);
extern void mempool_destroy(mempool_t *pool);
extern void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab that is passed in through pool_data.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);
static inline mempool_t *
mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
{
	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
			      (void *) kc);
}

/*
 * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
 * amount of memory specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
void mempool_kfree(void *element, void *pool_data);
static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
{
	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
			      (void *) size);
}

/*
 * A mempool_alloc_t and mempool_free_t for a simple page allocator that
 * allocates pages of the order specified by pool_data
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
void mempool_free_pages(void *element, void *pool_data);
static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
{
	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
			      (void *)(long)order);
}

#endif /* _LINUX_MEMPOOL_H */
