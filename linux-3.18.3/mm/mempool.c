/*
 *  linux/mm/mempool.c
 *
 *  memory buffer pool support. Such pools are mostly used
 *  for guaranteed, deadlock-free memory allocations during
 *  extreme VM load.
 *
 *  started by Ingo Molnar, Copyright (C) 2001
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kmemleak.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>

static void add_element(mempool_t *pool, void *element)
{
	BUG_ON(pool->curr_nr >= pool->min_nr);
	pool->elements[pool->curr_nr++] = element;
}

static void *remove_element(mempool_t *pool)
{
	BUG_ON(pool->curr_nr <= 0);
	return pool->elements[--pool->curr_nr];
}

/**
 * mempool_destroy - deallocate a memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * Free all reserved elements in @pool and @pool itself.  This function
 * only sleeps if the free_fn() function sleeps.
 */
/* 销毁一个内存池 */
void mempool_destroy(mempool_t *pool)
{
	while (pool->curr_nr) {
		/* 销毁elements数组中的所有对象 */
		/* element = pool->elements[--pool->curr_nr] */
		void *element = remove_element(pool);
		pool->free(element, pool->pool_data);
	}
	/* 销毁elements指针数组 */
	kfree(pool->elements);
	/* 销毁内存池结构体 */
	kfree(pool);
}
EXPORT_SYMBOL(mempool_destroy);

/**
 * mempool_create - create a memory pool
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * this function creates and allocates a guaranteed size, preallocated
 * memory pool. The pool can be used from the mempool_alloc() and mempool_free()
 * functions. This function might sleep. Both the alloc_fn() and the free_fn()
 * functions might sleep - as long as the mempool_alloc() function is not called
 * from IRQ contexts.
 */
/* 创建一个内存池
 * min_nr: 内存池中存放的对象数量
 * alloc_fn: 分配函数
 * free_fn: 释放函数
 * pool_data: 私有成员变量
 */
mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
				mempool_free_t *free_fn, void *pool_data)
{
	return mempool_create_node(min_nr,alloc_fn,free_fn, pool_data,
				   GFP_KERNEL, NUMA_NO_NODE);
}
EXPORT_SYMBOL(mempool_create);

mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			       mempool_free_t *free_fn, void *pool_data,
			       gfp_t gfp_mask, int node_id)
{
	mempool_t *pool;
	/* 分配一个内存池结构体 */
	pool = kzalloc_node(sizeof(*pool), gfp_mask, node_id);
	if (!pool)
		return NULL;
	/* 分配一个长度为min_nr的数组用于存放申请后对象的指针 */
	pool->elements = kmalloc_node(min_nr * sizeof(void *),
				      gfp_mask, node_id);
	if (!pool->elements) {
		kfree(pool);
		return NULL;
	}
	/* 初始化锁 */
	spin_lock_init(&pool->lock);
	pool->min_nr = min_nr;
	/* 私有成员，当此内存池是从slab缓冲区获取内存对象时，可将此私有成员设置为目标slab缓冲区 */
	pool->pool_data = pool_data;
	/* 初始化等待队列 */
	init_waitqueue_head(&pool->wait);
	pool->alloc = alloc_fn;
	pool->free = free_fn;

	/*
	 * First pre-allocate the guaranteed number of buffers.
	 */
	/* pool->curr_nr初始为0，因为pool使用kzalloc_node分配的，会清0 */
	while (pool->curr_nr < pool->min_nr) {
		void *element;

		/* 调用pool->alloc函数min_nr次 */
		element = pool->alloc(gfp_mask, pool->pool_data);
		/* 如果申请不到element，则直接销毁此内存池 */
		if (unlikely(!element)) {
			mempool_destroy(pool);
			return NULL;
		}
		/* 添加到elements指针数组中 */
		add_element(pool, element);
	}
	/* 返回内存池结构体 */
	return pool;
}
EXPORT_SYMBOL(mempool_create_node);

/**
 * mempool_resize - resize an existing memory pool
 * @pool:       pointer to the memory pool which was allocated via
 *              mempool_create().
 * @new_min_nr: the new minimum number of elements guaranteed to be
 *              allocated for this pool.
 * @gfp_mask:   the usual allocation bitmask.
 *
 * This function shrinks/grows the pool. In the case of growing,
 * it cannot be guaranteed that the pool will be grown to the new
 * size immediately, but new mempool_free() calls will refill it.
 *
 * Note, the caller must guarantee that no mempool_destroy is called
 * while this function is running. mempool_alloc() & mempool_free()
 * might be called (eg. from IRQ contexts) while this function executes.
 */
int mempool_resize(mempool_t *pool, int new_min_nr, gfp_t gfp_mask)
{
	void *element;
	void **new_elements;
	unsigned long flags;

	BUG_ON(new_min_nr <= 0);

	spin_lock_irqsave(&pool->lock, flags);
	if (new_min_nr <= pool->min_nr) {
		while (new_min_nr < pool->curr_nr) {
			element = remove_element(pool);
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(element, pool->pool_data);
			spin_lock_irqsave(&pool->lock, flags);
		}
		pool->min_nr = new_min_nr;
		goto out_unlock;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	/* Grow the pool */
	new_elements = kmalloc(new_min_nr * sizeof(*new_elements), gfp_mask);
	if (!new_elements)
		return -ENOMEM;

	spin_lock_irqsave(&pool->lock, flags);
	if (unlikely(new_min_nr <= pool->min_nr)) {
		/* Raced, other resize will do our work */
		spin_unlock_irqrestore(&pool->lock, flags);
		kfree(new_elements);
		goto out;
	}
	memcpy(new_elements, pool->elements,
			pool->curr_nr * sizeof(*new_elements));
	kfree(pool->elements);
	pool->elements = new_elements;
	pool->min_nr = new_min_nr;

	while (pool->curr_nr < pool->min_nr) {
		spin_unlock_irqrestore(&pool->lock, flags);
		element = pool->alloc(gfp_mask, pool->pool_data);
		if (!element)
			goto out;
		spin_lock_irqsave(&pool->lock, flags);
		if (pool->curr_nr < pool->min_nr) {
			add_element(pool, element);
		} else {
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(element, pool->pool_data);	/* Raced */
			goto out;
		}
	}
out_unlock:
	spin_unlock_irqrestore(&pool->lock, flags);
out:
	return 0;
}
EXPORT_SYMBOL(mempool_resize);

/**
 * mempool_alloc - allocate an element from a specific memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 * @gfp_mask:  the usual allocation bitmask.
 *
 * this function only sleeps if the alloc_fn() function sleeps or
 * returns NULL. Note that due to preallocation, this function
 * *never* fails when called from process contexts. (it might
 * fail if called from an IRQ context.)
 * Note: using __GFP_ZERO is not supported.
 */
/* 内存池分配对象 */
void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	void *element;
	unsigned long flags;
	wait_queue_t wait;
	gfp_t gfp_temp;

	VM_WARN_ON_ONCE(gfp_mask & __GFP_ZERO);
	/* 如果有__GFP_WAIT标志，则会先阻塞，切换进程 */
	might_sleep_if(gfp_mask & __GFP_WAIT);

	/* 不使用预留内存 */
	gfp_mask |= __GFP_NOMEMALLOC;	/* don't allocate emergency reserves */
	/* 分配页时如果失败则返回，不进行重试 */
	gfp_mask |= __GFP_NORETRY;	/* don't loop in __alloc_pages */
	/* 分配失败不提供警告 */
	gfp_mask |= __GFP_NOWARN;	/* failures are OK */

	/* gfp_temp等于gfp_mask去除__GFP_WAIT和__GFP_IO的其他标志 */
	gfp_temp = gfp_mask & ~(__GFP_WAIT|__GFP_IO);

repeat_alloc:

	/* 使用内存池中的alloc函数进行分配对象，实际上就是从伙伴系统或者slab缓冲区获取内存对象 */
	element = pool->alloc(gfp_temp, pool->pool_data);
	/* 在内存富足的情况下，一般是能够获取到内存的 */
	if (likely(element != NULL))
		return element;

	/* 在内存不足的情况，造成从伙伴系统或slab缓冲区获取内存失败，则会执行到这 */
	/* 给内存池上锁，获取后此段临界区禁止中断和抢占 */
	spin_lock_irqsave(&pool->lock, flags);
	/* 如果当前内存池中有空闲数量，就是初始化时获取的内存数量保存在curr_nr中 */
	if (likely(pool->curr_nr)) {
		/* 从内存池中获取内存对象 */
		element = remove_element(pool);
		/* 解锁 */
		spin_unlock_irqrestore(&pool->lock, flags);
		
		/* paired with rmb in mempool_free(), read comment there */
		/* 写内存屏障，保证之前的写操作已经完成 */
		smp_wmb();
		/*
		 * Update the allocation stack trace as this is more useful
		 * for debugging.
		 */
		/* 用于debug */
		kmemleak_update_trace(element);
		return element;
	}

	/*
	 * We use gfp mask w/o __GFP_WAIT or IO for the first round.  If
	 * alloc failed with that and @pool was empty, retry immediately.
	 */
	/* 这里是内存池中也没有空闲内存对象的时候进行的操作 */
	/* gfp_temp != gfp_mask说明传入的gfp_mask允许阻塞等待，但是之前已经阻塞等待过了，所以这里立即重新获取一次 */
	if (gfp_temp != gfp_mask) {
		spin_unlock_irqrestore(&pool->lock, flags);
		gfp_temp = gfp_mask;
		goto repeat_alloc;
	}

	/* We must not sleep if !__GFP_WAIT */
	/* 传入的参数gfp_mask不允许阻塞等待，分配不到内存则直接退出 */
	if (!(gfp_mask & __GFP_WAIT)) {
		spin_unlock_irqrestore(&pool->lock, flags);
		return NULL;
	}

	/* Let's wait for someone else to return an element to @pool */
	init_wait(&wait);
	/* 加入到内存池的等待队列中，并把当前进程的状态设置为只有wake_up信号才能唤醒的状态，也就是当内存池中有空闲对象时，会主动唤醒等待队列中的第一个进程，或者等待超时时，定时器自动唤醒 */
	prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);

	spin_unlock_irqrestore(&pool->lock, flags);

	/*
	 * FIXME: this should be io_schedule().  The timeout is there as a
	 * workaround for some DM problems in 2.6.18.
	 */
	/* 阻塞等待5秒 */
	io_schedule_timeout(5*HZ);

	/* 从内存池的等待队列删除此进程 */
	finish_wait(&pool->wait, &wait);
	/* 跳转到repeat_alloc，重新尝试获取内存对象 */
	goto repeat_alloc;
}
EXPORT_SYMBOL(mempool_alloc);

/**
 * mempool_free - return an element to the pool.
 * @element:   pool element pointer.
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * this function only sleeps if the free_fn() function sleeps.
 */
/* 内存池释放内存对象操作 */
void mempool_free(void *element, mempool_t *pool)
{
	unsigned long flags;

	/* 传入的对象为空，则直接退出 */
	if (unlikely(element == NULL))
		return;

	/*
	 * Paired with the wmb in mempool_alloc().  The preceding read is
	 * for @element and the following @pool->curr_nr.  This ensures
	 * that the visible value of @pool->curr_nr is from after the
	 * allocation of @element.  This is necessary for fringe cases
	 * where @element was passed to this task without going through
	 * barriers.
	 *
	 * For example, assume @p is %NULL at the beginning and one task
	 * performs "p = mempool_alloc(...);" while another task is doing
	 * "while (!p) cpu_relax(); mempool_free(p, ...);".  This function
	 * may end up using curr_nr value which is from before allocation
	 * of @p without the following rmb.
	 */
	/* 读内存屏障 */
	smp_rmb();

	/*
	 * For correctness, we need a test which is guaranteed to trigger
	 * if curr_nr + #allocated == min_nr.  Testing curr_nr < min_nr
	 * without locking achieves that and refilling as soon as possible
	 * is desirable.
	 *
	 * Because curr_nr visible here is always a value after the
	 * allocation of @element, any task which decremented curr_nr below
	 * min_nr is guaranteed to see curr_nr < min_nr unless curr_nr gets
	 * incremented to min_nr afterwards.  If curr_nr gets incremented
	 * to min_nr after the allocation of @element, the elements
	 * allocated after that are subject to the same guarantee.
	 *
	 * Waiters happen iff curr_nr is 0 and the above guarantee also
	 * ensures that there will be frees which return elements to the
	 * pool waking up the waiters.
	 */
	/* 如果当前内存池中空闲的内存对象少于内存池中应当保存的内存对象的数量时，优先把释放的对象加入到内存池空闲数组中 */
	if (unlikely(pool->curr_nr < pool->min_nr)) {
		spin_lock_irqsave(&pool->lock, flags);
		if (likely(pool->curr_nr < pool->min_nr)) {
			/* 加入到pool->elements[pool->curr_nr++]中 */
			add_element(pool, element);
			spin_unlock_irqrestore(&pool->lock, flags);
			/* 唤醒等待队列中的第一个进程 */
			wake_up(&pool->wait);
			return;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}
	/* 直接调用释放函数 */
	pool->free(element, pool->pool_data);
}
EXPORT_SYMBOL(mempool_free);

/*
 * A commonly used alloc and free fn.
 */
/* 若内存池从slab缓冲区中获取内存对象，则内核提供的alloc函数 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	return kmem_cache_alloc(mem, gfp_mask);
}
EXPORT_SYMBOL(mempool_alloc_slab);

/* 若内存池从slab缓冲区中获取内存对象，则内核提供的free函数 */
void mempool_free_slab(void *element, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	kmem_cache_free(mem, element);
}
EXPORT_SYMBOL(mempool_free_slab);

/*
 * A commonly used alloc and free fn that kmalloc/kfrees the amount of memory
 * specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
{
	size_t size = (size_t)pool_data;
	return kmalloc(size, gfp_mask);
}
EXPORT_SYMBOL(mempool_kmalloc);

void mempool_kfree(void *element, void *pool_data)
{
	kfree(element);
}
EXPORT_SYMBOL(mempool_kfree);

/*
 * A simple mempool-backed page allocator that allocates pages
 * of the order specified by pool_data.
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
{
	int order = (int)(long)pool_data;
	return alloc_pages(gfp_mask, order);
}
EXPORT_SYMBOL(mempool_alloc_pages);

void mempool_free_pages(void *element, void *pool_data)
{
	int order = (int)(long)pool_data;
	__free_pages(element, order);
}
EXPORT_SYMBOL(mempool_free_pages);
