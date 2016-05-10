/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins 2003, 2004
 */

/*
 * Lock ordering in mm:
 *
 * inode->i_mutex	(while writing or truncating, not reading or faulting)
 *   mm->mmap_sem
 *     page->flags PG_locked (lock_page)
 *       mapping->i_mmap_mutex
 *         anon_vma->rwsem
 *           mm->page_table_lock or pte_lock
 *             zone->lru_lock (in mark_page_accessed, isolate_lru_page)
 *             swap_lock (in swap_duplicate, swap_info_get)
 *               mmlist_lock (in mmput, drain_mmlist and others)
 *               mapping->private_lock (in __set_page_dirty_buffers)
 *               inode->i_lock (in set_page_dirty's __mark_inode_dirty)
 *               bdi.wb->list_lock (in set_page_dirty's __mark_inode_dirty)
 *                 sb_lock (within inode_lock in fs/fs-writeback.c)
 *                 mapping->tree_lock (widely used, in set_page_dirty,
 *                           in arch-dependent flush_dcache_mmap_lock,
 *                           within bdi.wb->list_lock in __sync_single_inode)
 *
 * anon_vma->rwsem,mapping->i_mutex      (memory_failure, collect_procs_anon)
 *   ->tasklist_lock
 *     pte map lock
 */

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/backing-dev.h>

#include <asm/tlbflush.h>

#include "internal.h"

static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;

/* 从anon_vma_cachep这个slab中分配一个anon_vma结构，将其refcount设为1，anon_vma->root指向本身 */
static inline struct anon_vma *anon_vma_alloc(void)
{
	struct anon_vma *anon_vma;

	/* 从anon_vma_cachep这个slab中分配一个anon_vma结构 */
	anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_KERNEL);
	if (anon_vma) {
		/* 分配成功，新的anon_vma->refcount设置为1 */
		atomic_set(&anon_vma->refcount, 1);
		/*
		 * Initialise the anon_vma root to point to itself. If called
		 * from fork, the root will be reset to the parents anon_vma.
		 */
		/* 新的anon_vma的root指向本身 */
		anon_vma->root = anon_vma;
	}
	
	/* 返回分配成功的anon_vma */
	return anon_vma;
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
	VM_BUG_ON(atomic_read(&anon_vma->refcount));

	/*
	 * Synchronize against page_lock_anon_vma_read() such that
	 * we can safely hold the lock without the anon_vma getting
	 * freed.
	 *
	 * Relies on the full mb implied by the atomic_dec_and_test() from
	 * put_anon_vma() against the acquire barrier implied by
	 * down_read_trylock() from page_lock_anon_vma_read(). This orders:
	 *
	 * page_lock_anon_vma_read()	VS	put_anon_vma()
	 *   down_read_trylock()		  atomic_dec_and_test()
	 *   LOCK				  MB
	 *   atomic_read()			  rwsem_is_locked()
	 *
	 * LOCK should suffice since the actual taking of the lock must
	 * happen _before_ what follows.
	 */
	might_sleep();
	if (rwsem_is_locked(&anon_vma->root->rwsem)) {
		anon_vma_lock_write(anon_vma);
		anon_vma_unlock_write(anon_vma);
	}

	kmem_cache_free(anon_vma_cachep, anon_vma);
}

static inline struct anon_vma_chain *anon_vma_chain_alloc(gfp_t gfp)
{
	return kmem_cache_alloc(anon_vma_chain_cachep, gfp);
}

static void anon_vma_chain_free(struct anon_vma_chain *anon_vma_chain)
{
	kmem_cache_free(anon_vma_chain_cachep, anon_vma_chain);
}

static void anon_vma_chain_link(struct vm_area_struct *vma,
				struct anon_vma_chain *avc,
				struct anon_vma *anon_vma)
{
	avc->vma = vma;
	avc->anon_vma = anon_vma;
	/* 将新的avc->same_vma加入到vma的anon_vma_chain链表头部 */
	list_add(&avc->same_vma, &vma->anon_vma_chain);
	/* 将avc->rb加入到anon_vma的红黑树中 */
	anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
}

/**
 * anon_vma_prepare - attach an anon_vma to a memory region
 * @vma: the memory region in question
 *
 * This makes sure the memory mapping described by 'vma' has
 * an 'anon_vma' attached to it, so that we can associate the
 * anonymous pages mapped into it with that anon_vma.
 *
 * The common case will be that we already have one, but if
 * not we either need to find an adjacent mapping that we
 * can re-use the anon_vma from (very common when the only
 * reason for splitting a vma has been mprotect()), or we
 * allocate a new one.
 *
 * Anon-vma allocations are very subtle, because we may have
 * optimistically looked up an anon_vma in page_lock_anon_vma_read()
 * and that may actually touch the spinlock even in the newly
 * allocated vma (it depends on RCU to make sure that the
 * anon_vma isn't actually destroyed).
 *
 * As a result, we need to do proper anon_vma locking even
 * for the new allocation. At the same time, we do not want
 * to do any locking for the common case of already having
 * an anon_vma.
 *
 * This must be called with the mmap_sem held for reading.
 */
/* 为vma准备反向映射条件 
 * 检查此vma能与前后的vma进行合并吗，如果可以，则使用能够合并的那个vma的anon_vma，如果不能够合并，则申请一个空闲的anon_vma
 * 创建一个新的anon_vma_chain
 * 将avc->anon_vma指向获得的vma(此vma可能是新建的，也可能是可以合并的vma的anon_vma)，avc->vma指向vma，并把avc加入到vma的anon_vma_chain中
 */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	/* 获取vma的反向映射的anon_vma结构 */
	struct anon_vma *anon_vma = vma->anon_vma;
	struct anon_vma_chain *avc;

	/* 检查是否需要睡眠 */
	might_sleep();
	/* 如果此vma的anon_vma为空，则进行以下处理 */
	if (unlikely(!anon_vma)) {
		/* 获取vma所属的mm */
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated;

		/* 通过slab/slub分配一个struct anon_vma_chain */
		avc = anon_vma_chain_alloc(GFP_KERNEL);
		if (!avc)
			goto out_enomem;

		/* 检查vma能否与其前/后vma进行合并，如果可以，则返回能够合并的那个vma的anon_vma，如果不可以，返回NULL
		 * 主要检查vma前后的vma是否连在一起(vma->vm_end == 前/后vma->vm_start)
		 * vma->vm_policy和前/后vma->vm_policy
		 * 是否都为文件映射，除了(VM_READ|VM_WRITE|VM_EXEC|VM_SOFTDIRTY)其他标志位是否相同，如果为文件映射，前/后vma映射的文件位置是否正好等于vma映射的文件 + vma的长度
		 * 这里有个疑问，为什么匿名线性区会有vm_file不为空的时候，我也没找到原因
		 * 可以合并，则返回可合并的线性区的anon_vma
		 */
		anon_vma = find_mergeable_anon_vma(vma);
		allocated = NULL;
		/* anon_vma为空，也就是vma不能与前后的vma合并，则会分配一个 */
		if (!anon_vma) {
			
			/* 从anon_vma_cachep这个slab中分配一个anon_vma结构，将其refcount设为1，anon_vma->root指向本身 */
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				goto out_enomem_free_avc;
			/* 刚分配好的anon_vma存放在allocated */
			allocated = anon_vma;
		}

		/* 到这里，anon_vma有可能是可以合并的vma的anon_vma，也有可能是刚分配的anon_vma */
		
		/* 对anon_vma->root->rwsem上写锁，如果是新分配的anon_vma则是其本身的rwsem */
		anon_vma_lock_write(anon_vma);
		/* page_table_lock to protect against threads */
		/* 获取当前进程的线性区锁 */
		spin_lock(&mm->page_table_lock);
		/* 如果vma->anon_vma为空，这是很可能发生的，因为此函数开头获取的anon_vma为空才会走到这条代码路径上 */
		if (likely(!vma->anon_vma)) {
			/* 将vma->anon_vma设置为新分配的anon_vma，这个anon_vma也可能是前后能够合并的vma的anon_vma */
			vma->anon_vma = anon_vma;
			/*
			 * avc->vma = vma
			 * avc->anon_vma = anon_vma(这个可能是当前vma的anon_vma，也可能是前后可合并vma的anon_vma)
			 * 将新的avc->same_vma加入到vma的anon_vma_chain链表中
			 * 将新的avc->rb加入到anon_vma的红黑树中
			 */
			anon_vma_chain_link(vma, avc, anon_vma);
			/* 这两个置空，后面就不会释放掉 */
			allocated = NULL;
			avc = NULL;
		}
		/* mm的页表的锁 */
		spin_unlock(&mm->page_table_lock);
		/* 释放anon_vma的写锁 */
		anon_vma_unlock_write(anon_vma);

		if (unlikely(allocated))
			put_anon_vma(allocated);
		if (unlikely(avc))
			anon_vma_chain_free(avc);
	}
	return 0;

 out_enomem_free_avc:
	anon_vma_chain_free(avc);
 out_enomem:
	return -ENOMEM;
}

/*
 * This is a useful helper function for locking the anon_vma root as
 * we traverse the vma->anon_vma_chain, looping over anon_vma's that
 * have the same vma.
 *
 * Such anon_vma's should have the same root, so you'd expect to see
 * just a single mutex_lock for the whole traversal.
 */
/* anon_vma是父节点的anon_vma */
static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
	/* 获取anon_vma的红黑树的根，这个root初始化后是指向本身这个anon_vma的 */
	struct anon_vma *new_root = anon_vma->root;
	/* 如果new_root != root，则对root上锁 */
	if (new_root != root) {
		if (WARN_ON_ONCE(root))
			up_write(&root->rwsem);
		root = new_root;
		down_write(&root->rwsem);
	}
	return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
	if (root)
		up_write(&root->rwsem);
}

/*
 * Attach the anon_vmas from src to dst.
 * Returns 0 on success, -ENOMEM on failure.
 */
/* dst为子进程的vma，src为父进程的vma */
int anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct anon_vma_chain *avc, *pavc;
	struct anon_vma *root = NULL;

	/* 遍历父进程的每个anon_vma_chain链表中的结点，保存在pavc中 */
	list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma;

		/* 分配一个新的avc结构 */
		avc = anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
		/* 如果分配失败 */
		if (unlikely(!avc)) {
			unlock_anon_vma_root(root);
			root = NULL;
			/* 再次分配，一定要分配成功 */
			avc = anon_vma_chain_alloc(GFP_KERNEL);
			if (!avc)
				goto enomem_failure;
		}
		/* 获取父结点的pavc指向的anon_vma */
		anon_vma = pavc->anon_vma;
		/* 对anon_vma的root上锁
		 * 如果root != anon_vma->root，则对root上锁，并返回anon_vma->root
		 * 第一次循环，root = NULL
		 */
		root = lock_anon_vma_root(root, anon_vma);
		/* 
		 * 设置新的avc->vma指向子进程的vma
		 * 设置新的avc->anon_vma指向父进程anon_vma_chain结点指向的anon_vma(这个anon_vma不一定属于父进程)
		 * 将新的avc->same_vma加入到子进程的anon_vma_chain链表头部
		 * 将新的avc->rb加入到父进程anon_vma_chain结点指向的anon_vma
		 */
		anon_vma_chain_link(dst, avc, anon_vma);
	}
	/* 释放根的锁 */
	unlock_anon_vma_root(root);
	return 0;

 enomem_failure:
	unlink_anon_vmas(dst);
	return -ENOMEM;
}

/*
 * Attach vma to its own anon_vma, as well as to the anon_vmas that
 * the corresponding VMA in the parent process is attached to.
 * Returns 0 on success, non-zero on failure.
 */
/* vma为子进程的vma，pvma为父进程的vma，如果父进程的此vma没有anon_vma，直接返回 */
int anon_vma_fork(struct vm_area_struct *vma, struct vm_area_struct *pvma)
{
	struct anon_vma_chain *avc;
	struct anon_vma *anon_vma;
	int error;

	/* Don't bother if the parent process has no anon_vma here. */
	/* 父进程的此vma没有anon_vma，直接返回 */
	if (!pvma->anon_vma)
		return 0;

	/*
	 * First, attach the new VMA to the parent VMA's anon_vmas,
	 * so rmap can find non-COWed pages in child processes.
	 */
	/* 这里开始先检查父进程的此vma是否有anon_vma，有则继续，而上面进行了判断，只有父进程的此vma有anon_vma才会执行到这里
	 * 这里会遍历父进程的vma的anon_vma_chain链表，对每个结点新建一个anon_vma_chain，然后
	 * 设置新的avc->vma指向子进程的vma
	 * 设置新的avc->anon_vma指向父进程anon_vma_chain结点指向的anon_vma(这个anon_vma不一定属于父进程)
	 * 将新的avc->same_vma加入到子进程的anon_vma_chain链表中
	 * 将新的avc->rb加入到父进程anon_vma_chain结点指向的anon_vma
	 */
	error = anon_vma_clone(vma, pvma);
	if (error)
		return error;

	/* Then add our own anon_vma. */
	/* 分配一个anon_vma结构用于子进程，将其refcount设为1，anon_vma->root指向本身
	 * 即使此vma是用于映射文件的，也会分配一个anon_vma
	 */
	anon_vma = anon_vma_alloc();
	if (!anon_vma)
		goto out_error;
	/* 分配一个struct anon_vma_chain结构 */
	avc = anon_vma_chain_alloc(GFP_KERNEL);
	if (!avc)
		goto out_error_free_anon_vma;

	/*
	 * The root anon_vma's spinlock is the lock actually used when we
	 * lock any of the anon_vmas in this anon_vma tree.
	 */
	/* 将新的anon_vma的root指向父进程的anon_vma的root */
	anon_vma->root = pvma->anon_vma->root;
	/*
	 * With refcounts, an anon_vma can stay around longer than the
	 * process it belongs to. The root anon_vma needs to be pinned until
	 * this anon_vma is freed, because the lock lives in the root.
	 */
	/* 对父进程与子进程的anon_vma共同的root的refcount进行+1 */
	get_anon_vma(anon_vma->root);
	/* Mark this anon_vma as the one where our new (COWed) pages go. */
	vma->anon_vma = anon_vma;
	/* 对这个新的anon_vma上锁 */
	anon_vma_lock_write(anon_vma);
	/* 新的avc的vma指向子进程的vma
	 * 新的avc的anon_vma指向子进程vma的anon_vma
	 * 新的avc的same_vma加入到子进程vma的anon_vma_chain链表的头部
	 * 新的avc的rb加入到子进程vma的anon_vma的红黑树中
	 */
	anon_vma_chain_link(vma, avc, anon_vma);
	/* 对这个anon_vma解锁 */
	anon_vma_unlock_write(anon_vma);

	return 0;

 out_error_free_anon_vma:
	put_anon_vma(anon_vma);
 out_error:
	unlink_anon_vmas(vma);
	return -ENOMEM;
}

void unlink_anon_vmas(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc, *next;
	struct anon_vma *root = NULL;

	/*
	 * Unlink each anon_vma chained to the VMA.  This list is ordered
	 * from newest to oldest, ensuring the root anon_vma gets freed last.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_interval_tree_remove(avc, &anon_vma->rb_root);

		/*
		 * Leave empty anon_vmas on the list - we'll need
		 * to free them outside the lock.
		 */
		if (RB_EMPTY_ROOT(&anon_vma->rb_root))
			continue;

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
	unlock_anon_vma_root(root);

	/*
	 * Iterate the list once more, it now only contains empty and unlinked
	 * anon_vmas, destroy them. Could not do before due to __put_anon_vma()
	 * needing to write-acquire the anon_vma->root->rwsem.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		put_anon_vma(anon_vma);

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
}

static void anon_vma_ctor(void *data)
{
	struct anon_vma *anon_vma = data;

	init_rwsem(&anon_vma->rwsem);
	atomic_set(&anon_vma->refcount, 0);
	anon_vma->rb_root = RB_ROOT;
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor);
	anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain, SLAB_PANIC);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is tricky!
 *
 * Since there is no serialization what so ever against page_remove_rmap()
 * the best this function can do is return a locked anon_vma that might
 * have been relevant to this page.
 *
 * The page might have been remapped to a different anon_vma or the anon_vma
 * returned may already be freed (and even reused).
 *
 * In case it was remapped to a different anon_vma, the new anon_vma will be a
 * child of the old anon_vma, and the anon_vma lifetime rules will therefore
 * ensure that any anon_vma obtained from the page will still be valid for as
 * long as we observe page_mapped() [ hence all those page_mapped() tests ].
 *
 * All users of this function must be very careful when walking the anon_vma
 * chain and verify that the page in question is indeed mapped in it
 * [ something equivalent to page_mapped_in_vma() ].
 *
 * Since anon_vma's slab is DESTROY_BY_RCU and we know from page_remove_rmap()
 * that the anon_vma pointer from page->mapping is valid if there is a
 * mapcount, we can dereference the anon_vma after observing those.
 */
/* 获取匿名页所指向的anon_vma，如果是文件页，则返回NULL */
struct anon_vma *page_get_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long) ACCESS_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	/*
	 * If this page is still mapped, then its anon_vma cannot have been
	 * freed.  But if it has been unmapped, we have no security against the
	 * anon_vma structure being freed and reused (for another anon_vma:
	 * SLAB_DESTROY_BY_RCU guarantees that - so the atomic_inc_not_zero()
	 * above cannot corrupt).
	 */
	if (!page_mapped(page)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}
out:
	rcu_read_unlock();

	return anon_vma;
}

/*
 * Similar to page_get_anon_vma() except it locks the anon_vma.
 *
 * Its a little more complex as it tries to keep the fast path to a single
 * atomic op -- the trylock. If we fail the trylock, we fall back to getting a
 * reference like with page_get_anon_vma() and then block on the mutex.
 */
/* 获取page的anon_vma，并对其上读锁 */
struct anon_vma *page_lock_anon_vma_read(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	struct anon_vma *root_anon_vma;
	unsigned long anon_mapping;

	/* 上rcu读锁 */
	rcu_read_lock();
	/* 获取page->mapping */
	anon_mapping = (unsigned long) ACCESS_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	/* 检查page是否有被线性区引用，page->_mapcount >= 0 */
	if (!page_mapped(page))
		goto out;

	/* 获取page对应的anon_vma，page->mapping最低两位用于判断，其他位用于保存指向的地址 */
	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	root_anon_vma = ACCESS_ONCE(anon_vma->root);
	if (down_read_trylock(&root_anon_vma->rwsem)) {
		/*
		 * If the page is still mapped, then this anon_vma is still
		 * its anon_vma, and holding the mutex ensures that it will
		 * not go away, see anon_vma_free().
		 */
		if (!page_mapped(page)) {
			up_read(&root_anon_vma->rwsem);
			anon_vma = NULL;
		}
		goto out;
	}

	/* trylock failed, we got to sleep */
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	if (!page_mapped(page)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}

	/* we pinned the anon_vma, its safe to sleep */
	rcu_read_unlock();
	anon_vma_lock_read(anon_vma);

	if (atomic_dec_and_test(&anon_vma->refcount)) {
		/*
		 * Oops, we held the last refcount, release the lock
		 * and bail -- can't simply use put_anon_vma() because
		 * we'll deadlock on the anon_vma_lock_write() recursion.
		 */
		anon_vma_unlock_read(anon_vma);
		__put_anon_vma(anon_vma);
		anon_vma = NULL;
	}

	return anon_vma;

out:
	rcu_read_unlock();
	return anon_vma;
}

void page_unlock_anon_vma_read(struct anon_vma *anon_vma)
{
	anon_vma_unlock_read(anon_vma);
}

/*
 * At what user virtual address is page expected in @vma?
 */
static inline unsigned long
__vma_address(struct page *page, struct vm_area_struct *vma)
{
	/* 获取此页在vma所属进程地址空间的线性地址
	 * 如果是匿名线性区，page->index中保存的是此页映射到了匿名线性区中的虚拟页框号
	 */
	pgoff_t pgoff = page_to_pgoff(page);
	/* vma->vm_pgoff保存vma起始地址所在的虚拟页框号 
	 * pgoff保存的是page在此vma的进程地址空间的虚拟页框号
	 * vma->vm_start保存的是vma的起始地址
	 */
	return vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
}

inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address = __vma_address(page, vma);

	/* page should be within @vma mapping range */
	VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);

	return address;
}

/*
 * At what user virtual address is page expected in vma?
 * Caller should check the page is actually part of the vma.
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	if (PageAnon(page)) {
		struct anon_vma *page__anon_vma = page_anon_vma(page);
		/*
		 * Note: swapoff's unuse_vma() is more efficient with this
		 * check, and needs it to match anon_vma when KSM is active.
		 */
		if (!vma->anon_vma || !page__anon_vma ||
		    vma->anon_vma->root != page__anon_vma->root)
			return -EFAULT;
	} else if (page->mapping && !(vma->vm_flags & VM_NONLINEAR)) {
		if (!vma->vm_file ||
		    vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	address = __vma_address(page, vma);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		return -EFAULT;
	return address;
}

pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;
	pmd_t pmde;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	/*
	 * Some THP functions use the sequence pmdp_clear_flush(), set_pmd_at()
	 * without holding anon_vma lock for write.  So when looking for a
	 * genuine pmde (in which to find pte), test present and !THP together.
	 */
	pmde = ACCESS_ONCE(*pmd);
	if (!pmd_present(pmde) || pmd_trans_huge(pmde))
		pmd = NULL;
out:
	return pmd;
}

/*
 * Check that @page is mapped at @address into @mm.
 *
 * If @sync is false, page_check_address may perform a racy check to avoid
 * the page table lock when the pte is not present (helpful when reclaiming
 * highly shared pages).
 *
 * On success returns with pte mapped and locked.
 */
pte_t *__page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync)
{
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (unlikely(PageHuge(page))) {
		/* when pud is not present, pte will be NULL */
		pte = huge_pte_offset(mm, address);
		if (!pte)
			return NULL;

		ptl = huge_pte_lockptr(page_hstate(page), mm, pte);
		goto check;
	}

	/* 根据address，获取address对应的页中间目录项 */
	pmd = mm_find_pmd(mm, address);
	if (!pmd)
		return NULL;

	/* 根据页中间目录项pmd，获取address对应的页表项 */
	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	/* 如果页表项pte映射的页不在内存中 */
	if (!sync && !pte_present(*pte)) {
		/* 那么就取消此页表项到page的映射 */
		pte_unmap(pte);
		return NULL;
	}

	/* 获取锁(并不是上锁，而是指向锁的指针)，此锁可能是mm->page_table_lock也可能在pmd对应页描述符的ptl */
	ptl = pte_lockptr(mm, pmd);
check:
	/* 上锁 */
	spin_lock(ptl);
	/* 此页表项pte映射的就是此page */
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		/* 返回页表项 */
		return pte;
	}
	/* 页表项pte映射的不是此页，释放锁 */
	pte_unmap_unlock(pte, ptl);
	/* 此mm没有映射此page，返回NULL */
	return NULL;
}

/**
 * page_mapped_in_vma - check whether a page is really mapped in a VMA
 * @page: the page to test
 * @vma: the VMA to test
 *
 * Returns 1 if the page is mapped into the page tables of the VMA, 0
 * if the page is not mapped into the page tables of this VMA.  Only
 * valid for normal file or anonymous VMAs.
 */
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;

	address = __vma_address(page, vma);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		return 0;
	pte = page_check_address(page, vma->vm_mm, address, &ptl, 1);
	if (!pte)			/* the page is not in this mm */
		return 0;
	pte_unmap_unlock(pte, ptl);

	return 1;
}

struct page_referenced_arg {
	int mapcount;
	int referenced;
	unsigned long vm_flags;
	struct mem_cgroup *memcg;
};
/*
 * arg: page_referenced_arg will be passed
 */
/* 对page进行反向映射时，获取到一个vma，会通过此函数对page和vma进行处理 
 * address是目标page在此vma的线性地址，如果此page没有映射到此vma中，那么通过此线性地址找到的页表项也不会映射到目标page上
 * 相反，如果page映射到了此vma中，那么address找到的页表项就一定是映射了目标page的
 */
static int page_referenced_one(struct page *page, struct vm_area_struct *vma,
			unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	int referenced = 0;
	struct page_referenced_arg *pra = arg;

	/* 透明大页的情况 */
	if (unlikely(PageTransHuge(page))) {
		pmd_t *pmd;

		/*
		 * rmap might return false positives; we must filter
		 * these out using page_check_address_pmd().
		 */
		/* 检查此线性地址在mm中对应的页中间目录项是否映射的是page，如果是，返回此页中间目录项，否则返回NULL */
		pmd = page_check_address_pmd(page, mm, address,
					     PAGE_CHECK_ADDRESS_PMD_FLAG, &ptl);
		if (!pmd)
			return SWAP_AGAIN;

		if (vma->vm_flags & VM_LOCKED) {
			spin_unlock(ptl);
			pra->vm_flags |= VM_LOCKED;
			return SWAP_FAIL; /* To break the loop */
		}

		/* go ahead even if the pmd is pmd_trans_splitting() */
		if (pmdp_clear_flush_young_notify(vma, address, pmd))
			referenced++;
		spin_unlock(ptl);
	} else {
		/* 4K页的情况 */

		pte_t *pte;

		/*
		 * rmap might return false positives; we must filter
		 * these out using page_check_address().
		 */
		/* 检查此线性地址address在mm中对应的页表项是否映射的是page，如果是，返回此页表项，否则返回NULL
		 * 会对ptl上锁
		 */
		pte = page_check_address(page, mm, address, &ptl, 0);
		/* pte为空，说明此vma没有映射此page，返回SWAP_AGAIN，SWAP_AGAIN会继续遍历其他vma */
		if (!pte)
			return SWAP_AGAIN;

		/* 此vma映射了此页 */

		/* 如果此vma中的页禁止被换出 */
		if (vma->vm_flags & VM_LOCKED) {
			pte_unmap_unlock(pte, ptl);
			pra->vm_flags |= VM_LOCKED;
			/* 返回SWAP_FAIL */
			return SWAP_FAIL; /* To break the loop */
		}

		/* 清除页表项pte中的Accessed标志，如果通知链mm->mmu_notifier_mm有挂等待此通知的项目，则执行(一般没有) */
		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			/*
			 * Don't treat a reference through a sequentially read
			 * mapping as such.  If the page has been used in
			 * another mapping, we will catch it; if this other
			 * mapping is already gone, the unmap path will have
			 * set PG_referenced or activated the page.
			 */
			/* 此页被vma所属进程最近访问过，referenced++ */
			if (likely(!(vma->vm_flags & VM_SEQ_READ)))
				referenced++;
		}
		/* 释放锁 */
		pte_unmap_unlock(pte, ptl);
	}

	/* 此vma映射了此page，并且此页被此vma所属进程最近访问过 */
	if (referenced) {
		/* 增加映射的vma的访问计数器 */
		pra->referenced++;
		/* 在所有映射了此页的vma标志中增加此vma的标志 */
		pra->vm_flags |= vma->vm_flags;
	}

	/* pra->mapcount初始化时是page->_mapcount，就是引用了此页的页表项数量 */
	pra->mapcount--;
	/* 当pra->mapcount为0时，说明遍历完了 */
	if (!pra->mapcount)
		return SWAP_SUCCESS; /* To break the loop */

	return SWAP_AGAIN;
}

static bool invalid_page_referenced_vma(struct vm_area_struct *vma, void *arg)
{
	struct page_referenced_arg *pra = arg;
	struct mem_cgroup *memcg = pra->memcg;

	if (!mm_match_cgroup(vma->vm_mm, memcg))
		return true;

	return false;
}

/**
 * page_referenced - test if the page was referenced
 * @page: the page to test
 * @is_locked: caller holds lock on the page
 * @memcg: target memory cgroup
 * @vm_flags: collect encountered vma->vm_flags who actually referenced the page
 *
 * Quick test_and_clear_referenced for all mappings to a page,
 * returns the number of ptes which referenced the page.
 */
/* 检查此page最近是否有被访问
 * lru链表扫描时扫描一页调用一次此函数，如果此页的PG_referenced标志或者引用此页的页表项的Accessed置位，则表明此函数最近有被访问，返回1，否则返回0
 * 并且此函数每扫描一页都会将引用此页的页表项的Accessed清0，相当于从新开始直到下次page_referenced()扫描到此页时判断此页最近是否被访问
 * 此函数会涉及到通过反向映射找到引用此页的页表
 * 返回此页最近被多少个进程访问过
 */
int page_referenced(struct page *page,
		    int is_locked,
		    struct mem_cgroup *memcg,
		    unsigned long *vm_flags)
{
	int ret;
	int we_locked = 0;
	/* 进行page_referenced处理时需要使用的参数 */
	struct page_referenced_arg pra = {
		/*
		 * 注意此结构中有一个referenced，初始为0，此项用于记录此page被多少个进程访问过的计数器
		 */

		/* 保存page->_mapcount，引用了此页表项的数量，在扫描过程中，当扫描到一个引用了此page的vma时，此值会-- */
		.mapcount = page_mapcount(page),
		.memcg = memcg,
	};
	/* 反向映射扫描控制结构 */
	struct rmap_walk_control rwc = {
		/* 设置反向映射时获得每一个线性区vma后的处理函数 */
		.rmap_one = page_referenced_one,
		/* 设置反向映射时需要用到的参数为pra */
		.arg = (void *)&pra,
		/* 设置获取anon_vma->rwsem锁的自定义函数 */
		.anon_lock = page_lock_anon_vma_read,
	};

	*vm_flags = 0;
	/* 如果此页没有被映射，也就是没有被使用，直接返回0
	 * 因为page->_mapcount >= 0说明有多少个线性区引用了此页，0代表只有1个进程的线性区引用了此页
	 */
	if (!page_mapped(page))
		return 0;

	/* 如果page的page->mapping没有指向一个address_space或者anon_vma，则返回0 */
	if (!page_rmapping(page))
		return 0;

	/* 如果此页不是匿名页，并且用于KSM(内存合并)，并且没有上锁，则将其上锁(设置PG_locked) */
	if (!is_locked && (!PageAnon(page) || PageKsm(page))) {
		/* 设置page的PG_locked标志，对此页上锁 */
		we_locked = trylock_page(page);
		if (!we_locked)
			return 1;
	}

	/*
	 * If we are reclaiming on behalf of a cgroup, skip
	 * counting on behalf of references from different
	 * cgroups
	 */
	if (memcg) {
		/* 设置判断线性区是否需要处理的函数 */
		rwc.invalid_vma = invalid_page_referenced_vma;
	}

	/* 对此页进行反向映射 */
	ret = rmap_walk(page, &rwc);
	*vm_flags = pra.vm_flags;

	/* 释放此页的锁 */
	if (we_locked)
		unlock_page(page);

	/* 返回有多少个进程最近访问了此页 */
	return pra.referenced;
}

static int page_mkclean_one(struct page *page, struct vm_area_struct *vma,
			    unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte;
	spinlock_t *ptl;
	int ret = 0;
	int *cleaned = arg;

	pte = page_check_address(page, mm, address, &ptl, 1);
	if (!pte)
		goto out;

	if (pte_dirty(*pte) || pte_write(*pte)) {
		pte_t entry;

		/* 将pte对应页在cache中的缓存全部回写 */
		flush_cache_page(vma, address, pte_pfn(*pte));
		/* 获取pte指针对应的页表项内容，保存到entry中，然后将pte指针对应的页表项清空 */
		entry = ptep_clear_flush(vma, address, pte);
		/* 清除entry中的_PAGE_RW标志 */
		entry = pte_wrprotect(entry);
		/* 清除entry中的_PAGE_DIRTY标志 */
		entry = pte_mkclean(entry);
		/* 将entry回写到pte指针对应的页表项中 */
		set_pte_at(mm, address, pte, entry);
		ret = 1;
	}

	pte_unmap_unlock(pte, ptl);

	if (ret) {
		mmu_notifier_invalidate_page(mm, address);
		(*cleaned)++;
	}
out:
	return SWAP_AGAIN;
}

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
	if (vma->vm_flags & VM_SHARED)
		return false;

	return true;
}

int page_mkclean(struct page *page)
{
	int cleaned = 0;
	struct address_space *mapping;
	struct rmap_walk_control rwc = {
		.arg = (void *)&cleaned,
		.rmap_one = page_mkclean_one,
		.invalid_vma = invalid_mkclean_vma,
	};

	BUG_ON(!PageLocked(page));

	if (!page_mapped(page))
		return 0;

	mapping = page_mapping(page);
	if (!mapping)
		return 0;

	rmap_walk(page, &rwc);

	return cleaned;
}
EXPORT_SYMBOL_GPL(page_mkclean);

/**
 * page_move_anon_rmap - move a page to our anon_vma
 * @page:	the page to move to our anon_vma
 * @vma:	the vma the page belongs to
 * @address:	the user virtual address mapped
 *
 * When a page belongs exclusively to one process after a COW event,
 * that page can be moved into the anon_vma that belongs to just that
 * process, so the rmap code will not search the parent or sibling
 * processes.
 */
void page_move_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_VMA(!anon_vma, vma);
	VM_BUG_ON_PAGE(page->index != linear_page_index(vma, address), page);

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
}

/**
 * __page_set_anon_rmap - set up new anonymous rmap
 * @page:	Page to add to rmap	
 * @vma:	VM area to add page to.
 * @address:	User virtual address of the mapping	
 * @exclusive:	the page is exclusively owned by the current process
 */
/* 对一个页建立反向映射 */
/*
 * page: 建立反向映射的匿名页的页描述符
 * vma: 目标匿名线性区
 */
static void __page_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	/* 获取该页所在的vma对应的anon_vma */
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	/* 主要通过判断page->mapping的最低位是否为1来判断是否为匿名页，但是如果page是新的，所以它的page->mapping为空 */
	if (PageAnon(page))
		return;

	/*
	 * If the page isn't exclusively mapped into this vma,
	 * we must use the _oldest_ possible anon_vma for the
	 * page mapping!
	 */
	if (!exclusive)
		anon_vma = anon_vma->root;

	/* 相当于anon_vma的地址+1，这个主要用于保存到page->mapping中，因为mapping的最低位用于判断是否为匿名页，最低位为1则为匿名页 */
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	/* page->mapping指向anon_vma */
	page->mapping = (struct address_space *) anon_vma;
	/* page->index存放此page是vma中的第几页 */
	page->index = linear_page_index(vma, address);
}

/**
 * __page_check_anon_rmap - sanity check anonymous rmap addition
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 */
static void __page_check_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
#ifdef CONFIG_DEBUG_VM
	/*
	 * The page's anon-rmap details (mapping and index) are guaranteed to
	 * be set up correctly at this point.
	 *
	 * We have exclusion against page_add_anon_rmap because the caller
	 * always holds the page locked, except if called from page_dup_rmap,
	 * in which case the page is already known to be setup.
	 *
	 * We have exclusion against page_add_new_anon_rmap because those pages
	 * are initially only visible via the pagetables, and the pte is locked
	 * over the call to page_add_new_anon_rmap.
	 */
	BUG_ON(page_anon_vma(page)->root != vma->anon_vma->root);
	BUG_ON(page->index != linear_page_index(vma, address));
#endif
}

/**
 * page_add_anon_rmap - add pte mapping to an anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * The caller needs to hold the pte lock, and the page must be locked in
 * the anon_vma case: to serialize mapping,index checking after setting,
 * and to ensure that PageAnon is not being upgraded racily to PageKsm
 * (but PageKsm is never downgraded to PageAnon).
 */
void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	do_page_add_anon_rmap(page, vma, address, 0);
}

/*
 * Special version of the above for do_swap_page, which often runs
 * into pages that are exclusively owned by the current process.
 * Everybody else should continue to use page_add_anon_rmap above.
 */
void do_page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	int first = atomic_inc_and_test(&page->_mapcount);
	if (first) {
		/*
		 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
		 * these counters are not modified in interrupt context, and
		 * pte lock(a spinlock) is held, which implies preemption
		 * disabled.
		 */
		if (PageTransHuge(page))
			__inc_zone_page_state(page,
					      NR_ANON_TRANSPARENT_HUGEPAGES);
		__mod_zone_page_state(page_zone(page), NR_ANON_PAGES,
				hpage_nr_pages(page));
	}
	if (unlikely(PageKsm(page)))
		return;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	/* address might be in next vma when migration races vma_adjust */
	if (first)
		__page_set_anon_rmap(page, vma, address, exclusive);
	else
		__page_check_anon_rmap(page, vma, address);
}

/**
 * page_add_new_anon_rmap - add pte mapping to a new anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * Same as page_add_anon_rmap but must only be called on *new* pages.
 * This means the inc-and-test can be bypassed.
 * Page does not have to be locked.
 */
/* 对一个新页进行反向映射
 * page: 目标页
 * vma: 访问此页的vma
 * address: 目标线性地址
 */
void page_add_new_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	/* 地址必须处于vma中 */
	VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);

	/* 设置此页为匿名页 */
	SetPageSwapBacked(page);
	/* 设置此页的_mapcount = 0，说明此页正在使用，但是是非共享的(>0是共享) */
	atomic_set(&page->_mapcount, 0); /* increment count (starts at -1) */
	/* 如果是透明大页 */
	if (PageTransHuge(page))
		/* 统计 */
		__inc_zone_page_state(page, NR_ANON_TRANSPARENT_HUGEPAGES);
	__mod_zone_page_state(page_zone(page), NR_ANON_PAGES,
			hpage_nr_pages(page));

	/* 进行反向映射
	 * 设置page->mapping最低位为1
	 * page->mapping指向此vma->anon_vma
	 * page->index存放此page的虚拟页框号
	 */
	__page_set_anon_rmap(page, vma, address, 1);
}

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page: the page to add the mapping to
 *
 * The caller needs to hold the pte lock.
 */
void page_add_file_rmap(struct page *page)
{
	struct mem_cgroup *memcg;
	unsigned long flags;
	bool locked;

	memcg = mem_cgroup_begin_page_stat(page, &locked, &flags);
	if (atomic_inc_and_test(&page->_mapcount)) {
		__inc_zone_page_state(page, NR_FILE_MAPPED);
		mem_cgroup_inc_page_stat(memcg, MEM_CGROUP_STAT_FILE_MAPPED);
	}
	mem_cgroup_end_page_stat(memcg, locked, flags);
}

/* 主要对此页进行page->_mapcount-- 
 * 如果page->_mapcount--后为0，那还需要对zone的NR_FILE_MAPPED和memcg的MEM_CGROUP_STAT_FILE_MAPPED进行--
 */
static void page_remove_file_rmap(struct page *page)
{
	struct mem_cgroup *memcg;
	unsigned long flags;
	bool locked;

	memcg = mem_cgroup_begin_page_stat(page, &locked, &flags);

	/* page still mapped by someone else? */
	/* 对此页进行page->_mapcount--，如果--后结果为负则返回真 */
	if (!atomic_add_negative(-1, &page->_mapcount))
		goto out;

	/* Hugepages are not counted in NR_FILE_MAPPED for now. */
	if (unlikely(PageHuge(page)))
		goto out;

	/*
	 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	__dec_zone_page_state(page, NR_FILE_MAPPED);
	mem_cgroup_dec_page_stat(memcg, MEM_CGROUP_STAT_FILE_MAPPED);

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);
out:
	mem_cgroup_end_page_stat(memcg, locked, flags);
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page: page to remove mapping from
 *
 * The caller needs to hold the pte lock.
 */
/* 主要对此页的页描述符的_mapcount进行--操作 */
void page_remove_rmap(struct page *page)
{
	/* 如果是文件页 */
	if (!PageAnon(page)) {
		/* 主要对此页进行page->_mapcount-- 
 		 * 如果page->_mapcount--后为0，那还需要对zone的NR_FILE_MAPPED和memcg的MEM_CGROUP_STAT_FILE_MAPPED进行--
 		 */
		page_remove_file_rmap(page);
		return;
	}

	/* 这里处理的是匿名页 */

	/* page still mapped by someone else? */
	/* 对此页进行page->_mapcount--，如果--后结果为负则返回真，结果为负说明此页没有页表映射了 */
	if (!atomic_add_negative(-1, &page->_mapcount))
		return;

	/* Hugepages are not counted in NR_ANON_PAGES for now. */
	/* 大页不处理 */
	if (unlikely(PageHuge(page)))
		return;

	/*
	 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	/* 透明大页，更新统计 */
	if (PageTransHuge(page))
		__dec_zone_page_state(page, NR_ANON_TRANSPARENT_HUGEPAGES);

	__mod_zone_page_state(page_zone(page), NR_ANON_PAGES,
			      -hpage_nr_pages(page));

	/* 此页标记了PG_mlocked，用于锁在内存中 */
	if (unlikely(PageMlocked(page)))
		/* 清除此标记，因为有些情况会强制对mlock中的内存进行unmap操作 */
		clear_page_mlock(page);

	/*
	 * It would be tidy to reset the PageAnon mapping here,
	 * but that might overwrite a racing page_add_anon_rmap
	 * which increments mapcount after us but sets mapping
	 * before us: so leave the reset to free_hot_cold_page,
	 * and remember that it's only reliable while mapped.
	 * Leaving it set also helps swapoff to reinstate ptes
	 * faster for those pages still in swapcache.
	 */
}

/*
 * @arg: enum ttu_flags will be passed to this argument
 */
/*
 * 对vma进行unmap操作，并对此页的page->_mapcount--，这里面的页可能是文件页也可能是匿名页
 * page: 目标page
 * vma: 获取到的vma
 * address: page在vma所属的进程地址空间中的线性地址
 */
static int try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	int ret = SWAP_AGAIN;
	enum ttu_flags flags = (enum ttu_flags)arg;

	/* 先检查此vma有没有映射此page，有则返回此page在此进程地址空间的页表项 */
	/* 检查page有没有映射到mm这个地址空间中
	 * address是page在此vma所属进程地址空间的线性地址，获取方法: address = vma->vm_pgoff + page->pgoff << PAGE_SHIFT;
	 * 通过线性地址address获取对应在此进程地址空间的页表项，然后通过页表项映射的页框号和page的页框号比较，则知道页表项是否映射了此page
	 * 会对页表上锁
	 */
	pte = page_check_address(page, mm, address, &ptl, 0);
	/* pte为空，则说明page没有映射到此mm所属的进程地址空间，则跳到out */
	if (!pte)
		goto out;

	/*
	 * If the page is mlock()d, we cannot swap it out.
	 * If it's recently referenced (perhaps page_referenced
	 * skipped over this mm) then we should reactivate it.
	 */
	/* 如果flags没有要求忽略mlock的vma */
	if (!(flags & TTU_IGNORE_MLOCK)) {
		/* 如果此vma要求里面的页都锁在内存中，则跳到out_mlock */
		if (vma->vm_flags & VM_LOCKED)
			goto out_mlock;

		/* flags标记了对vma进行mlock释放模式，则跳到out_unmap，因为这个函数中只对vma进行unmap操作 */
		if (flags & TTU_MUNLOCK)
			goto out_unmap;
	}
	/* 不忽略页表项中的Accessed，这里就会清除页表项的Accessed标志 */
	if (!(flags & TTU_IGNORE_ACCESS)) {
		/* 清除页表项的Accessed标志 */
		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			/* 清除失败，发生在清除后检查是否为0 */
			ret = SWAP_FAIL;
			goto out_unmap;
		}
  	}

	/* Nuke the page table entry. */
	/* 空函数 */
	flush_cache_page(vma, address, page_to_pfn(page));
	/* 获取页表项内容，保存到pteval中，然后清空页表项 */
	pteval = ptep_clear_flush(vma, address, pte);

	/* Move the dirty bit to the physical page now the pte is gone. */
	/* 如果页表项标记了此页为脏页 */
	if (pte_dirty(pteval))
		/* 设置页描述符的PG_dirty标记 */
		set_page_dirty(page);

	/* Update high watermark before we lower rss */
	/* 更新进程所拥有的最大页框数 */
	update_hiwater_rss(mm);

	/* 此页是被标记为"坏页"的页，这种页用于内核纠正一些错误，是否用于边界检查? */
	if (PageHWPoison(page) && !(flags & TTU_IGNORE_HWPOISON)) {
		/* 非大页 */
		if (!PageHuge(page)) {
			/* 是匿名页，则mm的MM_ANONPAGES-- */
			if (PageAnon(page))
				dec_mm_counter(mm, MM_ANONPAGES);
			else
				/* 此页是文件页，则mm的MM_FILEPAGES-- */
				dec_mm_counter(mm, MM_FILEPAGES);
		}
		/* 设置页表项新的内容为 swp_entry_to_pte(make_hwpoison_entry(page)) */
		set_pte_at(mm, address, pte,
			   swp_entry_to_pte(make_hwpoison_entry(page)));
	} else if (pte_unused(pteval)) {
		/* 一些架构上会有这种情况，X86不会调用到这个判断中 */
		/*
		 * The guest indicated that the page content is of no
		 * interest anymore. Simply discard the pte, vmscan
		 * will take care of the rest.
		 */
		if (PageAnon(page))
			dec_mm_counter(mm, MM_ANONPAGES);
		else
			dec_mm_counter(mm, MM_FILEPAGES);
	} else if (PageAnon(page)) {
		/* 此页为匿名页处理 */

		/* 获取page->private中保存的内容，调用到try_to_unmap()前会把此页加入到swapcache，然后分配一个以swap页槽偏移量为内容的swp_entry_t */
		swp_entry_t entry = { .val = page_private(page) };
		pte_t swp_pte;

		/* 对于内存回收，基本都是这种情况，因为page在调用到这里之前已经被移动到了swapcache 
		 * 而对于内存压缩，
		 */
		if (PageSwapCache(page)) {
			/*
			 * Store the swap location in the pte.
			 * See handle_pte_fault() ...
			 */
			/* 检查entry是否有效
 			 * 并且增加entry对应页槽在swap_info_struct的swap_map的数值，此数值标记此页槽的页有多少个进程引用
 			 */
			if (swap_duplicate(entry) < 0) {
				/* 检查失败，把原来的页表项内容写回去 */
				set_pte_at(mm, address, pte, pteval);
				/* 返回值为SWAP_FAIL */
				ret = SWAP_FAIL;
				goto out_unmap;
			}
			
			/* entry有效，并且swap_map中目标页槽的数值也++了 */
			/* 这个if的情况是此vma所属进程的mm没有加入到所有进程的mmlist中(init_mm.mmlist) */
			if (list_empty(&mm->mmlist)) {
				spin_lock(&mmlist_lock);
				if (list_empty(&mm->mmlist))
					list_add(&mm->mmlist, &init_mm.mmlist);
				spin_unlock(&mmlist_lock);
			}
			/* 减少此mm的匿名页统计 */
			dec_mm_counter(mm, MM_ANONPAGES);
			/* 增加此mm的页表中标记了页在swap的页表项的数量 */
			inc_mm_counter(mm, MM_SWAPENTS);
		} else if (IS_ENABLED(CONFIG_MIGRATION)) {
			/*
			 * Store the pfn of the page in a special migration
			 * pte. do_swap_page() will wait until the migration
			 * pte is removed and then restart fault handling.
			 */
			/* 执行到这里，就是对匿名页进行页面迁移工作(内存压缩时使用) */
			
			/* 如果flags没有标记此次是在执行页面迁移操作 */
			BUG_ON(!(flags & TTU_MIGRATION));
			/* 为此匿名页创建一个页迁移使用的swp_entry_t，此swp_entry_t指向此匿名页 */
			entry = make_migration_entry(page, pte_write(pteval));
		}
		/*
		 * 这个entry有两种情况，保存在page->private中的以在swap中页槽偏移量为数据的swp_entry_t
		 * 另一种是一个迁移使用的swp_entry_t
		 */
		/* 将entry转为一个页表项 */
		swp_pte = swp_entry_to_pte(entry);
		/* 页表项有一位用于_PAGE_SOFT_DIRTY，用于kmemcheck */
		if (pte_soft_dirty(pteval))
			swp_pte = pte_swp_mksoft_dirty(swp_pte);
		/* 将配置好的新的页表项swp_pte写入页表项中 */
		set_pte_at(mm, address, pte, swp_pte);

		/* 如果页表项表示映射的是一个文件，则是一个bug。因为这里处理的是匿名页，主要检查页表项中的_PAGE_FILE位 */
		BUG_ON(pte_file(*pte));
	} else if (IS_ENABLED(CONFIG_MIGRATION) &&
		   (flags & TTU_MIGRATION)) {
		/* 本次调用到此是对文件页进行页迁移操作的，会为映射了此文件页的进程创建一个swp_entry_t，这个swp_entry_t指向此文件页 */
		/* Establish migration entry for a file page */
		swp_entry_t entry;
		
		/* 建立一个迁移使用的swp_entry_t，用于文件页迁移 */
		entry = make_migration_entry(page, pte_write(pteval));
		/* 将此页表的pte页表项写入entry转为的页表项内容 */
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
	} else
		/* 此页是文件页，仅对此mm的文件页计数--，文件页不需要设置页表项，只需要对页表项进行清空 */
		dec_mm_counter(mm, MM_FILEPAGES);

	/* 如果是匿名页，上面的代码已经将匿名页对应于此进程的页表项进行修改了 */

	/* 主要对此页的页描述符的_mapcount进行--操作，当_mapcount为-1时，表示此页已经没有页表项映射了 */
	page_remove_rmap(page);
	/* 每个进程对此页进行了unmap操作，此页的page->_count--，并判断是否为0，如果为0则释放此页，一般这里不会为0 */
	page_cache_release(page);

out_unmap:
	pte_unmap_unlock(pte, ptl);
	if (ret != SWAP_FAIL && !(flags & TTU_MUNLOCK))
		mmu_notifier_invalidate_page(mm, address);
out:
	return ret;

out_mlock:
	pte_unmap_unlock(pte, ptl);


	/*
	 * We need mmap_sem locking, Otherwise VM_LOCKED check makes
	 * unstable result and race. Plus, We can't wait here because
	 * we now hold anon_vma->rwsem or mapping->i_mmap_mutex.
	 * if trylock failed, the page remain in evictable lru and later
	 * vmscan could retry to move the page to unevictable lru if the
	 * page is actually mlocked.
	 */
	if (down_read_trylock(&vma->vm_mm->mmap_sem)) {
		if (vma->vm_flags & VM_LOCKED) {
			mlock_vma_page(page);
			ret = SWAP_MLOCK;
		}
		up_read(&vma->vm_mm->mmap_sem);
	}
	return ret;
}

/*
 * objrmap doesn't work for nonlinear VMAs because the assumption that
 * offset-into-file correlates with offset-into-virtual-addresses does not hold.
 * Consequently, given a particular page and its ->index, we cannot locate the
 * ptes which are mapping that page without an exhaustive linear search.
 *
 * So what this code does is a mini "virtual scan" of each nonlinear VMA which
 * maps the file to which the target page belongs.  The ->vm_private_data field
 * holds the current cursor into that scan.  Successive searches will circulate
 * around the vma's virtual address space.
 *
 * So as more replacement pressure is applied to the pages in a nonlinear VMA,
 * more scanning pressure is placed against them as well.   Eventually pages
 * will become fully unmapped and are eligible for eviction.
 *
 * For very sparsely populated VMAs this is a little inefficient - chances are
 * there there won't be many ptes located within the scan cluster.  In this case
 * maybe we could scan further - to the end of the pte page, perhaps.
 *
 * Mlocked pages:  check VM_LOCKED under mmap_sem held for read, if we can
 * acquire it without blocking.  If vma locked, mlock the pages in the cluster,
 * rather than unmapping them.  If we encounter the "check_page" that vmscan is
 * trying to unmap, return SWAP_MLOCK, else default SWAP_AGAIN.
 */
#define CLUSTER_SIZE	min(32*PAGE_SIZE, PMD_SIZE)
#define CLUSTER_MASK	(~(CLUSTER_SIZE - 1))

static int try_to_unmap_cluster(unsigned long cursor, unsigned int *mapcount,
		struct vm_area_struct *vma, struct page *check_page)
{
	struct mm_struct *mm = vma->vm_mm;
	pmd_t *pmd;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	struct page *page;
	unsigned long address;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	unsigned long end;
	int ret = SWAP_AGAIN;
	int locked_vma = 0;

	address = (vma->vm_start + cursor) & CLUSTER_MASK;
	end = address + CLUSTER_SIZE;
	if (address < vma->vm_start)
		address = vma->vm_start;
	if (end > vma->vm_end)
		end = vma->vm_end;

	pmd = mm_find_pmd(mm, address);
	if (!pmd)
		return ret;

	mmun_start = address;
	mmun_end   = end;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);

	/*
	 * If we can acquire the mmap_sem for read, and vma is VM_LOCKED,
	 * keep the sem while scanning the cluster for mlocking pages.
	 */
	if (down_read_trylock(&vma->vm_mm->mmap_sem)) {
		locked_vma = (vma->vm_flags & VM_LOCKED);
		if (!locked_vma)
			up_read(&vma->vm_mm->mmap_sem); /* don't need it */
	}

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	for (; address < end; pte++, address += PAGE_SIZE) {
		if (!pte_present(*pte))
			continue;
		page = vm_normal_page(vma, address, *pte);
		BUG_ON(!page || PageAnon(page));

		if (locked_vma) {
			if (page == check_page) {
				/* we know we have check_page locked */
				mlock_vma_page(page);
				ret = SWAP_MLOCK;
			} else if (trylock_page(page)) {
				/*
				 * If we can lock the page, perform mlock.
				 * Otherwise leave the page alone, it will be
				 * eventually encountered again later.
				 */
				mlock_vma_page(page);
				unlock_page(page);
			}
			continue;	/* don't unmap */
		}

		/*
		 * No need for _notify because we're within an
		 * mmu_notifier_invalidate_range_ {start|end} scope.
		 */
		if (ptep_clear_flush_young(vma, address, pte))
			continue;

		/* Nuke the page table entry. */
		flush_cache_page(vma, address, pte_pfn(*pte));
		pteval = ptep_clear_flush(vma, address, pte);

		/* If nonlinear, store the file page offset in the pte. */
		if (page->index != linear_page_index(vma, address)) {
			pte_t ptfile = pgoff_to_pte(page->index);
			if (pte_soft_dirty(pteval))
				ptfile = pte_file_mksoft_dirty(ptfile);
			set_pte_at(mm, address, pte, ptfile);
		}

		/* Move the dirty bit to the physical page now the pte is gone. */
		if (pte_dirty(pteval))
			set_page_dirty(page);

		page_remove_rmap(page);
		page_cache_release(page);
		dec_mm_counter(mm, MM_FILEPAGES);
		(*mapcount)--;
	}
	pte_unmap_unlock(pte - 1, ptl);
	mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
	if (locked_vma)
		up_read(&vma->vm_mm->mmap_sem);
	return ret;
}

static int try_to_unmap_nonlinear(struct page *page,
		struct address_space *mapping, void *arg)
{
	struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;
	unsigned long cursor;
	unsigned long max_nl_cursor = 0;
	unsigned long max_nl_size = 0;
	unsigned int mapcount;

	list_for_each_entry(vma,
		&mapping->i_mmap_nonlinear, shared.nonlinear) {

		cursor = (unsigned long) vma->vm_private_data;
		if (cursor > max_nl_cursor)
			max_nl_cursor = cursor;
		cursor = vma->vm_end - vma->vm_start;
		if (cursor > max_nl_size)
			max_nl_size = cursor;
	}

	if (max_nl_size == 0) {	/* all nonlinears locked or reserved ? */
		return SWAP_FAIL;
	}

	/*
	 * We don't try to search for this page in the nonlinear vmas,
	 * and page_referenced wouldn't have found it anyway.  Instead
	 * just walk the nonlinear vmas trying to age and unmap some.
	 * The mapcount of the page we came in with is irrelevant,
	 * but even so use it as a guide to how hard we should try?
	 */
	mapcount = page_mapcount(page);
	if (!mapcount)
		return ret;

	cond_resched();

	max_nl_size = (max_nl_size + CLUSTER_SIZE - 1) & CLUSTER_MASK;
	if (max_nl_cursor == 0)
		max_nl_cursor = CLUSTER_SIZE;

	do {
		list_for_each_entry(vma,
			&mapping->i_mmap_nonlinear, shared.nonlinear) {

			cursor = (unsigned long) vma->vm_private_data;
			while (cursor < max_nl_cursor &&
				cursor < vma->vm_end - vma->vm_start) {
				if (try_to_unmap_cluster(cursor, &mapcount,
						vma, page) == SWAP_MLOCK)
					ret = SWAP_MLOCK;
				cursor += CLUSTER_SIZE;
				vma->vm_private_data = (void *) cursor;
				if ((int)mapcount <= 0)
					return ret;
			}
			vma->vm_private_data = (void *) max_nl_cursor;
		}
		cond_resched();
		max_nl_cursor += CLUSTER_SIZE;
	} while (max_nl_cursor <= max_nl_size);

	/*
	 * Don't loop forever (perhaps all the remaining pages are
	 * in locked vmas).  Reset cursor on all unreserved nonlinear
	 * vmas, now forgetting on which ones it had fallen behind.
	 */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear, shared.nonlinear)
		vma->vm_private_data = NULL;

	return ret;
}

bool is_vma_temporary_stack(struct vm_area_struct *vma)
{
	int maybe_stack = vma->vm_flags & (VM_GROWSDOWN | VM_GROWSUP);

	if (!maybe_stack)
		return false;

	if ((vma->vm_flags & VM_STACK_INCOMPLETE_SETUP) ==
						VM_STACK_INCOMPLETE_SETUP)
		return true;

	return false;
}

static bool invalid_migration_vma(struct vm_area_struct *vma, void *arg)
{
	return is_vma_temporary_stack(vma);
}

static int page_not_mapped(struct page *page)
{
	return !page_mapped(page);
};

/**
 * try_to_unmap - try to remove all page table mappings to a page
 * @page: the page to get unmapped
 * @flags: action and flags
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used in the pageout path.  Caller must hold the page lock.
 * Return values are:
 *
 * SWAP_SUCCESS	- we succeeded in removing all mappings
 * SWAP_AGAIN	- we missed a mapping, try again later
 * SWAP_FAIL	- the page is unswappable
 * SWAP_MLOCK	- page is mlocked.
 */
/* 对映射了page的进程页表项进行unmap操作
 * 在内存回收过程中，如果是匿名页，那么page->private中是一个带有swap页槽偏移量的swp_entry_t，此后这个swp_entry_t可以转为页表项
 */
int try_to_unmap(struct page *page, enum ttu_flags flags)
{
	int ret;
	/* 反向映射控制结构 */
	struct rmap_walk_control rwc = {
		/* 对一个vma所属页表进行unmap操作
		 * 每次获取一个vma就会对此vma调用一次此函数，在函数里第一件事就是判断获取的vma有没有映射此page
		 */
		.rmap_one = try_to_unmap_one,
		.arg = (void *)flags,
		/* 对一个vma进行unmap后会执行此函数 */
		.done = page_not_mapped,
		.file_nonlinear = try_to_unmap_nonlinear,
		/* 用于对整个anon_vma的红黑树进行上锁，用读写信号量，锁是aon_vma的rwsem */
		.anon_lock = page_lock_anon_vma_read,
	};

	VM_BUG_ON_PAGE(!PageHuge(page) && PageTransHuge(page), page);

	/*
	 * During exec, a temporary VMA is setup and later moved.
	 * The VMA is moved under the anon_vma lock but not the
	 * page tables leading to a race where migration cannot
	 * find the migration ptes. Rather than increasing the
	 * locking requirements of exec(), migration skips
	 * temporary VMAs until after exec() completes.
	 */
	if ((flags & TTU_MIGRATION) && !PageKsm(page) && PageAnon(page))
		rwc.invalid_vma = invalid_migration_vma;

	/* 里面会对所有映射了此页的vma进行遍历，具体见反向映射 */
	ret = rmap_walk(page, &rwc);

	/* 没有vma要求此页锁在内存中，并且page->_mapcount为-1了，表示没有进程映射了此页 */
	if (ret != SWAP_MLOCK && !page_mapped(page))
		ret = SWAP_SUCCESS;
	return ret;
}

/**
 * try_to_munlock - try to munlock a page
 * @page: the page to be munlocked
 *
 * Called from munlock code.  Checks all of the VMAs mapping the page
 * to make sure nobody else has this page mlocked. The page will be
 * returned with PG_mlocked cleared if no other vmas have it mlocked.
 *
 * Return values are:
 *
 * SWAP_AGAIN	- no vma is holding page mlocked, or,
 * SWAP_AGAIN	- page mapped in mlocked vma -- couldn't acquire mmap sem
 * SWAP_FAIL	- page cannot be located at present
 * SWAP_MLOCK	- page is now mlocked.
 */
int try_to_munlock(struct page *page)
{
	int ret;
	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one,
		.arg = (void *)TTU_MUNLOCK,
		.done = page_not_mapped,
		/*
		 * We don't bother to try to find the munlocked page in
		 * nonlinears. It's costly. Instead, later, page reclaim logic
		 * may call try_to_unmap() and recover PG_mlocked lazily.
		 */
		.file_nonlinear = NULL,
		.anon_lock = page_lock_anon_vma_read,

	};

	VM_BUG_ON_PAGE(!PageLocked(page) || PageLRU(page), page);

	ret = rmap_walk(page, &rwc);
	return ret;
}

void __put_anon_vma(struct anon_vma *anon_vma)
{
	struct anon_vma *root = anon_vma->root;

	anon_vma_free(anon_vma);
	if (root != anon_vma && atomic_dec_and_test(&root->refcount))
		anon_vma_free(root);
}

/* 获取此页对应的anon_vma中的读锁并返回此页对应的anon_vma */
static struct anon_vma *rmap_walk_anon_lock(struct page *page,
					struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma;

	if (rwc->anon_lock)
		return rwc->anon_lock(page);

	/*
	 * Note: remove_migration_ptes() cannot use page_lock_anon_vma_read()
	 * because that depends on page_mapped(); but not all its usages
	 * are holding mmap_sem. Users without mmap_sem are required to
	 * take a reference count to prevent the anon_vma disappearing
	 */
	/* 获取page对应的anon_vma */
	anon_vma = page_anon_vma(page);
	if (!anon_vma)
		return NULL;

	anon_vma_lock_read(anon_vma);
	return anon_vma;
}

/*
 * rmap_walk_anon - do something to anonymous page using the object-based
 * rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the anon_vma struct it points to.
 *
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * LOCKED.
 */
/* 对匿名页page的反向映射扫描 */
static int rmap_walk_anon(struct page *page, struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma;
	/* 获取page->index，保存的是在线性区的页索引或是页的线性地址/PAGE_SIZE 
	 * 获取这个是用于计算页的线性地址，通过vma->vm_start + page->index * PAGE_SIZE
	 */
	pgoff_t pgoff = page_to_pgoff(page);
	struct anon_vma_chain *avc;
	/* 默认是SWAP_AGAIN，SWAP_AGAIN会继续遍历 */
	int ret = SWAP_AGAIN;

	/* 获取page对应的anon_vma，并且在里面会调用anon_lock，如果anon_lock为空，则直接对anon_vma上一次读锁 
	 * 如果从page_referenced()函数调用过来的情况，anon_lock为page_lock_anon_vma_read()
	 */
	anon_vma = rmap_walk_anon_lock(page, rwc);
	if (!anon_vma)
		return ret;

	/* 获取page->mapping所指的anon_vma的红黑树中的各个节点，每个结点是一个avc，然后通过avc->vma获取vma */
	anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff, pgoff) {
		struct vm_area_struct *vma = avc->vma;
		/* 获取此页在此vma中的线性地址 */
		unsigned long address = vma_address(page, vma);

		/* 判断是否是不需要处理的线性区，通过vma->vm_start + page->index * PAGE_SIZE */
		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		/* 判断page是否在获得的线性区中，并清空对应页表项的Accessed标志 */
		ret = rwc->rmap_one(page, vma, address, rwc->arg);
		if (ret != SWAP_AGAIN)
			break;
		if (rwc->done && rwc->done(page))
			break;
	}
	anon_vma_unlock_read(anon_vma);
	return ret;
}

/*
 * rmap_walk_file - do something to file page using the object-based rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * LOCKED.
 */
static int rmap_walk_file(struct page *page, struct rmap_walk_control *rwc)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page_to_pgoff(page);
	struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_mutex.
	 */
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!mapping)
		return ret;
	mutex_lock(&mapping->i_mmap_mutex);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		unsigned long address = vma_address(page, vma);

		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		ret = rwc->rmap_one(page, vma, address, rwc->arg);
		if (ret != SWAP_AGAIN)
			goto done;
		if (rwc->done && rwc->done(page))
			goto done;
	}

	if (!rwc->file_nonlinear)
		goto done;

	if (list_empty(&mapping->i_mmap_nonlinear))
		goto done;

	ret = rwc->file_nonlinear(page, mapping, rwc->arg);

done:
	mutex_unlock(&mapping->i_mmap_mutex);
	return ret;
}

int rmap_walk(struct page *page, struct rmap_walk_control *rwc)
{
	if (unlikely(PageKsm(page)))
		/* 此页用于ksm */
		return rmap_walk_ksm(page, rwc);
	else if (PageAnon(page))
		/* 如果此页是匿名页 */
		return rmap_walk_anon(page, rwc);
	else
		/* 如果此页是映射页 */
		return rmap_walk_file(page, rwc);
}

#ifdef CONFIG_HUGETLB_PAGE
/*
 * The following three functions are for anonymous (private mapped) hugepages.
 * Unlike common anonymous pages, anonymous hugepages have no accounting code
 * and no lru code, because we handle hugepages differently from common pages.
 */
static void __hugepage_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		return;
	if (!exclusive)
		anon_vma = anon_vma->root;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	page->index = linear_page_index(vma, address);
}

void hugepage_add_anon_rmap(struct page *page,
			    struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int first;

	BUG_ON(!PageLocked(page));
	BUG_ON(!anon_vma);
	/* address might be in next vma when migration races vma_adjust */
	first = atomic_inc_and_test(&page->_mapcount);
	if (first)
		__hugepage_set_anon_rmap(page, vma, address, 0);
}

void hugepage_add_new_anon_rmap(struct page *page,
			struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	atomic_set(&page->_mapcount, 0);
	__hugepage_set_anon_rmap(page, vma, address, 1);
}
#endif /* CONFIG_HUGETLB_PAGE */
