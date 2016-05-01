#ifndef _LINUX_RMAP_H
#define _LINUX_RMAP_H
/*
 * Declarations for Reverse Mapping functions in mm/rmap.c
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/memcontrol.h>

/*
 * The anon_vma heads a list of private "related" vmas, to scan if
 * an anonymous page pointing to this anon_vma needs to be unmapped:
 * the vmas on the list will be related by forking, or by splitting.
 *
 * Since vmas come and go as they are split and merged (particularly
 * in mprotect), the mapping field of an anonymous page cannot point
 * directly to a vma: instead it points to an anon_vma, on whose list
 * the related vmas can be easily linked or unlinked.
 *
 * After unlinking the last vma on the list, we must garbage collect
 * the anon_vma object itself: we're guaranteed no page can be
 * pointing to this anon_vma once its vma list is empty.
 */
/* 匿名线性区描述符，每个匿名vma都会有一个这个结构 */
struct anon_vma {
	/* 指向此anon_vma所属的root */
	struct anon_vma *root;		/* Root of this anon_vma tree */
	/* 读写信号量 */
	struct rw_semaphore rwsem;	/* W: modification, R: walking the list */
	/*
	 * The refcount is taken on an anon_vma when there is no
	 * guarantee that the vma of page tables will exist for
	 * the duration of the operation. A caller that takes
	 * the reference is responsible for clearing up the
	 * anon_vma if they are the last user on release
	 */
	/* 红黑树中结点数量，初始化时为1，也就是只有本结点，当加入root的anon_vma的红黑树时，此值不变 */
	atomic_t refcount;

	/*
	 * NOTE: the LSB of the rb_root.rb_node is set by
	 * mm_take_all_locks() _after_ taking the above lock. So the
	 * rb_root must only be read/written after taking the above lock
	 * to be sure to see a valid next pointer. The LSB bit itself
	 * is serialized by a system wide lock only visible to
	 * mm_take_all_locks() (mm_all_locks_mutex).
	 */
	/* 红黑树的根，用于存放引用了此anon_vma所属线性区中的页的其他线性区，用于匿名页反向映射 */
	struct rb_root rb_root;	/* Interval tree of private "related" vmas */
};

/*
 * The copy-on-write semantics of fork mean that an anon_vma
 * can become associated with multiple processes. Furthermore,
 * each child process will have its own anon_vma, where new
 * pages for that process are instantiated.
 *
 * This structure allows us to find the anon_vmas associated
 * with a VMA, or the VMAs associated with an anon_vma.
 * The "same_vma" list contains the anon_vma_chains linking
 * all the anon_vmas associated with this VMA.
 * The "rb" field indexes on an interval tree the anon_vma_chains
 * which link all the VMAs associated with this anon_vma.
 */
struct anon_vma_chain {
	/* 此结构所属的vma */
	struct vm_area_struct *vma;
	/* 此结构加入的红黑树所属的anon_vma */
	struct anon_vma *anon_vma;
	/* 用于加入到所属vma的anon_vma_chain链表中 */
	struct list_head same_vma;   /* locked by mmap_sem & page_table_lock */
	/* 用于加入到其他进程或者本进程的vma的anon_vma的红黑树中 */
	struct rb_node rb;			/* locked by anon_vma->rwsem */
	unsigned long rb_subtree_last;
#ifdef CONFIG_DEBUG_VM_RB
	unsigned long cached_vma_start, cached_vma_last;
#endif
};

enum ttu_flags {
	/* 对页进行unmap操作模式 */
	TTU_UNMAP = 1,			/* unmap mode */
	/* 对页进行迁移操作模式 */
	TTU_MIGRATION = 2,		/* migration mode */
	/* 对页进行munlock操作模式 */
	TTU_MUNLOCK = 4,		/* munlock mode */

	/* 忽略vma的mlock */
	TTU_IGNORE_MLOCK = (1 << 8),	/* ignore mlock */
	/* 忽略页表项的Accessed */
	TTU_IGNORE_ACCESS = (1 << 9),	/* don't age */
	TTU_IGNORE_HWPOISON = (1 << 10),/* corrupted page is recoverable */
};

#ifdef CONFIG_MMU
static inline void get_anon_vma(struct anon_vma *anon_vma)
{
	atomic_inc(&anon_vma->refcount);
}

void __put_anon_vma(struct anon_vma *anon_vma);

static inline void put_anon_vma(struct anon_vma *anon_vma)
{
	if (atomic_dec_and_test(&anon_vma->refcount))
		__put_anon_vma(anon_vma);
}

/* 获取此页对应的anon_vma */
static inline struct anon_vma *page_anon_vma(struct page *page)
{
	/* 根据page->mapping最低两位进行判断，PAGE_MAPPING_FLAGS为0x3，而PAGE_MAPPING_ANON为0x1 */
	if (((unsigned long)page->mapping & PAGE_MAPPING_FLAGS) !=
					    PAGE_MAPPING_ANON)
		return NULL;
	/* 获取page->mapping指向的数据，page->mapping最低两位用于判断，其他位用于指针 */
	return page_rmapping(page);
}

static inline void vma_lock_anon_vma(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	if (anon_vma)
		down_write(&anon_vma->root->rwsem);
}

static inline void vma_unlock_anon_vma(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	if (anon_vma)
		up_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_lock_write(struct anon_vma *anon_vma)
{
	down_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_write(struct anon_vma *anon_vma)
{
	up_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
{
	down_read(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_read(struct anon_vma *anon_vma)
{
	up_read(&anon_vma->root->rwsem);
}


/*
 * anon_vma helper functions.
 */
void anon_vma_init(void);	/* create anon_vma_cachep */
int  anon_vma_prepare(struct vm_area_struct *);
void unlink_anon_vmas(struct vm_area_struct *);
int anon_vma_clone(struct vm_area_struct *, struct vm_area_struct *);
int anon_vma_fork(struct vm_area_struct *, struct vm_area_struct *);

static inline void anon_vma_merge(struct vm_area_struct *vma,
				  struct vm_area_struct *next)
{
	VM_BUG_ON_VMA(vma->anon_vma != next->anon_vma, vma);
	unlink_anon_vmas(next);
}

struct anon_vma *page_get_anon_vma(struct page *page);

/*
 * rmap interfaces called when adding or removing pte of page
 */
void page_move_anon_rmap(struct page *, struct vm_area_struct *, unsigned long);
void page_add_anon_rmap(struct page *, struct vm_area_struct *, unsigned long);
void do_page_add_anon_rmap(struct page *, struct vm_area_struct *,
			   unsigned long, int);
void page_add_new_anon_rmap(struct page *, struct vm_area_struct *, unsigned long);
void page_add_file_rmap(struct page *);
void page_remove_rmap(struct page *);

void hugepage_add_anon_rmap(struct page *, struct vm_area_struct *,
			    unsigned long);
void hugepage_add_new_anon_rmap(struct page *, struct vm_area_struct *,
				unsigned long);

static inline void page_dup_rmap(struct page *page)
{
	atomic_inc(&page->_mapcount);
}

/*
 * Called from mm/vmscan.c to handle paging out
 */
int page_referenced(struct page *, int is_locked,
			struct mem_cgroup *memcg, unsigned long *vm_flags);

#define TTU_ACTION(x) ((x) & TTU_ACTION_MASK)

int try_to_unmap(struct page *, enum ttu_flags flags);

/*
 * Called from mm/filemap_xip.c to unmap empty zero page
 */
pte_t *__page_check_address(struct page *, struct mm_struct *,
				unsigned long, spinlock_t **, int);

/* 检查page有没有映射到mm这个地址空间中
 * address是page在此vma所属进程地址空间的线性地址，获取方法: address = vma->vm_pgoff + page->pgoff << PAGE_SHIFT;
 * 通过线性地址address获取对应在此进程地址空间的页表项，然后通过页表项映射的页框号和page的页框号比较，则知道页表项是否映射了此page
 */
static inline pte_t *page_check_address(struct page *page, struct mm_struct *mm,
					unsigned long address,
					spinlock_t **ptlp, int sync)
{
	pte_t *ptep;

	__cond_lock(*ptlp, ptep = __page_check_address(page, mm, address,
						       ptlp, sync));
	return ptep;
}

/*
 * Used by swapoff to help locate where page is expected in vma.
 */
unsigned long page_address_in_vma(struct page *, struct vm_area_struct *);

/*
 * Cleans the PTEs of shared mappings.
 * (and since clean PTEs should also be readonly, write protects them too)
 *
 * returns the number of cleaned PTEs.
 */
int page_mkclean(struct page *);

/*
 * called in munlock()/munmap() path to check for other vmas holding
 * the page mlocked.
 */
int try_to_munlock(struct page *);

/*
 * Called by memory-failure.c to kill processes.
 */
struct anon_vma *page_lock_anon_vma_read(struct page *page);
void page_unlock_anon_vma_read(struct anon_vma *anon_vma);
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma);

/*
 * rmap_walk_control: To control rmap traversing for specific needs
 *
 * arg: passed to rmap_one() and invalid_vma()
 * rmap_one: executed on each vma where page is mapped
 * done: for checking traversing termination condition
 * file_nonlinear: for handling file nonlinear mapping
 * anon_lock: for getting anon_lock by optimized way rather than default
 * invalid_vma: for skipping uninterested vma
 */
struct rmap_walk_control {
	void *arg;
	int (*rmap_one)(struct page *page, struct vm_area_struct *vma,
					unsigned long addr, void *arg);
	int (*done)(struct page *page);
	int (*file_nonlinear)(struct page *, struct address_space *, void *arg);
	struct anon_vma *(*anon_lock)(struct page *page);
	bool (*invalid_vma)(struct vm_area_struct *vma, void *arg);
};

int rmap_walk(struct page *page, struct rmap_walk_control *rwc);

#else	/* !CONFIG_MMU */

#define anon_vma_init()		do {} while (0)
#define anon_vma_prepare(vma)	(0)
#define anon_vma_link(vma)	do {} while (0)

static inline int page_referenced(struct page *page, int is_locked,
				  struct mem_cgroup *memcg,
				  unsigned long *vm_flags)
{
	*vm_flags = 0;
	return 0;
}

#define try_to_unmap(page, refs) SWAP_FAIL

static inline int page_mkclean(struct page *page)
{
	return 0;
}


#endif	/* CONFIG_MMU */

/*
 * Return values of try_to_unmap
 */
#define SWAP_SUCCESS	0
#define SWAP_AGAIN	1
#define SWAP_FAIL	2
#define SWAP_MLOCK	3

#endif	/* _LINUX_RMAP_H */
