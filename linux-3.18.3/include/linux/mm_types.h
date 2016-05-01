#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/page-debug-flags.h>
#include <linux/uprobes.h>
#include <linux/page-flags-layout.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;

#define USE_SPLIT_PTE_PTLOCKS	(NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)
#define USE_SPLIT_PMD_PTLOCKS	(USE_SPLIT_PTE_PTLOCKS && \
		IS_ENABLED(CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK))
#define ALLOC_SPLIT_PTLOCKS	(SPINLOCK_SIZE > BITS_PER_LONG/8)

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * The objects in struct page are organized in double word blocks in
 * order to allows us to use atomic double word operations on portions
 * of struct page. That is currently only used by slub but the arrangement
 * allows the use of atomic double word operations on the flags/mapping
 * and lru list pointers also.
 */
/* 页描述符，描述一个页框，也会用于描述一个SLAB，相当于同时是页描述符，也是SLAB描述符 */
/* 页的分类:
 * 不可移动页: 在内存中有固定位置，不能移到到其他位置，内核使用的大多数内存属于这种类别的页
 * 可回收页: 针对某个磁盘文件进行映射时使用的页
 * 可移动: 没有针对某个磁盘文件进行映射时使用的页，一般为: 进程堆、进程栈、进程数据段、匿名mmap共享内存、shmem共享内存
 */
struct page {
	/* First double word block */
	/* 用于页描述符，一组标志(如PG_locked、PG_error)，同时页框所在的管理区和node的编号也保存在当中 */
	/* 在lru算法中主要用到的标志
	 * PG_active: 表示此页当前是否活跃，当放到或者准备放到活动lru链表时，被置位
	 * PG_referenced: 表示此页最近是否被访问，每次页面访问都会被置位
	 * PG_lru: 表示此页是处于lru链表中的
	 * PG_mlocked: 表示此页被mlock()锁在内存中，禁止换出和释放
	 * PG_swapbacked: 表示此页依靠swap，可能是进程的匿名页(堆、栈、数据段)，匿名mmap共享内存映射，shmem共享内存映射
	 */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	union {
		/* 最低两位用于判断类型，其他位数用于保存指向的地址
		 * 如果为空，则该页属于交换高速缓存(swap cache，swap时会产生竞争条件，用swap cache解决)  
		 * 不为空，如果最低位为1，该页为匿名页，指向对应的anon_vma(分配时需要对齐)
		 * 不为空，如果最低位为0，则该页为文件页，指向文件的address_space
		 */
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
		/* 用于SLAB描述符，指向第一个对象的地址 */
		void *s_mem;			/* slab first object */
	};


	/* Second double word */
	struct {
		union {
			/* 作为不同的含义被几种内核成分使用。例如，它在页磁盘映像或匿名区中标识存放在页框中的数据的位置，或者它存放一个换出页标识符
			 * 当此页作为映射页(文件映射)时，保存这块页的数据在整个文件数据中以页为大小的偏移量
			 * 当此页作为匿名页时，保存此页在线性区vma内的页索引或者是页的线性地址 >> PAGE_SIZE。
			 * 对于匿名页的page->index表示的是page在vma中的虚拟页框号(此页的开始线性地址 >> PAGE_SIZE)。共享匿名页的产生应该只有在fork，clone完成并在写时复制前。
			 */
			pgoff_t index;		/* Our offset within mapping. */
			/* 用于SLAB和SLUB描述符，指向空闲对象链表 */
			void *freelist;	
			/* 当管理区页框分配器压力过大时，设置这个标志就确保这个页框专门用于释放其他页框时使用 */
			bool pfmemalloc;	/* If set by the page allocator,
						 * ALLOC_NO_WATERMARKS was set
						 * and the low watermark was not
						 * met implying that the system
						 * is under some pressure. The
						 * caller should try ensure
						 * this page is only used to
						 * free other pages.
						 */
		};

		union {
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
	defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
			/* Used for cmpxchg_double in slub */
			/* SLUB使用，在cmpxchg_double中使用 */
			unsigned long counters;
#else
			/*
			 * Keep _count separate from slub cmpxchg_double data.
			 * As the rest of the double word is protected by
			 * slab_lock but _count is not.
			 */
			/* SLUB使用 */
			unsigned counters;
#endif

			struct {

				union {
					/*
					 * Count of ptes mapped in
					 * mms, to show when page is
					 * mapped & limit reverse map
					 * searches.
					 *
					 * Used also for tail pages
					 * refcounting instead of
					 * _count. Tail pages cannot
					 * be mapped and keeping the
					 * tail page _count zero at
					 * all times guarantees
					 * get_page_unless_zero() will
					 * never succeed on tail
					 * pages.
					 */
					/* 页框中的页表项计数，如果没有为-1，如果为PAGE_BUDDY_MAPCOUNT_VALUE(-128)，说明此页及其后的一共2的private次方个数页框处于伙伴系统中
					 * 如果大于等于0，说明此页正在使用，并且表示引用此页框的页表项数量，如果等于0则说明此页是非共享的，大于0表示此页是共享的
					 */
					atomic_t _mapcount;

					struct { /* SLUB使用 */
						/* 已使用对象数量，如果CPU正在使用当前slab，即使还有空闲对象没有使用，inuse也等于objects */
						unsigned inuse:16;
						/* slab中对象数量，默认等于对应 kmem_cache 中的 kmem_cache_order_objects 中的objects数量 */
						unsigned objects:15;
						/* 冻结标识，slub使用，将slab放入kmem_cache_cpu中就为冻结状态 */
						unsigned frozen:1;
					};
					int units;	/* SLOB */
				};
				/* 页框的引用计数，如果为-1，则此页框空闲，并可分配给任一进程或内核；如果大于或等于0，则说明页框被分配给了一个或多个进程，或用于存放内核数据。page_count()返回_count加1的值，也就是该页的使用者数目 */
				/* 当此页从伙伴系统拿出来时，_count被设置为1(这个1代表是此新页要立即要映射给的进程或者使用的内核模块)
				 * 当每多一个进程映射此页时，此值会++，比如映射前此值为0，当有10个进程映射此页时，此值为10
				 * 当此页加入到lru缓存时，这个引用计数会++，从lru缓存中加入到lru链表时，_count会--
				 * 当一个页从lru链表中拿出来时，如果_count如果为0的话，则此页直接释放到伙伴系统中
				 * 当此页加入到swapcache中时，此值会++，从swapcache中拿出来时，会--
				 * 当此页有buffer_head时，此值会++，当此页的buffer_head被移除时，此值会--
				 * 此参数在内存回收的时候有很重要的意义，只有此值为0的页，才会被回收
				 */
				atomic_t _count;		/* Usage count, see below. */
			};
			/* 用于SLAB时描述当前SLAB已经使用的对象 */
			unsigned int active;	/* SLAB */
		};
	};


	/* Third double word block */
	union {
		/* 页处于不同情况时，加入的链表不同
		 * 1.是一个进程正在使用的页，加入到对应lru链表
		 * 2.如果为空闲页框，并且是空闲块的第一个页，加入到伙伴系统的空闲块链表中(只有空闲块的第一个页需要加入)
		 * 3.如果是一个slab的第一个页，则将其加入到slab链表中(比如slab的满slab链表，slub的部分空slab链表)
		 * 4.将页隔离时用于加入隔离链表
		 */
		struct list_head lru;	/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 * Can be used as a generic list
					 * by the page owner.
					 */
		/* SLAB和SLUB使用 */
		struct {		/* slub per cpu partial pages */
			/* 下一个SLAB/SLUB */
			struct page *next;	/* Next partial slab */
#ifdef CONFIG_64BIT
			/* 以下这两个数据只会保存在部分空链表中的第一个SLAB/SLUB中 */
			/* 部分空链表中有多少个slab */
			int pages;	/* Nr of partial slabs left */
			/* 可用objects数量(待定) */
			int pobjects;	/* Approximate # of objects */
#else
			short int pages;
			short int pobjects;
#endif
		};

		/* SLAB使用 */
		struct slab *slab_page; /* slab fields */
		struct rcu_head rcu_head;	/* Used by SLAB
						 * when destroying via RCU
						 */
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && USE_SPLIT_PMD_PTLOCKS
		pgtable_t pmd_huge_pte; /* protected by page->ptl */
#endif
	};


	/* Remainder is not double word aligned */
	union {
		/* 可用于正在使用页的内核成分(例如: 在缓冲页的情况下它是一个缓冲器头指针，如果页是空闲的，则该字段由伙伴系统使用，在给伙伴系统使用时，表明的是块的2的次方数，只有块的第一个页框会使用) 
		 * 当此页是个匿名页，并被交换到swap中时，用于保存此页在swap的swp_entry_t
		 * 当此页是文件页时，保存此页映射的文件数据在磁盘中的块的头结点(struct buffer_head)并且页的标志中会有PAGE_FLAGS_PRIVATE，因为这个页映射的4k数据有可能分散在磁盘多个块上
		 */
		unsigned long private;		
#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
		spinlock_t *ptl;
#else
		spinlock_t ptl;
#endif
#endif
		/* SLAB描述符使用，指向SLAB的高速缓存 */
		struct kmem_cache *slab_cache;	/* SL[AU]B: Pointer to slab */
		struct page *first_page;	/* Compound tail pages */
	};

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	/* 线性地址，如果是没有映射的高端内存的页框，则为空 */
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
#ifdef CONFIG_WANT_PAGE_DEBUG_FLAGS
	unsigned long debug_flags;	/* Use atomic bitops on this */
#endif

#ifdef CONFIG_KMEMCHECK
	/*
	 * kmemcheck wants to track the status of each byte in a page; this
	 * is a pointer to such a status block. NULL if not tracked.
	 */
	void *shadow;
#endif

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
}
/*
 * The struct page can be forced to be double word aligned so that atomic ops
 * on double words work. The SLUB allocator can make use of such a feature.
 */
#ifdef CONFIG_HAVE_ALIGNED_STRUCT_PAGE
	__aligned(2 * sizeof(unsigned long))
#endif
;

struct page_frag {
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 offset;
	__u32 size;
#else
	__u16 offset;
	__u16 size;
#endif
};

typedef unsigned long __nocast vm_flags_t;

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	vm_flags_t	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	int		vm_usage;	/* region usage count (access under nommu_region_sem) */
	bool		vm_icache_flushed : 1; /* true if the icache has been flushed for
						* this region */
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
/* 描述线性区结构 
 * 内核尽力把新分配的线性区与紧邻的现有线性区进程合并。如果两个相邻的线性区访问权限相匹配，就能把它们合并在一起。
 * 每个线性区都有一组连续号码的页(非页框)所组成，而页只有在被访问的时候系统会产生缺页异常，在异常中分配页框
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	/* 线性区内的第一个线性地址 */
	unsigned long vm_start;		
	/* 线性区之外的第一个线性地址 */
	unsigned long vm_end;		

	/* linked list of VM areas per task, sorted by address */
	/* 整个链表会按地址大小递增排序 */
	/* vm_next: 线性区链表中的下一个线性区 */
	/* vm_prev: 线性区链表中的上一个线性区 */
	struct vm_area_struct *vm_next, *vm_prev;

	/* 用于组织当前内存描述符的线性区的红黑树的结点 */
	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	/* 此vma的子树中最大的空闲内存块大小(bytes) */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	/* 指向所属的内存描述符 */
	struct mm_struct *vm_mm;	
	/* 页表项标志的初值，当增加一个页时，内核根据这个字段的值设置相应页表项中的标志 */
	/* 页表中的User/Supervisor标志应当总被置1 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/* 线性区标志
	 * 读写可执行权限会复制到页表项中，由分页单元去检查这几个权限
	 */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/* 链接到反向映射所使用的数据结构，主要用于映射页的反向映射，分线性映射和非线性映射 */
	union {
		/* 线性映射时使用 */
		struct {
			/* 加入到struct address_space中的i_mmap红黑树，实现文件页的反向映射 */
			struct rb_node rb;
			unsigned long rb_subtree_last;
		} linear;
		/* 非线性映射时使用的链表
		 * 非线性映射与线性映射的区别:  
		 * 线性映射，如果vma大小为8K，那映射的内容是文件的连续8K内容，比如0~8K的数据
		 * 非线性映射，如果vma大小为8k，那映射的内容是文件的两个页，这两个页是随机的，比如0~4K,12~16K
		 */
		struct list_head nonlinear;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/* 
	 * 指向匿名线性区链表头的指针，这个链表会将此mm_struct中的所有匿名线性区链接起来
	 * 匿名的MAP_PRIVATE、堆和栈的vma都会存在于这个anon_vma_chain链表中
	 * 如果mm_struct的anon_vma为空，那么其anon_vma_chain也一定为空
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	/* 指向anon_vma数据结构的指针 */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/* 指向线性区操作的方法，对于匿名线性区，一般为空，对于文件映射区，根据文件系统而定，默认是generic_file_vm_ops 
	 * 如果是shmem共享内存，则是shmem_vm_ops
	 */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	/* 如果是映射文件，保存开始地址在映射文件中的偏移量(以页大小为单位)。对匿名页，它等于0或者此vma->vm_start地址对应的页号(此页号非物理页框号，可以理解为虚拟页框号)
	 * 如果此vma是匿名线性区vma，此值为vm_start >> PAGE_SIZE，它保存的是vm_start所在的虚拟页框号
	 */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	/* 指向映射文件的文件对象，也可能指向建立shmem共享内存中返回的struct file，如果是匿名映射区，此值为NULL或者一个匿名文件(这里跟swap有关，待看) */
	struct file * vm_file;		/* File we map to (can be NULL). */
	/* 指向内存区的私有数据 */
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

enum {
	MM_FILEPAGES,	/* 一个进程的mm_struct中文件页数量 */
	MM_ANONPAGES, 	/* 一个进程的mm_struct中匿名页数量 */
	MM_SWAPENTS,	/* 一个进程的mm_struct中页表中标记了页在swap的页表项的数量 */
	NR_MM_COUNTERS
};

#if USE_SPLIT_PTE_PTLOCKS && defined(CONFIG_MMU)
#define SPLIT_RSS_COUNTING
/* per-thread cached information, */
struct task_rss_stat {
	int events;	/* for synchronization threshold */
	int count[NR_MM_COUNTERS];
};
#endif /* USE_SPLIT_PTE_PTLOCKS */

struct mm_rss_stat {
	atomic_long_t count[NR_MM_COUNTERS];
};

struct kioctx_table;
/* 内存描述符，每个进程都会有一个，除了内核线程(使用被调度出去的进程的mm_struct)和轻量级进程(使用父进程的mm_struct) */
/* 所有的内存描述符存放在一个双向链表中，链表中第一个元素是init_mm，它是初始化阶段进程0的内存描述符 */
struct mm_struct {
	/* 指向线性区对象的链表头，链表是经过排序的，按线性地址升序排列 */
	struct vm_area_struct *mmap;		/* list of VMAs */
	/* 指向线性区对象的红黑树的根，一个内存描述符的线性区会用两种方法组织，链表和红黑树，红黑树适合内存描述符有非常多线性区的情况 */
	struct rb_root mm_rb;
	u32 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
	/* 在进程地址空间中找一个可以使用的线性地址空间，查找一个空闲的地址区间
	 * len: 指定区间的长度
	 * 返回新区间的起始地址
	 */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
	/* 标识第一个分配的匿名线性区或文件内存映射的线性地址 */
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long mmap_legacy_base;         /* base of mmap area in bottom-up allocations */
	unsigned long task_size;		/* size of task vm space */
	/* 所有vma中最大的结束地址 */
	unsigned long highest_vm_end;		/* highest vma end address */
	/* 指向页全局目录 */
	pgd_t * pgd;
	/* 次使用计数器，存放了共享此mm_struct的轻量级进程的个数，但所有的mm_users在mm_count的计算中只算作1 */
	atomic_t mm_users;		/* 初始为1 */	
	/* 主使用计数器，当mm_count递减时，系统会检查是否为0，为0则解除这个mm_struct */
	atomic_t mm_count;		/* 初始为1 */		
	/* 页表数 */
	atomic_long_t nr_ptes;			/* Page table pages */
	/* 线性区的个数，默认最多是65535个，系统管理员可以通过写/proc/sys/vm/max_map_count文件修改这个值 */
	int map_count;				/* number of VMAs */
	
	/* 线性区的自旋锁和页表的自旋锁 */
	spinlock_t page_table_lock;		/* Protects page tables and some counters */
	/* 线性区的读写信号量，当需要对某个线性区vma进行操作时，会获取 */
	struct rw_semaphore mmap_sem;

	/* 用于链入内核中所有mm_struct的双向链表中 */
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* 进程所拥有的最大页框数 */
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	/* 进程线性区中的最大页数 */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	/* 进程地址空间的大小(页框数) */
	unsigned long total_vm;		/* Total pages mapped */
	/* 锁住而不能换出的页的数量 */
	unsigned long locked_vm;	/* Pages that have PG_mlocked set */
	unsigned long pinned_vm;	/* Refcount permanently increased */
	/* 共享文件内存映射中的页数量 */
	unsigned long shared_vm;	/* Shared pages (files) */
	/* 可执行内存映射中的页数量 */
	unsigned long exec_vm;		/* VM_EXEC & ~VM_WRITE */
	/* 用户态堆栈的页数量 */
	unsigned long stack_vm;		/* VM_GROWSUP/DOWN */
	unsigned long def_flags;
	
	/* start_code: 可执行代码的起始位置
	 * end_code: 可执行代码的最后位置
	 * start_data: 已初始化数据的起始位置
	 * end_data: 已初始化数据的最后位置
	 */
	unsigned long start_code, end_code, start_data, end_data;
	
	/* start_brk:   堆的起始位置
	 * brk:         堆的当前最后地址
	 * start_stack: 用户态栈的起始地址
	 */
	unsigned long start_brk, brk, start_stack;

	/* arg_start: 命令行参数的起始位置
	 * arg_end:   命令行参数的最后位置
	 * env_start: 环境变量的起始位置
	 * env_end:   环境变量的最后位置
	 */
	unsigned long arg_start, arg_end, env_start, env_end;
	
	/* 开始执行ELF程序时使用 */
	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	/*
	 * Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	/* 分配给进程的页框数量 */
	struct mm_rss_stat rss_stat;

	/* 与binfmt_misc相关? */
	struct linux_binfmt *binfmt;

	/* 用于懒惰TLB交换的位掩码 */
	cpumask_var_t cpu_vm_mask_var;

	/* Architecture-specific MM context */
	/* 指向特定体系结构的表(例如: x86平台上的LDT地址) */
	mm_context_t context;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	struct core_state *core_state; /* coredumping support */
#ifdef CONFIG_AIO
	/* 保护异步IO上下文链表的锁 */
	spinlock_t			ioctx_lock;
	/* 异步IO上下文链表 */
	struct kioctx_table __rcu	*ioctx_table;
#endif
#ifdef CONFIG_MEMCG
	/*
	 * "owner" points to a task that is regarded as the canonical
	 * user/owner of this mm. All of the following must be true in
	 * order for it to be changed:
	 *
	 * current == mm->owner
	 * current->mm != mm
	 * new_owner->mm == mm
	 * new_owner->alloc_lock is held
	 */
	/* 所属进程 */
	struct task_struct __rcu *owner;
#endif

	/* store ref to file /proc/<pid>/exe symlink points to */
	/* 代码段中映射的可执行文件的file，此文件路径会出现在/proc/进程ID/exe文件中 */
	struct file *exe_file;
#ifdef CONFIG_MMU_NOTIFIER
	struct mmu_notifier_mm *mmu_notifier_mm;
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
	pgtable_t pmd_huge_pte; /* protected by page_table_lock */
#endif
#ifdef CONFIG_CPUMASK_OFFSTACK
	struct cpumask cpumask_allocation;
#endif
#ifdef CONFIG_NUMA_BALANCING
	/*
	 * numa_next_scan is the next time that the PTEs will be marked
	 * pte_numa. NUMA hinting faults will gather statistics and migrate
	 * pages to new nodes if necessary.
	 */
	unsigned long numa_next_scan;

	/* Restart point for scanning and setting pte_numa */
	unsigned long numa_scan_offset;

	/* numa_scan_seq prevents two threads setting pte_numa */
	int numa_scan_seq;
#endif
#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
	/*
	 * An operation with batched TLB flushing is going on. Anything that
	 * can move process memory needs to flush the TLB when moving a
	 * PROT_NONE or PROT_NUMA mapped page.
	 */
	bool tlb_flush_pending;
#endif
	struct uprobes_state uprobes_state;
};

static inline void mm_init_cpumask(struct mm_struct *mm)
{
#ifdef CONFIG_CPUMASK_OFFSTACK
	mm->cpu_vm_mask_var = &mm->cpumask_allocation;
#endif
	cpumask_clear(mm->cpu_vm_mask_var);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return mm->cpu_vm_mask_var;
}

#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
/*
 * Memory barriers to keep this state in sync are graciously provided by
 * the page table locks, outside of which no page table modifications happen.
 * The barriers below prevent the compiler from re-ordering the instructions
 * around the memory barriers that are already present in the code.
 */
static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	barrier();
	return mm->tlb_flush_pending;
}
static inline void set_tlb_flush_pending(struct mm_struct *mm)
{
	mm->tlb_flush_pending = true;

	/*
	 * Guarantee that the tlb_flush_pending store does not leak into the
	 * critical section updating the page tables
	 */
	smp_mb__before_spinlock();
}
/* Clearing is done after a TLB flush, which also provides a barrier. */
static inline void clear_tlb_flush_pending(struct mm_struct *mm)
{
	barrier();
	mm->tlb_flush_pending = false;
}
#else
static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	return false;
}
static inline void set_tlb_flush_pending(struct mm_struct *mm)
{
}
static inline void clear_tlb_flush_pending(struct mm_struct *mm)
{
}
#endif

struct vm_special_mapping
{
	const char *name;
	struct page **pages;
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	NR_TLB_FLUSH_REASONS,
};

#endif /* _LINUX_MM_TYPES_H */
