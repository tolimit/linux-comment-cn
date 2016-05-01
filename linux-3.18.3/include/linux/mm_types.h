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
/* ҳ������������һ��ҳ��Ҳ����������һ��SLAB���൱��ͬʱ��ҳ��������Ҳ��SLAB������ */
/* ҳ�ķ���:
 * �����ƶ�ҳ: ���ڴ����й̶�λ�ã������Ƶ�������λ�ã��ں�ʹ�õĴ�����ڴ�������������ҳ
 * �ɻ���ҳ: ���ĳ�������ļ�����ӳ��ʱʹ�õ�ҳ
 * ���ƶ�: û�����ĳ�������ļ�����ӳ��ʱʹ�õ�ҳ��һ��Ϊ: ���̶ѡ�����ջ���������ݶΡ�����mmap�����ڴ桢shmem�����ڴ�
 */
struct page {
	/* First double word block */
	/* ����ҳ��������һ���־(��PG_locked��PG_error)��ͬʱҳ�����ڵĹ�������node�ı��Ҳ�����ڵ��� */
	/* ��lru�㷨����Ҫ�õ��ı�־
	 * PG_active: ��ʾ��ҳ��ǰ�Ƿ��Ծ�����ŵ�����׼���ŵ��lru����ʱ������λ
	 * PG_referenced: ��ʾ��ҳ����Ƿ񱻷��ʣ�ÿ��ҳ����ʶ��ᱻ��λ
	 * PG_lru: ��ʾ��ҳ�Ǵ���lru�����е�
	 * PG_mlocked: ��ʾ��ҳ��mlock()�����ڴ��У���ֹ�������ͷ�
	 * PG_swapbacked: ��ʾ��ҳ����swap�������ǽ��̵�����ҳ(�ѡ�ջ�����ݶ�)������mmap�����ڴ�ӳ�䣬shmem�����ڴ�ӳ��
	 */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	union {
		/* �����λ�����ж����ͣ�����λ�����ڱ���ָ��ĵ�ַ
		 * ���Ϊ�գ����ҳ���ڽ������ٻ���(swap cache��swapʱ�����������������swap cache���)  
		 * ��Ϊ�գ�������λΪ1����ҳΪ����ҳ��ָ���Ӧ��anon_vma(����ʱ��Ҫ����)
		 * ��Ϊ�գ�������λΪ0�����ҳΪ�ļ�ҳ��ָ���ļ���address_space
		 */
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
		/* ����SLAB��������ָ���һ������ĵ�ַ */
		void *s_mem;			/* slab first object */
	};


	/* Second double word */
	struct {
		union {
			/* ��Ϊ��ͬ�ĺ��屻�����ں˳ɷ�ʹ�á����磬����ҳ����ӳ����������б�ʶ�����ҳ���е����ݵ�λ�ã����������һ������ҳ��ʶ��
			 * ����ҳ��Ϊӳ��ҳ(�ļ�ӳ��)ʱ���������ҳ�������������ļ���������ҳΪ��С��ƫ����
			 * ����ҳ��Ϊ����ҳʱ�������ҳ��������vma�ڵ�ҳ����������ҳ�����Ե�ַ >> PAGE_SIZE��
			 * ��������ҳ��page->index��ʾ����page��vma�е�����ҳ���(��ҳ�Ŀ�ʼ���Ե�ַ >> PAGE_SIZE)����������ҳ�Ĳ���Ӧ��ֻ����fork��clone��ɲ���дʱ����ǰ��
			 */
			pgoff_t index;		/* Our offset within mapping. */
			/* ����SLAB��SLUB��������ָ����ж������� */
			void *freelist;	
			/* ��������ҳ�������ѹ������ʱ�����������־��ȷ�����ҳ��ר�������ͷ�����ҳ��ʱʹ�� */
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
			/* SLUBʹ�ã���cmpxchg_double��ʹ�� */
			unsigned long counters;
#else
			/*
			 * Keep _count separate from slub cmpxchg_double data.
			 * As the rest of the double word is protected by
			 * slab_lock but _count is not.
			 */
			/* SLUBʹ�� */
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
					/* ҳ���е�ҳ������������û��Ϊ-1�����ΪPAGE_BUDDY_MAPCOUNT_VALUE(-128)��˵����ҳ������һ��2��private�η�����ҳ���ڻ��ϵͳ��
					 * ������ڵ���0��˵����ҳ����ʹ�ã����ұ�ʾ���ô�ҳ���ҳ�����������������0��˵����ҳ�Ƿǹ���ģ�����0��ʾ��ҳ�ǹ����
					 */
					atomic_t _mapcount;

					struct { /* SLUBʹ�� */
						/* ��ʹ�ö������������CPU����ʹ�õ�ǰslab����ʹ���п��ж���û��ʹ�ã�inuseҲ����objects */
						unsigned inuse:16;
						/* slab�ж���������Ĭ�ϵ��ڶ�Ӧ kmem_cache �е� kmem_cache_order_objects �е�objects���� */
						unsigned objects:15;
						/* �����ʶ��slubʹ�ã���slab����kmem_cache_cpu�о�Ϊ����״̬ */
						unsigned frozen:1;
					};
					int units;	/* SLOB */
				};
				/* ҳ������ü��������Ϊ-1�����ҳ����У����ɷ������һ���̻��ںˣ�������ڻ����0����˵��ҳ�򱻷������һ���������̣������ڴ���ں����ݡ�page_count()����_count��1��ֵ��Ҳ���Ǹ�ҳ��ʹ������Ŀ */
				/* ����ҳ�ӻ��ϵͳ�ó���ʱ��_count������Ϊ1(���1�����Ǵ���ҳҪ����Ҫӳ����Ľ��̻���ʹ�õ��ں�ģ��)
				 * ��ÿ��һ������ӳ���ҳʱ����ֵ��++������ӳ��ǰ��ֵΪ0������10������ӳ���ҳʱ����ֵΪ10
				 * ����ҳ���뵽lru����ʱ��������ü�����++����lru�����м��뵽lru����ʱ��_count��--
				 * ��һ��ҳ��lru�������ó���ʱ�����_count���Ϊ0�Ļ������ҳֱ���ͷŵ����ϵͳ��
				 * ����ҳ���뵽swapcache��ʱ����ֵ��++����swapcache���ó���ʱ����--
				 * ����ҳ��buffer_headʱ����ֵ��++������ҳ��buffer_head���Ƴ�ʱ����ֵ��--
				 * �˲������ڴ���յ�ʱ���к���Ҫ�����壬ֻ�д�ֵΪ0��ҳ���Żᱻ����
				 */
				atomic_t _count;		/* Usage count, see below. */
			};
			/* ����SLABʱ������ǰSLAB�Ѿ�ʹ�õĶ��� */
			unsigned int active;	/* SLAB */
		};
	};


	/* Third double word block */
	union {
		/* ҳ���ڲ�ͬ���ʱ�����������ͬ
		 * 1.��һ����������ʹ�õ�ҳ�����뵽��Ӧlru����
		 * 2.���Ϊ����ҳ�򣬲����ǿ��п�ĵ�һ��ҳ�����뵽���ϵͳ�Ŀ��п�������(ֻ�п��п�ĵ�һ��ҳ��Ҫ����)
		 * 3.�����һ��slab�ĵ�һ��ҳ��������뵽slab������(����slab����slab����slub�Ĳ��ֿ�slab����)
		 * 4.��ҳ����ʱ���ڼ����������
		 */
		struct list_head lru;	/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 * Can be used as a generic list
					 * by the page owner.
					 */
		/* SLAB��SLUBʹ�� */
		struct {		/* slub per cpu partial pages */
			/* ��һ��SLAB/SLUB */
			struct page *next;	/* Next partial slab */
#ifdef CONFIG_64BIT
			/* ��������������ֻ�ᱣ���ڲ��ֿ������еĵ�һ��SLAB/SLUB�� */
			/* ���ֿ��������ж��ٸ�slab */
			int pages;	/* Nr of partial slabs left */
			/* ����objects����(����) */
			int pobjects;	/* Approximate # of objects */
#else
			short int pages;
			short int pobjects;
#endif
		};

		/* SLABʹ�� */
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
		/* ����������ʹ��ҳ���ں˳ɷ�(����: �ڻ���ҳ�����������һ��������ͷָ�룬���ҳ�ǿ��еģ�����ֶ��ɻ��ϵͳʹ�ã��ڸ����ϵͳʹ��ʱ���������ǿ��2�Ĵη�����ֻ�п�ĵ�һ��ҳ���ʹ��) 
		 * ����ҳ�Ǹ�����ҳ������������swap��ʱ�����ڱ����ҳ��swap��swp_entry_t
		 * ����ҳ���ļ�ҳʱ�������ҳӳ����ļ������ڴ����еĿ��ͷ���(struct buffer_head)����ҳ�ı�־�л���PAGE_FLAGS_PRIVATE����Ϊ���ҳӳ���4k�����п��ܷ�ɢ�ڴ��̶������
		 */
		unsigned long private;		
#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
		spinlock_t *ptl;
#else
		spinlock_t ptl;
#endif
#endif
		/* SLAB������ʹ�ã�ָ��SLAB�ĸ��ٻ��� */
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
	/* ���Ե�ַ�������û��ӳ��ĸ߶��ڴ��ҳ����Ϊ�� */
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
/* �����������ṹ 
 * �ں˾������·��������������ڵ��������������̺ϲ�������������ڵ�����������Ȩ����ƥ�䣬���ܰ����Ǻϲ���һ��
 * ÿ������������һ�����������ҳ(��ҳ��)����ɣ���ҳֻ���ڱ����ʵ�ʱ��ϵͳ�����ȱҳ�쳣�����쳣�з���ҳ��
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	/* �������ڵĵ�һ�����Ե�ַ */
	unsigned long vm_start;		
	/* ������֮��ĵ�һ�����Ե�ַ */
	unsigned long vm_end;		

	/* linked list of VM areas per task, sorted by address */
	/* ��������ᰴ��ַ��С�������� */
	/* vm_next: �����������е���һ�������� */
	/* vm_prev: �����������е���һ�������� */
	struct vm_area_struct *vm_next, *vm_prev;

	/* ������֯��ǰ�ڴ����������������ĺ�����Ľ�� */
	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	/* ��vma�����������Ŀ����ڴ���С(bytes) */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	/* ָ���������ڴ������� */
	struct mm_struct *vm_mm;	
	/* ҳ�����־�ĳ�ֵ��������һ��ҳʱ���ں˸�������ֶε�ֵ������Ӧҳ�����еı�־ */
	/* ҳ���е�User/Supervisor��־Ӧ���ܱ���1 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/* ��������־
	 * ��д��ִ��Ȩ�޻Ḵ�Ƶ�ҳ�����У��ɷ�ҳ��Ԫȥ����⼸��Ȩ��
	 */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/* ���ӵ�����ӳ����ʹ�õ����ݽṹ����Ҫ����ӳ��ҳ�ķ���ӳ�䣬������ӳ��ͷ�����ӳ�� */
	union {
		/* ����ӳ��ʱʹ�� */
		struct {
			/* ���뵽struct address_space�е�i_mmap�������ʵ���ļ�ҳ�ķ���ӳ�� */
			struct rb_node rb;
			unsigned long rb_subtree_last;
		} linear;
		/* ������ӳ��ʱʹ�õ�����
		 * ������ӳ��������ӳ�������:  
		 * ����ӳ�䣬���vma��СΪ8K����ӳ����������ļ�������8K���ݣ�����0~8K������
		 * ������ӳ�䣬���vma��СΪ8k����ӳ����������ļ�������ҳ��������ҳ������ģ�����0~4K,12~16K
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
	 * ָ����������������ͷ��ָ�룬�������Ὣ��mm_struct�е�����������������������
	 * ������MAP_PRIVATE���Ѻ�ջ��vma������������anon_vma_chain������
	 * ���mm_struct��anon_vmaΪ�գ���ô��anon_vma_chainҲһ��Ϊ��
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	/* ָ��anon_vma���ݽṹ��ָ�� */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/* ָ�������������ķ���������������������һ��Ϊ�գ������ļ�ӳ�����������ļ�ϵͳ������Ĭ����generic_file_vm_ops 
	 * �����shmem�����ڴ棬����shmem_vm_ops
	 */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	/* �����ӳ���ļ������濪ʼ��ַ��ӳ���ļ��е�ƫ����(��ҳ��СΪ��λ)��������ҳ��������0���ߴ�vma->vm_start��ַ��Ӧ��ҳ��(��ҳ�ŷ�����ҳ��ţ��������Ϊ����ҳ���)
	 * �����vma������������vma����ֵΪvm_start >> PAGE_SIZE�����������vm_start���ڵ�����ҳ���
	 */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	/* ָ��ӳ���ļ����ļ�����Ҳ����ָ����shmem�����ڴ��з��ص�struct file�����������ӳ��������ֵΪNULL����һ�������ļ�(�����swap�йأ�����) */
	struct file * vm_file;		/* File we map to (can be NULL). */
	/* ָ���ڴ�����˽������ */
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
	MM_FILEPAGES,	/* һ�����̵�mm_struct���ļ�ҳ���� */
	MM_ANONPAGES, 	/* һ�����̵�mm_struct������ҳ���� */
	MM_SWAPENTS,	/* һ�����̵�mm_struct��ҳ���б����ҳ��swap��ҳ��������� */
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
/* �ڴ���������ÿ�����̶�����һ���������ں��߳�(ʹ�ñ����ȳ�ȥ�Ľ��̵�mm_struct)������������(ʹ�ø����̵�mm_struct) */
/* ���е��ڴ������������һ��˫�������У������е�һ��Ԫ����init_mm�����ǳ�ʼ���׶ν���0���ڴ������� */
struct mm_struct {
	/* ָ�����������������ͷ�������Ǿ�������ģ������Ե�ַ�������� */
	struct vm_area_struct *mmap;		/* list of VMAs */
	/* ָ������������ĺ�����ĸ���һ���ڴ����������������������ַ�����֯������ͺ������������ʺ��ڴ��������зǳ�������������� */
	struct rb_root mm_rb;
	u32 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
	/* �ڽ��̵�ַ�ռ�����һ������ʹ�õ����Ե�ַ�ռ䣬����һ�����еĵ�ַ����
	 * len: ָ������ĳ���
	 * �������������ʼ��ַ
	 */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
	/* ��ʶ��һ��������������������ļ��ڴ�ӳ������Ե�ַ */
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long mmap_legacy_base;         /* base of mmap area in bottom-up allocations */
	unsigned long task_size;		/* size of task vm space */
	/* ����vma�����Ľ�����ַ */
	unsigned long highest_vm_end;		/* highest vma end address */
	/* ָ��ҳȫ��Ŀ¼ */
	pgd_t * pgd;
	/* ��ʹ�ü�����������˹����mm_struct�����������̵ĸ����������е�mm_users��mm_count�ļ�����ֻ����1 */
	atomic_t mm_users;		/* ��ʼΪ1 */	
	/* ��ʹ�ü���������mm_count�ݼ�ʱ��ϵͳ�����Ƿ�Ϊ0��Ϊ0�������mm_struct */
	atomic_t mm_count;		/* ��ʼΪ1 */		
	/* ҳ���� */
	atomic_long_t nr_ptes;			/* Page table pages */
	/* �������ĸ�����Ĭ�������65535����ϵͳ����Ա����ͨ��д/proc/sys/vm/max_map_count�ļ��޸����ֵ */
	int map_count;				/* number of VMAs */
	
	/* ����������������ҳ��������� */
	spinlock_t page_table_lock;		/* Protects page tables and some counters */
	/* �������Ķ�д�ź���������Ҫ��ĳ��������vma���в���ʱ�����ȡ */
	struct rw_semaphore mmap_sem;

	/* ���������ں�������mm_struct��˫�������� */
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* ������ӵ�е����ҳ���� */
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	/* �����������е����ҳ�� */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	/* ���̵�ַ�ռ�Ĵ�С(ҳ����) */
	unsigned long total_vm;		/* Total pages mapped */
	/* ��ס�����ܻ�����ҳ������ */
	unsigned long locked_vm;	/* Pages that have PG_mlocked set */
	unsigned long pinned_vm;	/* Refcount permanently increased */
	/* �����ļ��ڴ�ӳ���е�ҳ���� */
	unsigned long shared_vm;	/* Shared pages (files) */
	/* ��ִ���ڴ�ӳ���е�ҳ���� */
	unsigned long exec_vm;		/* VM_EXEC & ~VM_WRITE */
	/* �û�̬��ջ��ҳ���� */
	unsigned long stack_vm;		/* VM_GROWSUP/DOWN */
	unsigned long def_flags;
	
	/* start_code: ��ִ�д������ʼλ��
	 * end_code: ��ִ�д�������λ��
	 * start_data: �ѳ�ʼ�����ݵ���ʼλ��
	 * end_data: �ѳ�ʼ�����ݵ����λ��
	 */
	unsigned long start_code, end_code, start_data, end_data;
	
	/* start_brk:   �ѵ���ʼλ��
	 * brk:         �ѵĵ�ǰ����ַ
	 * start_stack: �û�̬ջ����ʼ��ַ
	 */
	unsigned long start_brk, brk, start_stack;

	/* arg_start: �����в�������ʼλ��
	 * arg_end:   �����в��������λ��
	 * env_start: ������������ʼλ��
	 * env_end:   �������������λ��
	 */
	unsigned long arg_start, arg_end, env_start, env_end;
	
	/* ��ʼִ��ELF����ʱʹ�� */
	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	/*
	 * Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	/* ��������̵�ҳ������ */
	struct mm_rss_stat rss_stat;

	/* ��binfmt_misc���? */
	struct linux_binfmt *binfmt;

	/* ��������TLB������λ���� */
	cpumask_var_t cpu_vm_mask_var;

	/* Architecture-specific MM context */
	/* ָ���ض���ϵ�ṹ�ı�(����: x86ƽ̨�ϵ�LDT��ַ) */
	mm_context_t context;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	struct core_state *core_state; /* coredumping support */
#ifdef CONFIG_AIO
	/* �����첽IO������������� */
	spinlock_t			ioctx_lock;
	/* �첽IO���������� */
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
	/* �������� */
	struct task_struct __rcu *owner;
#endif

	/* store ref to file /proc/<pid>/exe symlink points to */
	/* �������ӳ��Ŀ�ִ���ļ���file�����ļ�·���������/proc/����ID/exe�ļ��� */
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
