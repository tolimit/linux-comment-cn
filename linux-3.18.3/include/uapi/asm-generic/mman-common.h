#ifndef __ASM_GENERIC_MMAN_COMMON_H
#define __ASM_GENERIC_MMAN_COMMON_H

/*
 Author: Michael S. Tsirkin <mst@mellanox.co.il>, Mellanox Technologies Ltd.
 Based on: asm-xxx/mman.h
*/

/* 页内容可以被读取 */
#define PROT_READ	0x1		/* page can be read */
/* 页可以被写入 */
#define PROT_WRITE	0x2		/* page can be written */
/* 页内容可以被指向 */
#define PROT_EXEC	0x4		/* page can be executed */
/* 页用于原子操作 */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
/* 页不可访问 */
#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */
/* 线性区的页可以被几个进程共享 */
#define MAP_SHARED	0x01	
/* 线性区的页不能被进程共享，但是在fork时，子进程会继承此匿名页线性区，并会进行写时复制 */
#define MAP_PRIVATE	0x02	
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
/* 区间的起始地址必须是由参数addr所指定 */
#define MAP_FIXED	0x10		
/* 建立匿名映射。此时会忽略参数fd，不涉及文件，而且映射区域无法和其他进程共享。可以与有亲属关系的进程共享 */
#define MAP_ANONYMOUS	0x20		
#ifdef CONFIG_MMAP_ALLOW_UNINITIALIZED
# define MAP_UNINITIALIZED 0x4000000	/* For anonymous mmap, memory could be uninitialized */
#else
# define MAP_UNINITIALIZED 0x0		/* Don't support this flag */
#endif

#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */

#define MADV_NORMAL	0		/* no further special treatment */
#define MADV_RANDOM	1		/* expect random page references */
#define MADV_SEQUENTIAL	2		/* expect sequential page references */
#define MADV_WILLNEED	3		/* will need these pages */
#define MADV_DONTNEED	4		/* don't need these pages */

/* common parameters: try to keep these consistent across architectures */
#define MADV_REMOVE	9		/* remove these pages & resources */
#define MADV_DONTFORK	10		/* don't inherit across fork */
#define MADV_DOFORK	11		/* do inherit across fork */
#define MADV_HWPOISON	100		/* poison a page for testing */
#define MADV_SOFT_OFFLINE 101		/* soft offline page for testing */

#define MADV_MERGEABLE   12		/* KSM may merge identical pages */
#define MADV_UNMERGEABLE 13		/* KSM may not merge identical pages */

#define MADV_HUGEPAGE	14		/* Worth backing with hugepages */
#define MADV_NOHUGEPAGE	15		/* Not worth backing with hugepages */

#define MADV_DONTDUMP   16		/* Explicity exclude from the core dump,
					   overrides the coredump filter bits */
#define MADV_DODUMP	17		/* Clear the MADV_DONTDUMP flag */

/* compatibility flags */
#define MAP_FILE	0

/*
 * When MAP_HUGETLB is set bits [26:31] encode the log2 of the huge page size.
 * This gives us 6 bits, which is enough until someone invents 128 bit address
 * spaces.
 *
 * Assume these are all power of twos.
 * When 0 use the default page size.
 */
#define MAP_HUGE_SHIFT	26
#define MAP_HUGE_MASK	0x3f

#endif /* __ASM_GENERIC_MMAN_COMMON_H */
