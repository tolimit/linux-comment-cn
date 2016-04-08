#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
/* 返回大于线性地址X的第一个页框号 */
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
/* 返回线性地址X所在页框号 */
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
/* 返回页框号X的物理地址 */
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

#endif
