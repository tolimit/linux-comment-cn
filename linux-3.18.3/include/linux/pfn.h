#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
/* ���ش������Ե�ַX�ĵ�һ��ҳ��� */
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
/* �������Ե�ַX����ҳ��� */
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
/* ����ҳ���X�������ַ */
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

#endif
