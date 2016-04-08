#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* ¸¸×Ó½ø³Ì¹²ÏíÄÚ´æÃèÊö·ûºÍËùÓĞÒ³±í */
#define CLONE_FS	0x00000200	/* ¸¸×Ó½ø³Ì¹²Ïí¸ùÄ¿Â¼ºÍµ±Ç°¹¤×÷Ä¿Â¼ËùÔÚÎÄ¼şµÄ±í£¬ÒÔ¼°ÓÃÓÚÆÁ±ÎĞÂÎÄ¼ş³õÊ¼Ğí¿ÉÈ¨µÄÎ»ÑÚÂë(umask) */
#define CLONE_FILES	0x00000400	/* ¸¸×Ó½ø³Ì¹²ÏíÒÑ´ò¿ªµÄÎÄ¼şÃèÊö·û */
#define CLONE_SIGHAND	0x00000800	/* ¸¸×Ó½ø³Ì¹²ÏíÏàÍ¬µÄĞÅºÅ´¦Àí³ÌĞò±í£¬¼´¸¸½ø³Ì»ò×Ó½ø³ÌÍ¨¹ısigactionĞŞ¸ÄĞÅºÅµÄ´¦Àí·½Ê½£¬Ò²»áÓ°ÏìÆäËû½ø³Ì¡£ 
									   µ«ÊÇ¸¸½ø³ÌºÍ×Ó½ø³Ì¸÷ÖÖÓĞ¶ÀÁ¢ÑÚÂë£¬Òò´ËÒ»¸ö½ø³ÌÍ¨¹ısigprocmaskÀ´×èÈû»ò²»×èÈûÄ³¸öĞÅºÅ£¬ÊÇ²»»áÓ°ÏìÆäËû½ø³ÌµÄ¡£ */
#define CLONE_PTRACE	0x00002000	/* Èç¹û¸¸½ø³Ì±»¸ú×Ù¿ÉÒÔ¼ÌĞø¸ú×Ù×Ó½ø³Ì */
#define CLONE_VFORK	0x00004000	/* ¸¸½ø³ÌÖ»ÄÜÔÚ×Ó½ø³ÌÊÍ·ÅµôËùÕ¼ÄÚ´æ×ÊÔ´ºó²Å±»»½ĞÑ */
#define CLONE_PARENT	0x00008000	/* ¸¸×Ó½ø³ÌÎªĞÖµÜ¹ØÏµ(ËûÃÇµÄ¸¸½ø³ÌÏàÍ¬) */
#define CLONE_THREAD	0x00010000	/* °Ñ×Ó½ø³Ì²åÈëµ½¸¸½ø³ÌµÄÍ¬Ò»Ïß³Ì×éÖĞ£¬´Ë±êÊ¾±ØĞëºÍCLONE_SIGHANDÅäÌ×Ê¹ÓÃ£¬Ïß³Ì¹²ÏíĞÅºÅ */
#define CLONE_NEWNS	0x00020000	/* ×Ó½ø³ÌÓĞËü×Ô¼ºµÄnamespace */
#define CLONE_SYSVSEM	0x00040000	/* ¸¸×Ó½ø³Ì¹²ÏíĞÅºÅÁ¿ */
#define CLONE_SETTLS	0x00080000	/* Îª×Ó½ø³Ì´´½¨Ò»¸öĞÂµÄTLS,¾ßÌå¼ûhttp://www.linuxidc.com/Linux/2012-06/64079p2.htm */
#define CLONE_PARENT_SETTID	0x00100000	/* °Ñ×Ó½ø³ÌµÄPIDĞ´ÈëÓÉptid²ÎÊıËùÖ¸ÏòµÄ¸¸½ø³ÌµÄÓÃ»§Ì¬±äÁ¿ */
#define CLONE_CHILD_CLEARTID	0x00200000	/* Èç¹û´Ë±êÖ¾±»ÉèÖÃ£¬ÔòÄÚºË½¨Á¢Ò»ÖÖ´¥·¢»úÖÆ£¬ÓÃÔÚ×Ó½ø³ÌÒªÍË³ö»òÕß×¼±¸¿ªÊ¼Ö´ĞĞ³ÌĞòÊ±£¬
											   ÔÚÕâĞ©Çé¿öÏÂ£¬ÄÚºË½«Çå³ıÓÉ²ÎÊıchild_tidptrËùÖ¸µÄÓÃ»§Ì¬±äÁ¿£¬²¢»½ĞÑµÈ´ıÕâ¸öÊÂ¼şµÄÈÎºÎ½ø³Ì */
#define CLONE_DETACHED		0x00400000	/* ºöÂÔ */
#define CLONE_UNTRACED		0x00800000	/* µ±¸¸½ø³Ì±»¸ú×ÙÊ±£¬²»µ¼ÖÂ×Ó½ø³ÌÒ²±»¸ú×Ù */
#define CLONE_CHILD_SETTID	0x01000000	/* °Ñ×Ó½ø³ÌµÄPIDĞ´ÈëÓÉchild_tidptr²ÎÊıËùÖ¸ÏòµÄ×Ó½ø³ÌµÄÓÃ»§Ì¬±äÁ¿ÖĞ */

/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
   and is now available for re-use. */
   
/* ÒÔÏÂ¸únamespaceÓĞ¹Ø£,¾ßÌå¼û
 * http://laokaddk.blog.51cto.com/368606/674256 
 */
#define CLONE_NEWUTS		0x04000000	/* New utsname group? */
#define CLONE_NEWIPC		0x08000000	/* New ipcs (IPC½ø³Ì¼äÍ¨ĞÅ) */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* ¸¸×Ó½ø³Ì¹²ÏíIO */

/*
 * µ÷¶È²ßÂÔ
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5
#define SCHED_DEADLINE		6

/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
#define SCHED_RESET_ON_FORK     0x40000000

/*
 * For the sched_{set,get}attr() calls
 */
#define SCHED_FLAG_RESET_ON_FORK	0x01

#endif /* _UAPI_LINUX_SCHED_H */
