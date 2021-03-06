#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* 父子进程共享内存描述符和所有页表 */
#define CLONE_FS	0x00000200	/* 父子进程共享根目录和当前工作目录所在文件的表，以及用于屏蔽新文件初始许可权的位掩码(umask) */
#define CLONE_FILES	0x00000400	/* 父子进程共享已打开的文件描述符 */
#define CLONE_SIGHAND	0x00000800	/* 父子进程共享相同的信号处理程序表，即父进程或子进程通过sigaction修改信号的处理方式，也会影响其他进程。 
									   但是父进程和子进程各种有独立掩码，因此一个进程通过sigprocmask来阻塞或不阻塞某个信号，是不会影响其他进程的。 */
#define CLONE_PTRACE	0x00002000	/* 如果父进程被跟踪可以继续跟踪子进程 */
#define CLONE_VFORK	0x00004000	/* 父进程只能在子进程释放掉所占内存资源后才被唤醒 */
#define CLONE_PARENT	0x00008000	/* 父子进程为兄弟关系(他们的父进程相同) */
#define CLONE_THREAD	0x00010000	/* 把子进程插入到父进程的同一线程组中，此标示必须和CLONE_SIGHAND配套使用，线程共享信号 */
#define CLONE_NEWNS	0x00020000	/* 子进程有它自己的namespace */
#define CLONE_SYSVSEM	0x00040000	/* 父子进程共享信号量 */
#define CLONE_SETTLS	0x00080000	/* 为子进程创建一个新的TLS,具体见http://www.linuxidc.com/Linux/2012-06/64079p2.htm */
#define CLONE_PARENT_SETTID	0x00100000	/* 把子进程的PID写入由ptid参数所指向的父进程的用户态变量 */
#define CLONE_CHILD_CLEARTID	0x00200000	/* 如果此标志被设置，则内核建立一种触发机制，用在子进程要退出或者准备开始执行程序时，
											   在这些情况下，内核将清除由参数child_tidptr所指的用户态变量，并唤醒等待这个事件的任何进程 */
#define CLONE_DETACHED		0x00400000	/* 忽略 */
#define CLONE_UNTRACED		0x00800000	/* 当父进程被跟踪时，不导致子进程也被跟踪 */
#define CLONE_CHILD_SETTID	0x01000000	/* 把子进程的PID写入由child_tidptr参数所指向的子进程的用户态变量中 */

/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
   and is now available for re-use. */
   
/* 以下跟namespace有关�,具体见
 * http://laokaddk.blog.51cto.com/368606/674256 
 */
#define CLONE_NEWUTS		0x04000000	/* New utsname group? */
#define CLONE_NEWIPC		0x08000000	/* New ipcs (IPC进程间通信) */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* 父子进程共享IO */

/*
 * 调度策略
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
