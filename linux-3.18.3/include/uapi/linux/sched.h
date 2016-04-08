#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* ���ӽ��̹����ڴ�������������ҳ�� */
#define CLONE_FS	0x00000200	/* ���ӽ��̹����Ŀ¼�͵�ǰ����Ŀ¼�����ļ��ı��Լ������������ļ���ʼ���Ȩ��λ����(umask) */
#define CLONE_FILES	0x00000400	/* ���ӽ��̹����Ѵ򿪵��ļ������� */
#define CLONE_SIGHAND	0x00000800	/* ���ӽ��̹�����ͬ���źŴ��������������̻��ӽ���ͨ��sigaction�޸��źŵĴ���ʽ��Ҳ��Ӱ���������̡� 
									   ���Ǹ����̺��ӽ��̸����ж������룬���һ������ͨ��sigprocmask������������ĳ���źţ��ǲ���Ӱ���������̵ġ� */
#define CLONE_PTRACE	0x00002000	/* ��������̱����ٿ��Լ��������ӽ��� */
#define CLONE_VFORK	0x00004000	/* ������ֻ�����ӽ����ͷŵ���ռ�ڴ���Դ��ű����� */
#define CLONE_PARENT	0x00008000	/* ���ӽ���Ϊ�ֵܹ�ϵ(���ǵĸ�������ͬ) */
#define CLONE_THREAD	0x00010000	/* ���ӽ��̲��뵽�����̵�ͬһ�߳����У��˱�ʾ�����CLONE_SIGHAND����ʹ�ã��̹߳����ź� */
#define CLONE_NEWNS	0x00020000	/* �ӽ��������Լ���namespace */
#define CLONE_SYSVSEM	0x00040000	/* ���ӽ��̹����ź��� */
#define CLONE_SETTLS	0x00080000	/* Ϊ�ӽ��̴���һ���µ�TLS,�����http://www.linuxidc.com/Linux/2012-06/64079p2.htm */
#define CLONE_PARENT_SETTID	0x00100000	/* ���ӽ��̵�PIDд����ptid������ָ��ĸ����̵��û�̬���� */
#define CLONE_CHILD_CLEARTID	0x00200000	/* ����˱�־�����ã����ں˽���һ�ִ������ƣ������ӽ���Ҫ�˳�����׼����ʼִ�г���ʱ��
											   ����Щ����£��ں˽�����ɲ���child_tidptr��ָ���û�̬�����������ѵȴ�����¼����κν��� */
#define CLONE_DETACHED		0x00400000	/* ���� */
#define CLONE_UNTRACED		0x00800000	/* �������̱�����ʱ���������ӽ���Ҳ������ */
#define CLONE_CHILD_SETTID	0x01000000	/* ���ӽ��̵�PIDд����child_tidptr������ָ����ӽ��̵��û�̬������ */

/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
   and is now available for re-use. */
   
/* ���¸�namespace�йأ,�����
 * http://laokaddk.blog.51cto.com/368606/674256 
 */
#define CLONE_NEWUTS		0x04000000	/* New utsname group? */
#define CLONE_NEWIPC		0x08000000	/* New ipcs (IPC���̼�ͨ��) */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* ���ӽ��̹���IO */

/*
 * ���Ȳ���
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
