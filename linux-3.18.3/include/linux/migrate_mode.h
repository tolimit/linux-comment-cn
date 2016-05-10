#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED
/*
 * MIGRATE_ASYNC means never block
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 * MIGRATE_SYNC will block when migrating pages
 */
enum migrate_mode {
	/* 
	 * 异步模式的意思是禁止阻塞，遇到阻塞和需要调度的时候直接返回，返回前会把隔离出来的页框放回去
	 * 在内存不足以分配连续页框时进行内存压缩，默认初始是异步模式，如果异步模式后还不能分配连续内存，则会转为轻同步模式(当明确表示不处理透明大页，或者当前进程是内核线程时，就会转为请同步模式)
	 * 而kswapd内核线程中只使用异步模式，不会使用同步模式
	 * 所以异步不处理MIRGATE_RECLAIMABLE类型的页框，因为这部分页框很大可能导致回写然后阻塞，只处理MIGRATE_MOVABLE和MIGRATE_CMA类型中的页
	 * 即使匿名页加入到了swapcache，被标记为了脏页，这里也不会进行回写，只有匿名页被内存回收换出时，才会进行回写
	 * 异步模式不会增加推迟计数器阀值
	 */
	MIGRATE_ASYNC,
	/* 在内存不足以分配连续页框并进行了异步内存压缩之后，有可能会进行轻同步模式，轻同步模式下处理MIRGATE_RECLAIMABLE、MIGRATE_MOVABLE和MIGRATE_CMA类型的页
	 * 此模式下允许进行大多数操作的阻塞，比如在磁盘设备繁忙时，锁繁忙时，但不会阻塞等待正在回写的页结束，对于正在回写的页直接跳过，也不会对脏页进行回写
	 * 轻同步模式会增加推迟计数器阀值
	 */
	MIGRATE_SYNC_LIGHT,
	/* 同步模式意味着在轻同步基础上，可能会对隔离出来需要移动的脏文件页进行回写到磁盘的操作(只会对脏文件页进行回写，脏匿名页只做移动，不会被回写)，并且当待处理的页正在回写时，会等待到回写结束 
	 * 这种模式发生有三种情况:
	 * 1.cma分配
	 * 2.通过alloc_contig_range()尝试分配一段指定了开始页框号和结束页框号的连续页框时
	 * 3.将1写入sysfs中的vm/compact_memory
	 * 同步模式会增加推迟计数器阀值，并且在同步模式下，会设置好compact_control，让同步模式时忽略pageblock的PB_migrate_skip标记
	 */
	MIGRATE_SYNC,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
