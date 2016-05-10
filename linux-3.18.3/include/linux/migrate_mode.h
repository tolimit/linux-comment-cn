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
	 * �첽ģʽ����˼�ǽ�ֹ������������������Ҫ���ȵ�ʱ��ֱ�ӷ��أ�����ǰ��Ѹ��������ҳ��Ż�ȥ
	 * ���ڴ治���Է�������ҳ��ʱ�����ڴ�ѹ����Ĭ�ϳ�ʼ���첽ģʽ������첽ģʽ�󻹲��ܷ��������ڴ棬���תΪ��ͬ��ģʽ(����ȷ��ʾ������͸����ҳ�����ߵ�ǰ�������ں��߳�ʱ���ͻ�תΪ��ͬ��ģʽ)
	 * ��kswapd�ں��߳���ֻʹ���첽ģʽ������ʹ��ͬ��ģʽ
	 * �����첽������MIRGATE_RECLAIMABLE���͵�ҳ����Ϊ�ⲿ��ҳ��ܴ���ܵ��»�дȻ��������ֻ����MIGRATE_MOVABLE��MIGRATE_CMA�����е�ҳ
	 * ��ʹ����ҳ���뵽��swapcache�������Ϊ����ҳ������Ҳ������л�д��ֻ������ҳ���ڴ���ջ���ʱ���Ż���л�д
	 * �첽ģʽ���������Ƴټ�������ֵ
	 */
	MIGRATE_ASYNC,
	/* ���ڴ治���Է�������ҳ�򲢽������첽�ڴ�ѹ��֮���п��ܻ������ͬ��ģʽ����ͬ��ģʽ�´���MIRGATE_RECLAIMABLE��MIGRATE_MOVABLE��MIGRATE_CMA���͵�ҳ
	 * ��ģʽ��������д���������������������ڴ����豸��æʱ������æʱ�������������ȴ����ڻ�д��ҳ�������������ڻ�д��ҳֱ��������Ҳ�������ҳ���л�д
	 * ��ͬ��ģʽ�������Ƴټ�������ֵ
	 */
	MIGRATE_SYNC_LIGHT,
	/* ͬ��ģʽ��ζ������ͬ�������ϣ����ܻ�Ը��������Ҫ�ƶ������ļ�ҳ���л�д�����̵Ĳ���(ֻ������ļ�ҳ���л�д��������ҳֻ���ƶ������ᱻ��д)�����ҵ��������ҳ���ڻ�дʱ����ȴ�����д���� 
	 * ����ģʽ�������������:
	 * 1.cma����
	 * 2.ͨ��alloc_contig_range()���Է���һ��ָ���˿�ʼҳ��źͽ���ҳ��ŵ�����ҳ��ʱ
	 * 3.��1д��sysfs�е�vm/compact_memory
	 * ͬ��ģʽ�������Ƴټ�������ֵ��������ͬ��ģʽ�£������ú�compact_control����ͬ��ģʽʱ����pageblock��PB_migrate_skip���
	 */
	MIGRATE_SYNC,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
