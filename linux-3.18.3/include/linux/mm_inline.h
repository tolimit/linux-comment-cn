#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

#include <linux/huge_mm.h>
#include <linux/swap.h>

/**
 * page_is_file_cache - should the page be on a file LRU or anon LRU?
 * @page: the page to test
 *
 * Returns 1 if @page is page cache page backed by a regular filesystem,
 * or 0 if @page is anonymous, tmpfs or otherwise ram or swap backed.
 * Used by functions that manipulate the LRU lists, to sort a page
 * onto the right LRU list.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the page is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 */
/* �ж�ҳ�Ƿ����ļ�ҳ��ͨ��PageSwapBacked�жϴ�ҳ�Ƿ���Ҫ�õ�swap����Ҫ��������ҳ */
static inline int page_is_file_cache(struct page *page)
{
	return !PageSwapBacked(page);
}

/* ��ҳ���뵽lruvec�е�lru���͵�����ͷ�� */
static __always_inline void add_page_to_lru_list(struct page *page,
				struct lruvec *lruvec, enum lru_list lru)
{
	/* ��ȡҳ����������Ϊ������͸����ҳ����������Ƕ��ҳ */
	int nr_pages = hpage_nr_pages(page);
	/* ����lruvec��lru���͵������ҳ���� */
	mem_cgroup_update_lru_size(lruvec, lru, nr_pages);
	/* ���뵽��ӦLRU����ͷ�������ﲻ�����������ڵ��ô˺���ǰ��Ҫ���� */
	list_add(&page->lru, &lruvec->lists[lru]);
	/* ����ͳ�� */
	__mod_zone_page_state(lruvec_zone(lruvec), NR_LRU_BASE + lru, nr_pages);
}

/* ����ҳ��lru�������Ƴ� */
static __always_inline void del_page_from_lru_list(struct page *page,
				struct lruvec *lruvec, enum lru_list lru)
{
	int nr_pages = hpage_nr_pages(page);
	/* ����ͳ�ƣ�ͳ�Ʊ�����lruvec��Ӧ��mem_cgroup_per_zone */
	mem_cgroup_update_lru_size(lruvec, lru, -nr_pages);
	/* ��lru���Ƴ� */
	list_del(&page->lru);
	/* ����ͳ�ƣ��������zone��ͳ�� */
	__mod_zone_page_state(lruvec_zone(lruvec), NR_LRU_BASE + lru, -nr_pages);
}

/**
 * page_lru_base_type - which LRU list type should a page be on?
 * @page: the page to test
 *
 * Used for LRU list index arithmetic.
 *
 * Returns the base LRU type - file or anon - @page should be on.
 */
static inline enum lru_list page_lru_base_type(struct page *page)
{
	if (page_is_file_cache(page))
		return LRU_INACTIVE_FILE;
	return LRU_INACTIVE_ANON;
}

/**
 * page_off_lru - which LRU list was page on? clearing its lru flags.
 * @page: the page to test
 *
 * Returns the LRU list a page was on, as an index into the array of LRU
 * lists; and clears its Unevictable or Active flags, ready for freeing.
 */
static __always_inline enum lru_list page_off_lru(struct page *page)
{
	enum lru_list lru;

	if (PageUnevictable(page)) {
		__ClearPageUnevictable(page);
		lru = LRU_UNEVICTABLE;
	} else {
		lru = page_lru_base_type(page);
		if (PageActive(page)) {
			__ClearPageActive(page);
			lru += LRU_ACTIVE;
		}
	}
	return lru;
}

/**
 * page_lru - which LRU list should a page be on?
 * @page: the page to test
 *
 * Returns the LRU list a page should be on, as an index
 * into the array of LRU lists.
 */
/* ����ҳ�����ͣ���ȡ��ҳӦ�÷��õ�lru��������� */
static __always_inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru;

	/* ͨ��PG_unevictable��־�жϴ�ҳ�Ƿ������ڴ��� */
	if (PageUnevictable(page))
		lru = LRU_UNEVICTABLE;
	else {
		/* ��ȡҳ�����ͣ�ͨ��PageSwapBacked�жϴ�ҳ�Ƿ�����swap�������������������Ҫ��������ҳlru������������ļ�ҳlru���� */
		lru = page_lru_base_type(page);
		/* �жϴ�ҳ�Ƿ��ǻҳ����Ҫͨ��PG_active��־ */
		if (PageActive(page))
			lru += LRU_ACTIVE;
	}
	return lru;
}

#endif
