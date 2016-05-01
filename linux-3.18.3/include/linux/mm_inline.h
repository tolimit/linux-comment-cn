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
/* 判断页是否是文件页，通过PageSwapBacked判断此页是否需要用到swap，需要则是匿名页 */
static inline int page_is_file_cache(struct page *page)
{
	return !PageSwapBacked(page);
}

/* 将页加入到lruvec中的lru类型的链表头部 */
static __always_inline void add_page_to_lru_list(struct page *page,
				struct lruvec *lruvec, enum lru_list lru)
{
	/* 获取页的数量，因为可能是透明大页的情况，会是多个页 */
	int nr_pages = hpage_nr_pages(page);
	/* 更新lruvec中lru类型的链表的页数量 */
	mem_cgroup_update_lru_size(lruvec, lru, nr_pages);
	/* 加入到对应LRU链表头部，这里不上锁，所以在调用此函数前需要上锁 */
	list_add(&page->lru, &lruvec->lists[lru]);
	/* 更新统计 */
	__mod_zone_page_state(lruvec_zone(lruvec), NR_LRU_BASE + lru, nr_pages);
}

/* 将此页从lru链表中移除 */
static __always_inline void del_page_from_lru_list(struct page *page,
				struct lruvec *lruvec, enum lru_list lru)
{
	int nr_pages = hpage_nr_pages(page);
	/* 更新统计，统计保存在lruvec对应的mem_cgroup_per_zone */
	mem_cgroup_update_lru_size(lruvec, lru, -nr_pages);
	/* 从lru中移除 */
	list_del(&page->lru);
	/* 更新统计，这里的是zone的统计 */
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
/* 根据页的类型，获取此页应该放置的lru链表的类型 */
static __always_inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru;

	/* 通过PG_unevictable标志判断此页是否被锁在内存中 */
	if (PageUnevictable(page))
		lru = LRU_UNEVICTABLE;
	else {
		/* 获取页的类型，通过PageSwapBacked判断此页是否依靠swap分区，如果依靠，则需要加入匿名页lru链表，否则加入文件页lru链表 */
		lru = page_lru_base_type(page);
		/* 判断此页是否是活动页，主要通过PG_active标志 */
		if (PageActive(page))
			lru += LRU_ACTIVE;
	}
	return lru;
}

#endif
