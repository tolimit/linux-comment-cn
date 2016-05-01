/*
 * include/linux/pagevec.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagevec is a multipage container which is used for that.
 */

#ifndef _LINUX_PAGEVEC_H
#define _LINUX_PAGEVEC_H

/* 14 pointers + two long's align the pagevec structure to a power of two */
#define PAGEVEC_SIZE	14

struct page;
struct address_space;

/* LRU缓存 
 * PAGEVEC_SIZE默认为14
 */
struct pagevec {
	/* 当前数量 */
	unsigned long nr;
	unsigned long cold;
	/* 指针数组，每一项都可以指向一个页描述符，默认大小是14 */
	struct page *pages[PAGEVEC_SIZE];
};

void __pagevec_release(struct pagevec *pvec);
void __pagevec_lru_add(struct pagevec *pvec);
unsigned pagevec_lookup_entries(struct pagevec *pvec,
				struct address_space *mapping,
				pgoff_t start, unsigned nr_entries,
				pgoff_t *indices);
void pagevec_remove_exceptionals(struct pagevec *pvec);
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages);
unsigned pagevec_lookup_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, int tag,
		unsigned nr_pages);

static inline void pagevec_init(struct pagevec *pvec, int cold)
{
	pvec->nr = 0;
	pvec->cold = cold;
}

static inline void pagevec_reinit(struct pagevec *pvec)
{
	pvec->nr = 0;
}

static inline unsigned pagevec_count(struct pagevec *pvec)
{
	return pvec->nr;
}

/* 获取lru缓存pvec剩余的空间数量 */
static inline unsigned pagevec_space(struct pagevec *pvec)
{
	return PAGEVEC_SIZE - pvec->nr;
}

/*
 * Add a page to a pagevec.  Returns the number of slots still available.
 */
/* 将page加入到lru缓存pvec中 */
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
	/* lru缓存pvec的pages[]中的pvec->nr项指针指向此页 */
	pvec->pages[pvec->nr++] = page;
	/* 返回此lru缓存剩余的空间 */
	return pagevec_space(pvec);
}

static inline void pagevec_release(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_release(pvec);
}

#endif /* _LINUX_PAGEVEC_H */
