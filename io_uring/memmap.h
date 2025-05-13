#ifndef IO_URING_MEMMAP_H
#define IO_URING_MEMMAP_H

#define IORING_MAP_OFF_PARAM_REGION		0x20000000ULL
#define IORING_MAP_OFF_ZCRX_REGION		0x30000000ULL

struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages);

#ifndef CONFIG_MMU
/**
 * return supported mmap capabilities for NOMMU environments
 */
unsigned int io_uring_nommu_mmap_capabilities(struct file *file);
#endif
/**
 * return an unmapped area suitable for mmap with io_uring
 */
unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags);
/**
 * handle mmap request for io_uring regions
 */
int io_uring_mmap(struct file *file, struct vm_area_struct *vma);

/**
 * release memory region and associated resources
 */
void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr);

/**
 * initialize and map a memory region based on user description
 */
int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
		     struct io_uring_region_desc *reg,
		     unsigned long mmap_offset);

/**
 * safely create and map a region, avoiding race conditions
 */
int io_create_region_mmap_safe(struct io_ring_ctx *ctx,
				struct io_mapped_region *mr,
				struct io_uring_region_desc *reg,
				unsigned long mmap_offset);

static inline void *io_region_get_ptr(struct io_mapped_region *mr)
{
	return mr->ptr;
}

static inline bool io_region_is_set(struct io_mapped_region *mr)
{
	return !!mr->nr_pages;
}

#endif
