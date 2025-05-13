// SPDX-License-Identifier: GPL-2.0

#include "alloc_cache.h"

/*
 * Function: void io_alloc_cache_free
 * Description: Frees the allocated entries in the given cache by calling the provided free function on each entry, and then frees the cache's memory.
 * Parameters:
 *   - cache: Pointer to the io_alloc_cache structure representing the cache to be freed.
 *   - free: A function pointer that specifies how to free each individual entry in the cache.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - Typically used when the cache is no longer needed and must be cleaned up by freeing all allocated memory.
 */

void io_alloc_cache_free(struct io_alloc_cache *cache, void (*free)(const void *))
{
	void *entry;

	if (!cache->entries)
		return;

	while ((entry = io_alloc_cache_get(cache)) != NULL)
		free(entry);

	kvfree(cache->entries); // Free the memory holding the cache entries
	cache->entries = NULL;  // Nullify the entries pointer to avoid dangling references
}

/*
 * Function: bool io_alloc_cache_init
 * Description: Initializes the io_alloc_cache by allocating memory for a specified number of entries and setting up cache parameters.
 * Parameters:
 *   - cache: Pointer to the io_alloc_cache structure that will be initialized.
 *   - max_nr: Maximum number of entries the cache will hold.
 *   - size: Size of each cache element (in bytes).
 *   - init_bytes: Number of bytes to initialize to zero in each allocated element.
 * Returns:
 *   - false if initialization is successful (cache memory was allocated).
 *   - true if memory allocation fails.
 * Example usage:
 *   - Used to initialize a cache before it can be used for object allocation.
 */

bool io_alloc_cache_init(struct io_alloc_cache *cache, unsigned max_nr, unsigned int size, unsigned int init_bytes)
{
	cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL); 
	if (!cache->entries)
		return true;  

	cache->nr_cached = 0;     
	cache->max_cached = max_nr;  
	cache->elem_size = size;     
	cache->init_clear = init_bytes;
	return false; 
}

/*
 * Function: void *io_cache_alloc_new
 * Description: Allocates a new object of the specified size from the cache, optionally initializing it to zero.
 * Parameters:
 *   - cache: Pointer to the io_alloc_cache structure from which to allocate the object.
 *   - gfp: Allocation flags (GFP_KERNEL or other memory allocation flags).
 * Returns:
 *   - Pointer to the newly allocated object, or NULL if allocation fails.
 * Example usage:
 *   - Typically used to allocate a new object from the cache with the specified size. If the `init_clear` flag is set, the object will be zero-initialized.
 */

void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = kmalloc(cache->elem_size, gfp);
	if (obj && cache->init_clear)
		memset(obj, 0, cache->init_clear); 
	return obj; 
}


