#include <sys/types.h>

extern void* hook_malloc(size_t size);
extern void* hook_calloc(size_t num, size_t size);
extern void* hook_realloc(void *ptr, size_t size);
extern void  hook_free(void *ptr);

// void* malloc(size_t size);
void* hook_malloc_arm(size_t size) {
	return hook_malloc(size);
}
//
// void* calloc(size_t num, size_t size);
void* hook_calloc_arm(size_t num, size_t size) {
	return hook_calloc(num, size);
}
//
// void* realloc(void *ptr, size_t size);
void* hook_realloc_arm(void *ptr, size_t size) {
	return hook_realloc(ptr, size);
}
//
// void free(void *ptr);
void hook_free_arm(void *ptr) {
	hook_free(ptr);
}
