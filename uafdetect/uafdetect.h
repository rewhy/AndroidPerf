#ifndef __UAF_DETECT_H
#define __UAF_DETECT_H

#include <unistd.h>
#include <android/log.h>

#include "debug/debug.h"
#include "linker/linker.h"

//	__android_log_print(ANDROID_LOG_INFO, UAF_LOG_TAG, __VA_ARGS__)

#define UAF_LOG_TAG		"UAF"
#define DEBUG_UAF_CHECK

#ifdef DEBUG_UAF_CHECK
	#define UAF_LOGI(fmt, x...) \
	do {\
			snprintf(pformat,sizeof(pformat), "[%d] [I][%-20s:%-4d] [%-32s] %s ",\
																		gettid(), FILE, LINE, FUNCTION, fmt); \
			__android_log_print(ANDROID_LOG_INFO, UAF_LOG_TAG, pformat, ##x); \
		} while (0)
#else
	#define UAF_LOGI(...)	;
#endif

//__android_log_print(ANDROID_LOG_ERROR, UAF_LOG_TAG, __VA_ARGS__)
#ifdef DEBUG_UAF_CHECK
	#define UAF_LOGE(fmt, x...) \
	do {\
			snprintf(pformat,sizeof(pformat), "[%d] [I][%-20s:%-4d] [%-32s] %s ",\
																		gettid(), FILE, LINE, FUNCTION, fmt); \
			__android_log_print(ANDROID_LOG_INFO, UAF_LOG_TAG, pformat, ##x); \
		} while (0)
#else
	#define UAF_LOGE(...)	;
#endif

#define BLOCK_FLAG_VALIDATE						0x01
#define BLOCK_FLAG_INVALIDATE					0x00

#define	UAF_CHECK_ADDR_FREE						0x01

#define	UAF_CHECK_ADDR_ARM						0x02
#define	UAF_CHECK_ADDR_VFP_ARM				0x04

#define	UAF_CHECK_ADDR_THUMB					0x08
#define	UAF_CHECK_ADDR_THUMB2					0x10
#define	UAF_CHECK_ADDR_VFP_THUMB			0x20


struct hookfuncpair{
	u4	org_addr;
	u4	hook_addr;
	//struct hookfuncpair	*next;
};
struct memblock {
	u4	base; // beginning address of the alloced memory block
	u4	size; // size of the alloced memory block
	u1	flat;	// validate or invalidate
	struct memblock *left;
	struct memblock *right;
};

// void* malloc(size_t size);
void* hook_malloc(size_t size);
void* hook_malloc_sys(size_t size);
void* hook_malloc_arm(size_t size);
//
// void* calloc(size_t num, size_t size);
void* hook_calloc(size_t num, size_t size);
void* hook_calloc_sys(size_t num, size_t size);
void* hook_calloc_arm(size_t num, size_t size);
//
// void* realloc(void *ptr, size_t size);
void* hook_realloc(void *ptr, size_t size);
void* hook_realloc_sys(void *ptr, size_t size);
void* hook_realloc_arm(void *ptr, size_t size);
//
// void free(void *ptr);
void hook_free(void *ptr);
void hook_free_sys(void *ptr);
void hook_free_arm(void *ptr);

u4 addr_check(u4 addr, u4 type);

int uafdetect_init();

//u4 get_hook_addr(const char *name);

u4 is_hook_needed(u4 addr);

#endif // __UAF_DETECT_H
