// profiler.h

#ifndef __PROFILE_H
#define __PROFILE_H

#include <jni.h>
#include "types.h"
#include "bt/bt.h"

typedef void *(*type_dlopen)(const char *file, int mode);
typedef void *(*type_dlsym)(void * handle, const char * name);

#define START_TRANSLATOR

/* untrusted code: 448M - 576M: 128M why? */
#define UNTRUSTED_LIB_START			(0x1c000000)
#define UNTRUSTED_LIB_SIZE			(0x8000000)
#define UNTRUSTED_LIB_END				(UNTRUSTED_LIB_START + UNTRUSTED_LIB_SIZE - 1)

#endif // __PROFILE_H
