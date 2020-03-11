#ifndef __SANDBOX_UTILITY_H__
#define __SANDBOX_UTILITY_H__


#include <errno.h>
#include <dlfcn.h>
#include <string.h>

#include "types.h"
#include "arm.h"


u4 readLine(int fd, void *buffer, size_t n);
u4 find_got(char *file);
u4 find_func_addr(char * lib_name, char * func_name);
u4 find_lib_base_addr(char * lib_name);

static inline int constant_fls(int x)
{
        int r = 32;
        if (!x)
            return 0;

        if (!(x & 0xffff0000u)) {
            x <<= 16;
            r -= 16;
        }
        if (!(x & 0xff000000u)) {
            x <<= 8;
            r -= 8;
        }
        if (!(x & 0xf0000000u)) {
            x <<= 4;
            r -= 4;
        }
        if (!(x & 0xc0000000u)) {
            x <<= 2;
            r -= 2;
       }
        if (!(x & 0x80000000u)) {
            x <<= 1;
            r -= 1;
        }
        return r;
}

static inline int fls(int x)
{
        int ret;

        if (__builtin_constant_p(x))
               return constant_fls(x);
        __asm (
           //https://bugzilla.mozilla.org/show_bug.cgi?id=586224
#if defined(ANDROID) && defined(ARM_SANDBOX)
    // On Android gcc compiler, the clz instruction is not supported with a
    // target smaller than armv7, despite it being legal for armv5+.
        "   .arch armv7\n"
#endif
        "clz\t%0, %1"
        : "=r" (ret)
        : "r" (x)
        );
        ret = 32 - ret;
        return ret;
}

#define ffs(x) ({ unsigned long __t = (x); fls(__t & -__t); })
#define __ffs(x) (ffs(x) - 1)
#define ffz(x) __ffs( ~(x) )

#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif


/*************** patch memory *****************/

/* put value into memory with address target */
static void inline patch_memory(u4 target, u4 value) {
    *(u4 *)(target) = value;
}

void fill_memory_hlt(void *dst, u4 size);

#endif