#ifndef _LINKER_DEBUG_H_
#define _LINKER_DEBUG_H_

#include <android/log.h>

#include "utility.h"


#ifdef ARM_SANDBOX

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "linker"

#define DEBUG_LINKER

/* Added by Rewhy */
#ifndef TRACE_ENTER
#define TRACE_ENTER __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Enter %s:%s\n", FILE, __func__)
#endif

#ifndef TRACE_EXIT
#define TRACE_EXIT __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Exit %s:%s\n", FILE, __func__)
#endif
/* End */


#ifdef DEBUG_LINKER
#define DEBUG_DL_ERR
#define DEBUG_DEBUG
#define DEBUG_TRACE
#endif

extern char pformat[256];

#ifndef FILE
#define FILE (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef LINE
#define LINE (__LINE__)
#endif

#ifndef FUNCTION
#define FUNCTION (__FUNCTION__)
#endif

#ifdef DEBUG_DL_ERR
    #define DL_ERR(fmt, x...) \
         do { \
            snprintf(pformat,sizeof(pformat), "[*][%s:%4d:(%s)]\t %s ",\
                                        FILE, LINE, FUNCTION, fmt); \
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
         } while(0)
#else
    #define DL_ERR(fmt, x...) do { if (0) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x);} } while(0)
#endif

#ifdef DEBUG_DEBUG
    #define DEBUG(fmt, x...) \
         do {\
            snprintf(pformat,sizeof(pformat), "[*][%s:%4d:(%s)]\t %s ",\
                                        FILE, LINE, FUNCTION, fmt); \
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
         } while (0)
#else
    #define DEBUG(fmt, x...) do { if (0) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x);} } while(0)
#endif


#ifdef DEBUG_TRACE
#define TRACE(fmt, x...) \
    do {\
        snprintf(pformat,sizeof(pformat), "[*][%s:%4d:(%s)]\t %s ",\
                                    FILE, LINE, FUNCTION, fmt); \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
    } while (0)
#else
    #define TRACE(fmt, x...) do { if (0) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x);} } while(0)
#endif

#define PRINT(x...) do {} while (0)
#define INFO(x...)  do {} while (0)
#define COUNT_RELOC(type)   do {} while (0)
#define WARN(fmt,args...)  do {} while (0)
#define ERROR(fmt,args...)   do {} while (0)

#define MARK(x...) do {} while (0)

#define DEBUG_DUMP_PHDR(phdr, name, pid) do { \
        DEBUG("%5d %s (phdr = 0x%08x)", (pid), (name), (unsigned)(phdr));   \
        DEBUG("\t\tphdr->offset   = 0x%08x", (unsigned)((phdr)->p_offset)); \
        DEBUG("\t\tphdr->p_vaddr  = 0x%08x", (unsigned)((phdr)->p_vaddr));  \
        DEBUG("\t\tphdr->p_paddr  = 0x%08x", (unsigned)((phdr)->p_paddr));  \
        DEBUG("\t\tphdr->p_filesz = 0x%08x", (unsigned)((phdr)->p_filesz)); \
        DEBUG("\t\tphdr->p_memsz  = 0x%08x", (unsigned)((phdr)->p_memsz));  \
        DEBUG("\t\tphdr->p_flags  = 0x%08x", (unsigned)((phdr)->p_flags));  \
        DEBUG("\t\tphdr->p_align  = 0x%08x", (unsigned)((phdr)->p_align));  \
    } while (0)


#ifndef DEBUG_TRACE_TYPE
#define DEBUG_TRACE_TYPE
#endif

#ifdef DEBUG_TRACE_TYPE
  #define TRACE_TYPE(t, x...) do { __android_log_print(ANDROID_LOG_INFO, t, ##x); } while(0)
#else
	#define TRACE_TYPE(t, x...) do {} while (0)
#endif

//should be removed in the future
#define RELOC_ABSOLUTE        0
#define RELOC_RELATIVE        1
#define RELOC_COPY            2
#define RELOC_SYMBOL          3
#define NUM_RELOC_STATS       4

#endif

#endif
