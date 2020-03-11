#ifndef _DEBUG_DEBUG_H_
#define _DEBUG_DEBUG_H_

#include <unistd.h>
#include <android/log.h>

#include "utility.h"

#include "darm/darm.h"


//do NOT include the full path in the output.
#define FILE (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define LINE (__LINE__)
#define FUNCTION (__FUNCTION__)


#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "profiler"

#define TRACE_FUNC_FLOW
/* Added by Rewhy */
#ifdef	TRACE_FUNC_FLOW
#define LOG_FUNC_TAG "FUNC"
#define TRACE_ENTER __android_log_print(ANDROID_LOG_INFO, LOG_FUNC_TAG, "[%d] Enter [%-16s:%-4d]: %-32s\n", gettid(), FILE, __LINE__, __func__)
#define TRACE_LINE	__android_log_print(ANDROID_LOG_INFO, LOG_FUNC_TAG, "[%d] Line  [%-16s:%-4d]: %-32s\n", gettid(), FILE, __LINE__, __func__)
#define TRACE_EXIT	__android_log_print(ANDROID_LOG_INFO, LOG_FUNC_TAG, "[%d] Exit  [%-16s:%-4d]: %-32s\n", gettid(), FILE, __LINE__, __func__)
#else
#define TRACE_ENTER ;
#define TRACE_LINE	;
#define TRACE_EXIT	; 
#endif
/* End */

#define DEBUG_PROFILER

#ifdef DEBUG_PROFILER
#define PROFILER_LOGE(...)   __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG,__VA_ARGS__)
#define PROFILER_LOGI(...)   __android_log_print(ANDROID_LOG_INFO,  LOG_TAG,__VA_ARGS__)
#else
/* kill the warning. (and (hopefully) compiler will remove these functions totally) */
#define PROFILER_LOGE(...)  do { if (0) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG,__VA_ARGS__); } while (0)
#define PROFILER_LOGI(...)  do { if (0) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG,__VA_ARGS__); } while (0)
#endif

#define LOG_SANDBOX_TAG "profiler"
#define DEBUG_SANDBOX

#ifdef DEBUG_SANDBOX
#define SANDBOX_LOGE(...)   __android_log_print(ANDROID_LOG_ERROR,  LOG_SANDBOX_TAG,__VA_ARGS__)
#define SANDBOX_LOGI(...)   __android_log_print(ANDROID_LOG_INFO,  LOG_SANDBOX_TAG,__VA_ARGS__)
#else
/* kill the warning. (and (hopefully) compiler will remove these functions totally) */
#define SANDBOX_LOGE(...)  do { if (0) __android_log_print(ANDROID_LOG_ERROR,  LOG_SANDBOX_TAG,__VA_ARGS__); } while (0)
#define SANDBOX_LOGI(...)  do { if (0) __android_log_print(ANDROID_LOG_ERROR,  LOG_SANDBOX_TAG,__VA_ARGS__); } while (0)
#endif


/********************* BT_DEBUG_XXX ************************/


#ifdef DEBUG_BT
#define DEBUG_BT_INFO
#define DEBUG_BT_DEBUG
#define DEBUG_BT_ERR
//#define DEBUG_BT_DARM
#endif

extern char pformat[256];

#ifdef DEBUG_BT_DARM
#define BT_DARM(addr, insn) \
	do { \
		darm_to_str(pformat, insn);\
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d] INSN: 0x%-8x-> 0x%-8x %s ", (u4)gettid(), addr, insn, pformat); \
	} while(0)
#else
#define BT_DARM(addr, insn) do { } while(0)
#endif

#ifdef DEBUG_BT_ERR
#define BT_ERR(kill, fmt, x...) \
	do { \
		snprintf(pformat,sizeof(pformat), "[%d] [E][%-20s:%-4d] [%-32s] %s ",\
				(u4)gettid(), FILE, LINE, FUNCTION, fmt); \
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
		if (kill) \
		__asm__ volatile("mov pc, #0\n" );        \
	} while(0)
#else
//kill warning
#define BT_ERR(kill, fmt, x...) \
	do { \
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##x); \
		if (kill) \
		__asm__ volatile("mov pc, #0\n" );        \
	} while(0)
#endif


#ifdef DEBUG_BT_INFO
#define BT_INFO(fmt, x...) \
	do {\
		snprintf(pformat,sizeof(pformat), "[%d] [I][%-20s:%-4d] [%-32s] %s ",\
				gettid(), FILE, LINE, FUNCTION, fmt); \
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
	} while (0)
#else
#define BT_INFO(fmt, x...) do { if (0) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##x); }} while(0)
#endif


#ifdef DEBUG_BT_DEBUG
#define BT_DEBUG(fmt, x...) \
	do {\
		snprintf(pformat,sizeof(pformat), "[%d] [D][%-20s:%-4d] [%-32s] %s ",\
				gettid(), FILE, LINE, FUNCTION, fmt); \
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
	} while (0)
#else
#define BT_DEBUG(fmt, x...) do { if (0) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##x); }} while(0)
#endif


#ifdef DEBUG_BT_DEBUG
#define BT_DEBUG_CLEAN(fmt, x...) \
	do {\
		snprintf(pformat,sizeof(pformat), "[%d] %s ",\
				gettid(), fmt); \
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG, pformat, ##x); \
	} while (0)
#else
#define BT_DEBUG_CLEAN(fmt, x...) do { if (0) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##x); }} while(0)
#endif


/************************************DEBUG INSTRUCTION INFO ********************************************************/

#ifdef DIS_INSN_INFO
#define INSN_INFO(info, tag, fmt, x...) \
	do {\
		__android_log_print(info, tag, pformat, ##x); \
	} while (0)
#else
#define INSN_INFO(info, tag, fmt, x...) do { if (0) {__android_log_print(info, tag, fmt, ##x); }} while(0)
#endif


#endif
