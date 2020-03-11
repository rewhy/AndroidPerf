#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utility.h"
#include "types.h"
#include "profiler.h"
#include "global.h"
#include "arm.h"
#include "trampoline/trampoline.h"


void *linker_dlopen(const char *filename, int flag);
void *linker_dlsym(void *handle, const char *symbol);
/* These are the wrapper functions for libdvm.*/
void *wrapper_dlopen(const char *file, int mode) {
	PROFILER_LOGE("[x] [%s:%d]: into wrapper_dlopen \n", FILE, LINE);
	void *res = linker_dlopen(file, mode);
	//void *res = dlopen(file, mode);
	PROFILER_LOGI("[x] [%s:%d]: exit wrapper_dlopen (res = 0x%x) \n", FILE, LINE,  (u4) res);
	return res;
	//return dlopen(file, mode);
}

/*
 * This function will be executed only once even multi-threads may
 * call the same JNI function several times.
 *
 *
 *  for example, suppose both two Java threads (t1 and t2)
 *   call a native function hello().
 *
 *  t1->hello(),  dalvik will call wrapper_dlsym and get sandbox_jni_gate_keeper()
 *                as the address of hello().
 *
 *  t2->hello(), dalvik thinks that it has already got the address of hello()
 *               and will jump to sandbox_jni_gate_keeper directly (since we
 *               return address of sandbox_jni_gate_keeper to dlsym(hello1) )
 *    problem: in sandbox_jni_gate_keeper, we may not know which original
 *             native function that dalvik wanted to call.
 *
 *  Solution:   wrapper_dlsym returns different address to different JNI
 *              functions!!!
 *
 *
 */

u4 native_funcs[GATE_KEEPER_STAGE1_ENTRY_NUM];
u4 func_index = 0;

u4 get_native_func(int index){
	return native_funcs[index];
}

static inline bool put_native_func(u4 addr) {
	TRACE_ENTER;
	if (func_index >= GATE_KEEPER_STAGE1_ENTRY_NUM) {
		PROFILER_LOGI("[x] [%d] [%s:%d]: too many native funcs: %d. Max allowed: %d \n",
				gettid(), FILE, LINE, func_index + 1,
				GATE_KEEPER_STAGE1_ENTRY_NUM);
		return false;
	}

	native_funcs[func_index] = addr;
	PROFILER_LOGI("[x] [%d] [%s:%d]: put native function 0x%x to native_funcs: %d \n", 
			gettid(), FILE, LINE, addr, func_index);
	func_index ++;
	TRACE_EXIT;
	return true;
}
void *wrapper_dlsym(void *handle, const char *name) {
	TRACE_ENTER;
	//PROFILER_LOGI("[x] [%s:%d]: dlsym = 0x%x\n", FILE, LINE, (u4)dlsym);
	void *ret = linker_dlsym(handle, name);
	//return ret;
	pid_t tid = gettid();
	PROFILER_LOGI("[x] [%d] [%s:%d] open symbole %s at 0x%x (handle = 0x%x)\n", tid, FILE, LINE, name, (u4)ret, (u4)handle);
	/*
	 * dlsym can find the symbol in sandbox since linker_dlopen has returned
	 * a valid hander back.
	 *
	 */
	PROFILER_LOGI("[x] [%d] [%s:%d]: into wrapper_dlsym %s 0x%x\n", tid, FILE, LINE,
			name, (u4)ret);
	PROFILER_LOGI("[x] [%d] [%s:%d]: untrusted lib:[0x%8x-0x%8x]\n", tid, FILE, LINE,
			sbox.sandbox_start + UNTRUSTED_LIB_START,
			sbox.sandbox_start + UNTRUSTED_LIB_END);

	if (ret != NULL) {
		if (((u4)ret >= (sbox.sandbox_start + UNTRUSTED_LIB_START) )
				&& ((u4)ret <= (sbox.sandbox_start + UNTRUSTED_LIB_END) ))
		{

			/* put native function into native_funcs */
			if (put_native_func((u4)ret) == false) {
				return NULL;
			}

			/* for different native functions, we return different addresses */
			u4 ret_addr = (u4)sbox.gate_keeper_start + (func_index - 1)
				* GATE_KEEPER_STAGE1_ENTRY_SIZE;

			PROFILER_LOGI("[x] [%d] [%s:%d]: return gate keeper address 0x%8x \n",
					tid, FILE, LINE, ret_addr);

#ifdef BDB_DEBUGGER
			bdb_debugger_init();
#endif
			//return gate keep address instead of real address
			TRACE_EXIT;
			return (void *)ret_addr;
		} else {
			PROFILER_LOGI("[x] [%d] [%s:%d]: not need gate keeper address \n",
					tid, FILE, LINE);
			return ret;
		}
	}
	TRACE_EXIT;
	return NULL;
}
