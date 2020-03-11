// profiler.c 2015-07-03
#include <string.h>
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "types.h"
#include "profiler.h"
#include "global.h"
#include "sandbox.h"

#include "uafdetect/uafdetect.h"

u4 dlopen_addr = 0x0;
u4 dlsym_addr = 0x0;

/* 
 * Register hook functions for dlopen and dlsym in libdvm.so.
 *
 * dlopen is used to load a native lib into memory.
 * dlsym is used to find a native function (symbol) and then invoke it.
 *
 * When both functions have been hooked,  we can process the libs and functions 
 * when they are loaded and invoked respectively.
 */
bool hook_libdvm(){
	TRACE_ENTER;
	/* Get the offset of GOT table of libdvm.so */
	u4 got_start = find_got("/system/lib/libdvm.so");

	if(got_start == 0){
		PROFILER_LOGE("[x] [%s:%d]: can not find GOT in libdvm.so \n", FILE, LINE);
		return false;
	}

	/* Get address of dlopen in libdl.so */
	u4 dlopen_addr = find_func_addr("/system/lib/libdl.so", "dlopen");
	if(dlopen_addr == 0) {
		PROFILER_LOGE("[x] [%s:%d]: can not find dlopen in libdl.so \n", FILE, LINE);
		return false;
	}

	/* Get address of dlsym in libdl.so */
	u4 dlsym_addr = find_func_addr("/system/lib/libdl.so", "dlsym");
	if(dlsym_addr == 0) {
		PROFILER_LOGE("[x] [%s:%d]: can not find dlsym in libdl.so \n", FILE, LINE);
		return false;
	}

	/* Get base address of libdvm.so */
	u4 libdvm_base = find_lib_base_addr("/system/lib/libdvm.so");

	PROFILER_LOGI("[x] [%s:%d]: libdvm_base 0x%x got_start 0x%x dlopen 0x%x dlsym 0x%x \n", FILE, LINE, libdvm_base, got_start, dlopen_addr, dlsym_addr);
	/* Hook both previous functions in GOT table */
	int i = 0;
	/* Get the address of GOT table in libdvm.so */
	u4 *c_addr = (u4 *)(libdvm_base + (got_start & 0xfffffffc));
	u1 is_hook_dlopen = 0;
	u1 is_hook_dlsym = 0;

	/* TODO: get the actual size of GOT table (256 by default) */
	u4 got_size = 256;
	for(i = 0; i < got_size; i++){
		if(*c_addr == dlopen_addr) {
			/* GOT table is read only, so we need to make it rw using mprotect */
			mprotect((void *)((u4)c_addr & ~ARM_PAGE_MASK), ARM_PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC);
			*c_addr = (u4)wrapper_dlopen;
			mprotect((void *)((u4)c_addr & ~ARM_PAGE_MASK), ARM_PAGE_SIZE,
					PROT_READ | PROT_EXEC);
			PROFILER_LOGI("[*] [%s:%d]: change dlopen in GOT from [0x%x] to [0x%x] \n", 
					FILE, LINE, dlopen_addr, (u4)wrapper_dlopen);
			is_hook_dlopen = 1;
		}
		else if(*c_addr == dlsym_addr) {
			mprotect((void *)((u4)c_addr & ~ARM_PAGE_MASK), ARM_PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC);
			*c_addr = (u4)wrapper_dlsym;
			mprotect((void *)((u4)c_addr & ~ARM_PAGE_MASK), ARM_PAGE_SIZE,
					PROT_READ | PROT_EXEC);
			PROFILER_LOGI("[*] [%s:%d]: change dlsym in GOT from [0x%0x] to [0x%x] \n",
					FILE, LINE, dlsym_addr, (u4)wrapper_dlsym);
			is_hook_dlsym = 1;
		}
		if(is_hook_dlsym && is_hook_dlopen){
			break;
		}
		c_addr++;
	}
	if(i == got_size){
		PROFILER_LOGE("[*] [%s:%d]: register hook functions error (dlopen=%d dlsym=%d).\n", 
				FILE, LINE, is_hook_dlopen, is_hook_dlsym);
	}
	/* PROFILER_LOGI("[*] [%s:%d]: register hook functions error (dlopen=%d dlsym=%d).\n", 
		 FILE, LINE, is_hook_dlopen, is_hook_dlsym); */
	TRACE_EXIT;
	return true;
}

bool init_profiler_address_space() {
	return init_sandbox_address_space();
}

bool __profiler_linker_init(unsigned profiler_start) {
	return __sandbox_linker_init(profiler_start);
}

bool init_profiler() {
	if(init_profiler_address_space() == false) {
		PROFILER_LOGE("[x] [%s:%d]: can not init profiler address space \n", FILE, LINE);
		return false;
	}

	/* Register hook functions for libdvm */
	if(hook_libdvm() == false) {
		PROFILER_LOGE("[x] [%s:%d]: can not hook libdvm \n", FILE, LINE);
		return false;
	};

	/* init the linker */
	__profiler_linker_init(sbox.sandbox_start);

	/* init binary translation */
	fbt_init();

	/* init the trampoline */
	init_trampoline();
	return true;
}

/* This function is called for initialization during loading library */
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
	sbox.vm = vm;
	if(init_profiler()) {
		sandbox_mode = true;
		uafdetect_init();
	}
	return JNI_VERSION_1_6;
}

