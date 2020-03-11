#include <string.h>
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "utility.h"
#include "types.h"
#include "sandbox.h"
#include "global.h"


/* TODO: Multithread support!!! */

/**************global variable*********************/
sandbox sbox;

/* if sandbox can not be initiated, we will run the app without sandboxing it*/
bool sandbox_mode = false;


/*************internal functions ***************************/

#if 0
/*
 * hook dlopen and dlsym in libdvm.
 *
 * Libdvm uses dlopen to load a native lib into memory.
 * Libdvm uses dlsym to find a native function and then call this native func.
 *
 * After hooking these functions, we can get called when libdvm loads native
 * libs and calls native functions.
 *
 */
bool hook_libdvm() {

	/* get the offset of got table in libdvm */
	u4 got_start = find_got("/system/lib/libdvm.so");

	if (got_start == 0) {
		SANDBOX_LOGE("[x] [%s:%d]: can not find got in libdvm \n",FILE,LINE);
		return false;
	}

	/* get the dlopen address in libdl */
	u4 dlopen_addr = find_func_addr("/system/lib/libdl.so", "dlopen");
	if (dlopen_addr == 0) {
		SANDBOX_LOGE("[x] [%s:%d]: can not find dlopen in libdl \n",FILE,LINE);
		return false;
	}

	/* get the dlsym address in libdl */
	u4 dlsym_addr = find_func_addr("/system/lib/libdl.so", "dlsym");
	if (dlsym_addr == 0) {
		SANDBOX_LOGE("[x] [%s:%d]: can not find dlsym in libdl \n",FILE,LINE);
		return false;
	}

	/* find the base address of libdvm */
	u4 libdvm_base = find_lib_base_addr("/system/lib/libdvm.so");

	SANDBOX_LOGI("[*] [%s:%d]: libdvm_base 0x%x got_start 0x%x dlopen 0x%x \n", FILE,
			LINE, libdvm_base, got_start, dlopen_addr);

	/* hook the functions in got table */
	int i = 0;
	/* ensure the address is 4 bytes aligned. */
	u4 * c_addr = (u4 *)(libdvm_base + (got_start & 0xfffffffc));

	u4 hook_cnt = 0;

	/* 256 should be enough!
	 * TODO: can we find the actual size of got table?
	 */
	for (i = 0; i < 256; i ++) {
		if (*c_addr == dlopen_addr) {
			/* I do not know why the GOT table is read only. It's supposed
			 * to be rw. Anyway, I can use mprotect to make it rw.
			 *
			 * TODO: can we change it to previous flags after overwriting
			 * the GOT table?
			 */

			mprotect((void *)((u4)c_addr & ~ARM_PAGE_MASK), ARM_PAGE_SIZE ,
					PROT_READ | PROT_WRITE | PROT_EXEC);
			*c_addr = (u4)wrapper_dlopen;
			SANDBOX_LOGI("[*] [%s:%d]: change dlopen in got to [0x%x] \n", FILE, LINE,
					(u4)wrapper_dlopen);
			hook_cnt ++;
		} else if (*c_addr == dlsym_addr) {
			mprotect((void *)((u4)c_addr & ~ARM_PAGE_MASK), ARM_PAGE_SIZE ,
					PROT_READ | PROT_WRITE | PROT_EXEC);
			*c_addr = (u4)wrapper_dlsym;
			SANDBOX_LOGI("[*] [%s:%d]: change dlsym in got to [0x%x] \n", FILE, LINE,
					(u4)wrapper_dlsym);
			hook_cnt ++;
		}

		if (hook_cnt == 2)
			break;

		c_addr ++;
	}

	if (i == 256)
		return false;

	return true;
}

#endif

bool init_sandbox_address_space() {
	TRACE_ENTER;
	u4 sandbox_start, sandbox_end;

	/* mmap a large space for untrusted native code. */
	sandbox_start = (u4)mmap(NULL, SANDBOX_MEM_SIZE + SANDBOX_START_ALIGNED,
			PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (MAP_FAILED == (void *)sandbox_start) {
		SANDBOX_LOGE("[x] [%s:%d]: can not init the sandbox. error: %s \n", FILE, LINE,
				strerror(errno));
		return false;
	}

	sandbox_end = sandbox_start + SANDBOX_MEM_SIZE + SANDBOX_START_ALIGNED;

	SANDBOX_LOGI("[*] [%s:%d]: got a large space : 0x%x-0x%x \n", FILE, LINE,
			sandbox_start,
			sandbox_end);

	/* make sure sandbox_start is 16M aligned */
	sbox.sandbox_start = sandbox_start & ~(SANDBOX_START_ALIGNED - 1);
	sbox.sandbox_start += SANDBOX_START_ALIGNED;

	/*make sure sandbox end is 16M aligned*/
	sbox.sandbox_end = (sandbox_end & (~(SANDBOX_START_ALIGNED - 1))) - 1;

	/*munmap other space*/
	if (sbox.sandbox_start != sandbox_start) {
		munmap((void *)(sandbox_start), sbox.sandbox_start - sandbox_start);
		SANDBOX_LOGI("[*] [%s:%d]: munmap address space: [0x%x:0x%x] \n", FILE, LINE,
				sandbox_start,
				sbox.sandbox_start - sandbox_start);
	}


	if (sbox.sandbox_end != sandbox_end) {
		munmap((void *)(sbox.sandbox_end + 1), sandbox_end - sbox.sandbox_end -1);
		SANDBOX_LOGI("[*] [%s:%d]: munmap address space: [0x%x:0x%x] \n", FILE, LINE,
				sbox.sandbox_end + 1,
				sandbox_end - sbox.sandbox_end -1);
	}

	SANDBOX_LOGI("[*] [%s:%d]: sandbox address space: 0x%x-0x%x \n", FILE, LINE,
			sbox.sandbox_start,
			sbox.sandbox_end);

	TRACE_EXIT;
	return true;
}
#if 0
/*
 * Initiate the sandbox.
 * (1) allocate a large memory space (1GB) for sandbox.
 * (2) hook dlopen/dlsym in libdvm
 * (3) ??
 */
bool init_sandbox() {

	if (init_sandbox_address_space() == false) {
		SANDBOX_LOGE("[x] [%s:%d]: can not init sandbox address space \n", FILE, LINE);
		return false;
	}

	/* hook libdvm */
	if (hook_libdvm() == false) {
		SANDBOX_LOGE("[x] [%s:%d]: can not hook libdvm \n", FILE, LINE);
		return false;
	}

	//init the linker
	__sandbox_linker_init(sbox.sandbox_start);

	//init binary translation
	fbt_init();

	//init the trampoline
	init_trampoline();

	return true;
}

/************ functions**********************************/


JNIEXPORT jboolean JNICALL
Java_org_yajin_nativecontainer_MainActivity_sandboxInit
(JNIEnv* env, jobject thiz) {
	return JNI_TRUE;
}


/* This function will be called when loading the native libs */
jint JNI_OnLoad(JavaVM* vm, void* reserved) {

	/*  TODO: if init_sandbox() returns false, then
	 *      (1) release the sandbox memory space
	 *      (2) remove the hooks in libdvm
	 */
	sbox.vm = vm;
	if (init_sandbox()) {
		sandbox_mode = true;
	}

	return JNI_VERSION_1_6;
}
#endif
