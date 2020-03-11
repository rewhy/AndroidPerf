#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
//#include <ucontext.h>
#include "ucontext.h"

#include "utility.h"
#include "types.h"
#include "sandbox.h"
#include "global.h"
#include "arm.h"
#include "trampoline.h"

bool init_ret_trampoline() {
	TRACE_ENTER;
	/*************** ret trampoline *****************/
	u4 * destination = (void *)(sbox.sandbox_start + RET_TRAMPOLINE_START);
	u4 * src = (void *)&sandbox_ret_trampoline;
	u4 ret_trampoline_arm_len = (u4)&sandbox_ret_trampoline_end	- (u4)&sandbox_ret_trampoline;
	u4 ret_trampoline_arm_cstart = (u4)&sandbox_ret_trampoline_constant_unlock - (u4)&sandbox_ret_trampoline;

#ifdef DEBUG_BT_RUNTIME
	u4 ret_trampoline_arm_dstart = (u4)&sandbox_ret_trampoline_constant_debug	- (u4)&sandbox_ret_trampoline;
#endif

	SANDBOX_LOGI("[x] [%s:%d]: copy ret trampoline to 0x%8x from 0x%8x, size 0x%x \n",
			FILE,LINE, (u4)destination, (u4)src, ret_trampoline_arm_len);

	mprotect(destination, ARM_PAGE_SIZE, PROT_READ | PROT_WRITE);
	//put halt into destination
	fill_memory_hlt(destination, ARM_PAGE_SIZE);

	memcpy(destination, src, ret_trampoline_arm_len);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(unlock_thread()) \n", 
			FILE, LINE, (u4)(destination) + ret_trampoline_arm_cstart, (u4)unlock_thread);

	// patch it
	patch_memory(((u4)destination) + ret_trampoline_arm_cstart,	(u4)unlock_thread);

#ifdef DEBUG_BT_RUNTIME
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)(destination) + ret_trampoline_arm_dstart,
			(u4)bt_debug_print_address);
	// patch it
	patch_memory(((u4)destination) + ret_trampoline_arm_dstart,
			(u4)bt_debug_print_address);
#endif

	mprotect(destination, ARM_PAGE_SIZE, PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}

/*
 *
 * gate_keeper is the entry from trusted world to untrusted world.
 *
 *  For each native functions, we return different address to dalvik vm.
 *  Then when calling native functions, we can know that which original native
 *   functions dalvik vm wanted to call. (see wrapper.c)
 *
 *    memory layout:
 *
 *       offset 0 - 8K: first stage gate keeper.
 *
 *                     entry 0:   (gate keeper for first native function)
 *                       push {lr}
 *                       push {r4, r5, r6, r7, r8, r9, r10, fp, lr}
 *                       mov r4, #0
 *                       b stage2
 *                    entry 1:    (gate keeper for second native function)
 *                       push {lr}
 *                       push {r4, r5, r6, r7, r8, r9, r10, fp, lr}
 *                       mov r4, #1
 *                       b stage2
 *                    entry 2:
 *                       xxx
 *                       xxx
 *
 *
 *       offset 8k - 12k:  second stage of gate keeper (function sandbox_jni_gate_keeper())
 *
 *
 */

bool init_gate_keeper() {
	TRACE_ENTER;
	//alloc memory page for gate keeper
	u4 g_size = GATE_KEEPER_STAGE1_SIZE + GATE_KEEPER_STAGE2_SIZE;
	sbox.gate_keeper_start = memalign(ARM_PAGE_SIZE, g_size);

	if (sbox.gate_keeper_start == NULL) {
		SANDBOX_LOGE("[x] [%s:%d]: can not alloc memory page for gate keeper",
				FILE, LINE);
		return false;
	}

	SANDBOX_LOGI("[x] [%s:%d]: allocated gate keeper address 0x%x",
			FILE, LINE, (u4)sbox.gate_keeper_start);

	//fill_memory_hlt(gate_keeper_start, GATE_KEEPER_STAGE1_SIZE +
	//                                            GATE_KEEPER_STAGE2_SIZE);

	/*copy stage1 gate keeper */
	int i = 0;

	u4 stage1_entry[4] = {GATE_KEEPER_STAGE1_E1, GATE_KEEPER_STAGE1_E2,
		GATE_KEEPER_STAGE1_E3, GATE_KEEPER_STAGE1_E4};

	for (i = 0; i < GATE_KEEPER_STAGE1_ENTRY_NUM; i++) {
		u4 entry_offset = i * GATE_KEEPER_STAGE1_ENTRY_SIZE;
		memcpy((void *)((u4)sbox.gate_keeper_start + entry_offset),
				stage1_entry, GATE_KEEPER_STAGE1_ENTRY_SIZE);


		u4 imm = i;
		*(u4*)((u4)sbox.gate_keeper_start + entry_offset + 8) =
			GATE_KEEPER_STAGE1_E3 | imm;

		/* patch offset
		 *
		 *  pc is 8 bytes advanced. entry_offset + 12: offset of GATE_KEEPER_STAGE1_E4
		 *   offset is 2 bits aligned
		 */
		u4 p_offset = GATE_KEEPER_STAGE1_SIZE - (entry_offset + 12 + 8);
		*(u4*)((u4)sbox.gate_keeper_start + entry_offset + 12) =
			GATE_KEEPER_STAGE1_E4 | (p_offset>>2);
	}

	/* stage2 gate keeper */ /* What's the usage of stage2? */
	u4 stage2_start = (u4)sbox.gate_keeper_start + GATE_KEEPER_STAGE1_SIZE;
	u4 stage2_size = (u4)&sandbox_jni_gate_keeper_end - (u4)&sandbox_jni_gate_keeper;
	memcpy((void *)stage2_start, (void *)&sandbox_jni_gate_keeper, stage2_size);


	u4 offset = (u4)&sandbox_jni_gate_keeper_arm_constant_translate
		- (u4)&sandbox_jni_gate_keeper;
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
			FILE, LINE,
			(u4)stage2_start + offset,
			(u4)fbt_translate_noexecute_bridge);
	patch_memory((u4)stage2_start + offset, (u4)fbt_translate_noexecute_bridge);

	offset = (u4)&sandbox_jni_gate_keeper_arm_constant_lock
		- (u4)&sandbox_jni_gate_keeper;
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(lock_thread)",
			FILE, LINE,
			(u4)stage2_start + offset,
			(u4)lock_thread);
	patch_memory((u4)stage2_start + offset, (u4)lock_thread);

#ifdef DEBUG_BT_RUNTIME	
	offset = (u4)&sandbox_jni_gate_keeper_debug_constant 
		- (u4)&sandbox_jni_gate_keeper;
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address)",
			FILE, LINE,
			(u4)stage2_start + offset,
			(u4)bt_debug_print_address);
	patch_memory((u4)stage2_start + offset, (u4)bt_debug_print_address);
#endif

	cacheflush((u4)sbox.gate_keeper_start, g_size, 0);

	//remove w from this page (rx)
	mprotect(sbox.gate_keeper_start, g_size, PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}

bool init_constructor_gate_keeper() {
	//init the constructor gate_keeper

	//add w to this page (also need rx
	//because init_gate_keeper may be in the same page with gate keeper)
	// (we need to add w to 2 pages since &sandbox_constructor_gate_keeper_arm_constant_lock
	// maybe at another page)
	/*
	 *
	 *                __ sandbox_constructor_gate_keeper
	 *            xxxx
	 *            xxxx_ another page start
	 *            xxxx  _ sandbox_constructor_gate_keeper_arm_constant_lock
	 *
	 *
	 */
	TRACE_ENTER;
	mprotect((void *)((u4)&sandbox_constructor_gate_keeper & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2 ,
			PROT_WRITE | PROT_READ | PROT_EXEC);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
			FILE,LINE,
			(u4)&sandbox_constructor_gate_keeper_arm_constant_translate,
			(u4)fbt_translate_noexecute_bridge);
	patch_memory((u4)&sandbox_constructor_gate_keeper_arm_constant_translate,
			(u4)fbt_translate_noexecute_bridge);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(lock_thread_1)",
			FILE,LINE,
			(u4)&sandbox_constructor_gate_keeper_arm_constant_lock,
			(u4)lock_thread_1);
	patch_memory((u4)&sandbox_constructor_gate_keeper_arm_constant_lock,
			(u4)lock_thread_1);

	//remove w from this page (rx)
	mprotect((void *)((u4)&sandbox_constructor_gate_keeper & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2,
			PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}


bool init_jni_trampoline() {
	TRACE_ENTER;
	mprotect((void *)((u4)&sandbox_jni_trampoline & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2 ,
			PROT_WRITE | PROT_READ | PROT_EXEC);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(get_tld)",
			FILE,LINE,
			(u4)&sandbox_jni_trampoline_constant_get_tld,
			(u4)get_tld);
	patch_memory((u4)&sandbox_jni_trampoline_constant_get_tld,
			(u4)get_tld);


	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(get_tld)",
			FILE,LINE,
			(u4)&sandbox_jni_trampoline_thumb_constant_get_tld,
			(u4)get_tld);
	patch_memory((u4)&sandbox_jni_trampoline_thumb_constant_get_tld,
			(u4)get_tld);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
			FILE,LINE,
			(u4)&sandbox_jni_trampoline_constant_translate,
			(u4)fbt_translate_noexecute_bridge);
	patch_memory((u4)&sandbox_jni_trampoline_constant_translate,
			(u4)fbt_translate_noexecute_bridge);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
			FILE,LINE,
			(u4)&sandbox_jni_trampoline_thumb_constant_translate,
			(u4)fbt_translate_noexecute_bridge);
	patch_memory((u4)&sandbox_jni_trampoline_thumb_constant_translate,
			(u4)fbt_translate_noexecute_bridge);

#ifdef DEBUG_BT_RUNTIME
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)&sandbox_jni_trampoline_constant_debug,
			(u4)bt_debug_print_address);
	patch_memory((u4)&sandbox_jni_trampoline_constant_debug,
			(u4)bt_debug_print_address);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)&sandbox_jni_trampoline_thumb_constant_debug,
			(u4)bt_debug_print_address);
	patch_memory((u4)&sandbox_jni_trampoline_thumb_constant_debug,
			(u4)bt_debug_print_address);
#endif


	//remove w from this page (rx)
	mprotect((void *)((u4)&sandbox_jni_trampoline & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2,
			PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}


// bool init_gate_keeper() {
//     //init the gate_keeper

//     //add w to this page (also need rx
//     //because init_gate_keeper may be in the same page with gate keeper)
//     // (we need to add w to 2 pages since &sandbox_jni_gate_keeper_arm_constant_tld
//     // maybe at another page)
//     /*
//      *
//      *                __ sandbox_jni_gate_keeper
//      *            xxxx
//      *            xxxx_ another page start
//      *            xxxx  _ sandbox_jni_gate_keeper_arm_constant_tld
//      *
//      *
//      */
//     mprotect((void *)((u4)&sandbox_jni_gate_keeper & ~ARM_PAGE_MASK),
//                            ARM_PAGE_SIZE * 2 ,
//                            PROT_WRITE | PROT_READ | PROT_EXEC);

//     //SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(tld)\n",FILE,LINE,
//     //                        (u4)&sandbox_jni_gate_keeper_arm_constant_tld, (u4)tld);

//     //patch_memory((u4)&sandbox_jni_gate_keeper_arm_constant_tld, (u4)tld);

//     SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
//                             FILE,LINE,
//                             (u4)&sandbox_jni_gate_keeper_arm_constant_translate,
//                             (u4)fbt_translate_noexecute_bridge);
//     patch_memory((u4)&sandbox_jni_gate_keeper_arm_constant_translate,
//                             (u4)fbt_translate_noexecute_bridge);

//     SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(lock_thread)",
//                             FILE,LINE,
//                             (u4)&sandbox_jni_gate_keeper_arm_constant_lock,
//                             (u4)lock_thread);
//     patch_memory((u4)&sandbox_jni_gate_keeper_arm_constant_lock,
//                             (u4)lock_thread);

//     //remove w from this page (rx)
//     mprotect((void *)((u4)&sandbox_jni_gate_keeper & ~ARM_PAGE_MASK),
//                            ARM_PAGE_SIZE * 2,
//                            PROT_READ | PROT_EXEC);
//     return true;
// }

bool init_ijump_trampoline() {
	//the indirect_jimp_trampoline
	TRACE_ENTER;
	u4 * destination = (void *)(sbox.sandbox_start + IJUMP_TRAMPOLINE_START);
	u4 * src = (void *)&sandbox_ijump_trampoline_arm;
	u4 ijump_trampoline_arm_len = (u4)&sandbox_ijump_trampoline_arm_end
		- (u4)&sandbox_ijump_trampoline_arm;
	u4 ijump_trampoline_arm_cstart = (u4)&sandbox_ijump_trampoline_arm_constant
		- (u4)&sandbox_ijump_trampoline_arm;

	u4 ijump_trampoline_arm_get_tld_start = (u4)&sandbox_ijump_trampoline_arm_constant_get_tld
		- (u4)&sandbox_ijump_trampoline_arm;


	mprotect(destination, ARM_PAGE_SIZE, PROT_READ | PROT_WRITE);
	fill_memory_hlt(destination, ARM_PAGE_SIZE);
	memcpy(destination, src, ijump_trampoline_arm_len);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with [0x%8x] (fbt_translate_noexecute_bridge) \n",
			FILE,LINE,
			(u4)(destination) + ijump_trampoline_arm_cstart,
			(u4)fbt_translate_noexecute_bridge);
	//patch it
	patch_memory(((u4)destination) + ijump_trampoline_arm_cstart,
			(u4)fbt_translate_noexecute_bridge);


	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with [0x%8x] (get_tld)",
			FILE,LINE,
			(u4)(destination) + ijump_trampoline_arm_get_tld_start,
			(u4)get_tld);
	//patch it
	patch_memory(((u4)destination) + ijump_trampoline_arm_get_tld_start,
			(u4)get_tld);



#ifdef DEBUG_BT_RUNTIME
	u4 ijump_trampoline_debug_cstart = (u4)&sandbox_ijump_trampoline_debug_constant
		- (u4)&sandbox_ijump_trampoline_arm;

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with [0x%8x] (bt_debug_print_address)",
			FILE,LINE,
			(u4)(destination) + ijump_trampoline_debug_cstart,
			(u4)bt_debug_print_address);
	//patch it
	patch_memory(((u4)destination) + ijump_trampoline_debug_cstart,
			(u4)bt_debug_print_address);
#endif

	//flush the cache
	cacheflush((u4)destination, ARM_PAGE_SIZE, 0);
	mprotect(destination, ARM_PAGE_SIZE, PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}



bool init_callback_trampoline(){
	TRACE_ENTER;
	mprotect((void *)((u4)&sandbox_callback_trampoline & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2 ,
			PROT_WRITE | PROT_READ | PROT_EXEC);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(get_tld)",
			FILE,LINE,
			(u4)&sandbox_callback_trampoline_constant_get_tld,
			(u4)get_tld);
	patch_memory((u4)&sandbox_callback_trampoline_constant_get_tld,
			(u4)get_tld);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(lock_thread_1)",
			FILE,LINE,
			(u4)&sandbox_callback_trampoline_constant_lock,
			(u4)lock_thread_1);
	patch_memory((u4)&sandbox_callback_trampoline_constant_lock,
			(u4)lock_thread_1);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
			FILE,LINE,
			(u4)&sandbox_callback_trampoline_constant_translate,
			(u4)fbt_translate_noexecute_bridge);
	patch_memory((u4)&sandbox_callback_trampoline_constant_translate,
			(u4)fbt_translate_noexecute_bridge);

#ifdef DEBUG_BT_RUNTIME
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)&sandbox_callback_trampoline_constant_debug,
			(u4)bt_debug_print_address);
	patch_memory((u4)&sandbox_callback_trampoline_constant_debug,
			(u4)bt_debug_print_address);
#endif

	//remove w from this page (rx)
	mprotect((void *)((u4)&sandbox_callback_trampoline & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2,
			PROT_READ | PROT_EXEC);
	
	mprotect((void *)((u4)&sandbox_callback_trampoline_thumb & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2 ,
			PROT_WRITE | PROT_READ | PROT_EXEC);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(get_tld)",
			FILE,LINE,
			(u4)&sandbox_callback_trampoline_thumb_constant_get_tld,
			(u4)get_tld);
	patch_memory((u4)&sandbox_callback_trampoline_thumb_constant_get_tld,
			(u4)get_tld);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(lock_thread_1)",
			FILE,LINE,
			(u4)&sandbox_callback_trampoline_thumb_constant_lock,
			(u4)lock_thread_1);
	patch_memory((u4)&sandbox_callback_trampoline_thumb_constant_lock,
			(u4)lock_thread_1);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(fbt_translate_noexecute_bridge)",
			FILE,LINE,
			(u4)&sandbox_callback_trampoline_thumb_constant_translate,
			(u4)fbt_translate_noexecute_bridge);
	patch_memory((u4)&sandbox_callback_trampoline_thumb_constant_translate,
			(u4)fbt_translate_noexecute_bridge);

#ifdef DEBUG_BT_RUNTIME
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)&sandbox_callback_trampoline_thumb_constant_debug,
			(u4)bt_debug_print_address);
	patch_memory((u4)&sandbox_callback_trampoline_thumb_constant_debug,
			(u4)bt_debug_print_address);
#endif

	//remove w from this page (rx)
	mprotect((void *)((u4)&sandbox_callback_trampoline_thumb & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2,
			PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}

bool init_callback_ret_trampoline(){
	TRACE_ENTER;
	mprotect((void *)((u4)&sandbox_callback_ret_trampoline & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2 ,
			PROT_WRITE | PROT_READ | PROT_EXEC);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(get_tld)",
			FILE,LINE,
			(u4)&sandbox_callback_ret_trampoline_constant_get_tld,
			(u4)get_tld);
	patch_memory((u4)&sandbox_callback_ret_trampoline_constant_get_tld,
			(u4)get_tld);
	
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(unlock_thread)",
			FILE,LINE,
			(u4)&sandbox_callback_ret_trampoline_constant_unlock,
			(u4)unlock_thread);
	patch_memory((u4)&sandbox_callback_ret_trampoline_constant_unlock,
			(u4)unlock_thread);

#ifdef DEBUG_BT_RUNTIME
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)&sandbox_callback_ret_trampoline_constant_debug,
			(u4)bt_debug_print_address);
	patch_memory((u4)&sandbox_callback_ret_trampoline_constant_debug,
			(u4)bt_debug_print_address);
#endif
	//remove w from this page (rx)
	mprotect((void *)((u4)&sandbox_callback_ret_trampoline & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2,
			PROT_READ | PROT_EXEC);
	
	mprotect((void *)((u4)&sandbox_callback_ret_trampoline_thumb & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2 ,
			PROT_WRITE | PROT_READ | PROT_EXEC);

	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(get_tld)",
			FILE,LINE,
			(u4)&sandbox_callback_ret_trampoline_thumb_constant_get_tld,
			(u4)get_tld);
	patch_memory((u4)&sandbox_callback_ret_trampoline_thumb_constant_get_tld,
			(u4)get_tld);
	
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(unlock_thread)",
			FILE,LINE,
			(u4)&sandbox_callback_ret_trampoline_thumb_constant_unlock,
			(u4)unlock_thread);
	patch_memory((u4)&sandbox_callback_ret_trampoline_thumb_constant_unlock,
			(u4)unlock_thread);

#ifdef DEBUG_BT_RUNTIME
	SANDBOX_LOGI("[x] [%s:%d]: patch 0x%8x with 0x%8x(bt_debug_print_address()) \n",
			FILE,LINE, (u4)&sandbox_callback_ret_trampoline_thumb_constant_debug,
			(u4)bt_debug_print_address);
	patch_memory((u4)&sandbox_callback_ret_trampoline_thumb_constant_debug,
			(u4)bt_debug_print_address);
#endif
	//remove w from this page (rx)
	mprotect((void *)((u4)&sandbox_callback_ret_trampoline_thumb & ~ARM_PAGE_MASK),
			ARM_PAGE_SIZE * 2,
			PROT_READ | PROT_EXEC);
	TRACE_EXIT;
	return true;
}

/*void sigsegv_handler(int signo, siginfo_t *si, void *arg){
ucontext_t *ctx = (ucontext_t *)arg;
SANDBOX_LOGE("[x] [%s:%d]: Handler captured signal %d with pc: 0x%8x, lr: 0x%8x", 
FILE, LINE, signo, 
(u4)ctx->uc_mcontext.arm_pc, 
(u4)ctx->uc_mcontext.arm_lr);

ctx->uc_mcontext.arm_pc = sandbox_callback_trampoline(ucontext_t *ctx);
}*/



extern void sigsegv_handler(int signo, siginfo_t *si, void *arg);
bool init_signal_sigsegv(){
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO;
	if(sigaction(SIGSEGV, &sa, NULL) == -1){
		SANDBOX_LOGI("[x] [%s:%d]: register handler of signal SIGSEGV error",
				FILE,LINE);
		return false;
	}
	SANDBOX_LOGI("[x] [%s:%d]: register handler of signal SIGSEGV",
			FILE,LINE);
	return true;
}

void init_trampoline() {
	TRACE_ENTER;
	init_ret_trampoline();
	init_gate_keeper();
	init_constructor_gate_keeper();
	init_ijump_trampoline();
	init_jni_trampoline();
	init_callback_trampoline();
	init_callback_ret_trampoline();
	init_signal_sigsegv();
	TRACE_EXIT;
}

