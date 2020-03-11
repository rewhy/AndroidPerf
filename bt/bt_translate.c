#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "ucontext.h"

#include "ba/ba.h"
#include "sandbox.h"
#include "asm.h"
#include "global.h"

#include "bt.h"
#include "bt_code_cache.h"
#include "bt_asm_macros.h"

#include "uafdetect/uafdetect.h"

#include "log/log.h"

/*
 *  The binary translator :
 *     In fact, we only care about two types of instructions:
 *      (1) instructions that read data from memory or store data into memory
 *      (2) instructions that can change the control flow except direct jump
 *
 *  Challenge:
 *			Arm instruction has rich addressing mode and implicit indirect jump by
 *			change pc register directly.
 *
 */

/* the instruction decoding here is based on ARM Architecture Reference Manual
 * ARM v7-A and ARM v7-R edition (ARM DDI 0406A) */

/*
 * Do we need to process the unpredictable instructions:
 *
 * Some instructions have unpredictable behavior according the the manual such
 * as using pc reg as the destination register in LDRB (or pc as base register
 * while specifying ! (wp).)
 *
 * NACL disallows such instructions (and we should too). However this may increase
 * performance head when translating instructions since this needs we check more
 * instructions. So in current version, we do not process these instructions.
 */


/* target instruction mode string */
char * target_mode[2] = {"ARM", "THUMB"};

//unsigned long g_translated_thumb_insn = 0;
//unsigned long g_translated_arm_insn = 0;
// store the total size of the translated instructions
unsigned int g_bytes_translated = 0;
// the sizo of the total code.
extern int g_code_size;
translation_state fbt_translate_instr(struct translate *ts, int t_mode) {
	TRACE_ENTER;
	//BT_DEBUG_CLEAN("    ------->\n");
	ins_type ret = 0;
	//BT_DARM((u4)ts->next_instr, *(u4*)ts->next_instr);
	if (t_mode == ARM_MODE_THUMB) {
		ret = fbt_translate_instr_thumb(ts);
		//g_translated_thumb_insn++;
	} else if (t_mode == ARM_MODE_ARM) {
		// return fbt_translate_instr_arm(ts);
		ret = fbt_translate_instr_arm(ts);
		//g_translated_arm_insn++;
	} else {
		BT_ERR(true, "error mode %d \n", t_mode);
	}

	/* mapping from ins_type to translation_state*/
	/*   INS_INDIRECT_JUMP  -> close
	 *   INS_DIRECT_JUMP   -> close
	 */

	BT_DEBUG_CLEAN("ret 0x%-8x", ret);

	//BT_DEBUG_CLEAN("    <-------\n");

	if ((ret & (INS_INDIRECT_JUMP | INS_DIRECT_JUMP))
			&& (!(ret & INS_CONDITIONAL_JUMP)))
		return CLOSE;

	TRACE_EXIT;
	return NEUTRAL;
}


//jump from src to target
/*
 * the new allocated code cache should be close to old new, so we can use
 * pc based jump.
 */
void link_two_code_cache(unsigned char * src, unsigned char * target, int t_mode) {
	TRACE_ENTER;
	if (((u4) target - (u4)src) >= 0x2000000) {
		BT_ERR(true, "The target [0x%8x] is too far away from src [0x%8x]",
				(u4)target, (u4)src);
	}

	if ((u4) target - (u4)src<= 4) {
		BT_ERR(true, "The target [0x%8x] is too near from src [0x%8x]",
				(u4)target, (u4)src);
	}

	u4 offset = (u4) target - (u4)src;

	//see document of b instruction.
	if (t_mode == ARM_MODE_ARM) {
		//because pc is 8 bytes away current instruction in ARM
		offset -= 8;
		offset = offset >>2;
		ARM_B(src, offset);
	} else {
		//because pc is 4 bytes away current instruction in THUMB
		offset -= 4;
		offset = offset >>1;
		THUMB_B_IMM11(src, offset);
	}

	BT_DEBUG("DEBUG: The src [0x%x] is mapped to target [0x%x] with offset [0x%x] ",
			(u4)src, (u4)target, offset);
	TRACE_EXIT;
}

// static inline fbt_set_region_prot(struct thread_local_data *tld, int prot) {
//     mprotect(ts->transl_instr,
// }

// #define DIS_CODE_CACHE
void *fbt_translate_noexecute(void *orig_address,
		struct thread_local_data *tld, int t_mode) {
	TRACE_ENTER;
	BT_DEBUG("DEBUG: orig_address [0x%8x], tld: [0x%8x]",
			(u4)orig_address, (u4)tld);

	assert(tld != NUL);
	/*
	 *  If we are returning from untrusted code, jump to ret
	 *     trampoline directly.
	 *
	 *  Before entering untrusted code, we put the address of
	 *   ret trampoline into lr register.
	 *
	 */
	//if (((u4)orig_address == sbox.sandbox_start + RET_TRAMPOLINE_START) ||
	if ((orig_address == tld->ret_trampoline) 
			|| ((u4)orig_address == sandbox_callback_ret_trampoline)
			|| ((u4)orig_address == sandbox_callback_ret_trampoline_thumb)) {
		BT_DEBUG("DEBUG: orig_address [0x%8x], tld: [0x%8x]. will call ret trampoline",
				(u4)orig_address, (u4)tld);
		return orig_address;

	}

	/* valid the address first */
	if (((u4)orig_address < sbox.sandbox_start + UNTRUSTED_LIB_START)
			|| ((u4)orig_address > sbox.sandbox_start + UNTRUSTED_LIB_END)) {
		/*
		 * if it's the JNI call, then return the address of JNI trampoline.
		 *
		 *  We have different JNI trampoline for thumb and arm mode
		 *
		 */
		if (validate_jni((u4)orig_address)) {
			tld->jni_func_addr = (u4)orig_address;

			if (t_mode == ARM_MODE_THUMB) {
				BT_DEBUG("DEBUG: return JNI trampoline (thumb) [0x%8x], tld: [0x%8x]",
						(u4)&sandbox_jni_trampoline_thumb, (u4)tld);
				tld->jni_func_addr = tld->jni_func_addr + 1;
				BT_DEBUG("DEBUG: tld->jni_func_addr [0x%8x], tld: [0x%8x]",
						(u4)tld->jni_func_addr, (u4)tld);
				return &sandbox_jni_trampoline_thumb;
			} else {
				BT_DEBUG("DEBUG: return JNI trampoline [0x%8x], tld: [0x%8x]",
						(u4)&sandbox_jni_trampoline, (u4)tld);
				BT_DEBUG("DEBUG: tld->jni_func_addr [0x%8x], tld: [0x%8x]",
						(u4)tld->jni_func_addr, (u4)tld);
				return &sandbox_jni_trampoline;
			}

		} else {
#ifndef TRACE_SYSTEM_LIB
		/*	hook_addr = is_hook_needed((u4)orig_address);
			if(hook_addr > 0){
				tld->jni_func_addr = hook_addr;
				*isHooked = true;
				t_mode = hook_addr & 0x1;
			} else {
			}*/
			tld->jni_func_addr = (u4)orig_address;

			if (t_mode == ARM_MODE_THUMB) {
				BT_DEBUG("DEBUG: return system trampoline (thumb) [0x%8x], tld: [0x%8x]",
						(u4)&sandbox_jni_trampoline_thumb, (u4)tld);
				tld->jni_func_addr = tld->jni_func_addr + 1;
				BT_DEBUG("DEBUG: tld->jni_func_addr [0x%8x], tld: [0x%8x]",
						(u4)tld->jni_func_addr, (u4)tld);
				return &sandbox_jni_trampoline_thumb;
			} else {
				BT_DEBUG("DEBUG: return system trampoline [0x%8x], tld: [0x%8x]",
						(u4)&sandbox_jni_trampoline, (u4)tld);
				BT_DEBUG("DEBUG: tld->jni_func_addr [0x%8x], tld: [0x%8x]",
						(u4)tld->jni_func_addr, (u4)tld);
				return &sandbox_jni_trampoline;
			}
#else
			BT_ERR(false, "ERROR: address 0x%8x is beyond the range of untrusted code.",
					(u4)orig_address);
#endif
		}
	}
	//BT_INFO("INFO: finished the address validation.");
	/* if the target is already translated then we return the cached version  */
	void *already_translated = fbt_ccache_find(tld, orig_address);
	if (already_translated != NULL) {
		BT_DEBUG("already translated -> [0x%8x]", (u4) already_translated);
		return already_translated;
	}

	struct mem_info *code_block = tld->chunk;
	/* make sure that we don't translate translated code */
	while (code_block != NULL) {
		if ((orig_address >= code_block->ptr) &&
				(orig_address <= (code_block->ptr + code_block->size))) {
			BT_ERR(true, "Translating translated code: "
					"0x%8x (0x%8x len: 0x%8x (0x%8x))",
					(u4)orig_address, (u4)(code_block->ptr),
					(u4)code_block->size, (u4)code_block);
		}
		code_block = code_block->next;
	}

	/* we need to translate TU, add to ccache index,
		 jump to the translated code */
	translation_state tu_state = NEUTRAL;

	struct translate *ts = &(tld->trans);
	ts->next_instr = (unsigned char*)orig_address;

	/* check if more memory needs to be allocated for tcache */
	if ((long)(ts->code_cache_end - ts->transl_instr) < 128) {
		BT_DEBUG("Not enough memory for new code block[0x%x - 0x%x] - allocating more!",
				(u4)ts->transl_instr, (u4)ts->code_cache_end);
		unsigned char *prev_transl_instr = ts->transl_instr;

		fbt_allocate_new_code_cache(tld);

		/* add a jmp connect old and new tcache memory blocks */
		if (prev_transl_instr != NULL) {
			link_two_code_cache(prev_transl_instr, ts->transl_instr, t_mode);
			/* make the translation cache as rx */
			mprotect(prev_transl_instr, ts->code_cache_end - prev_transl_instr,
					PROT_READ| PROT_EXEC);
		}
	}

#if 1
	/*this checking can be removed for performance*/
	if ((u4)(ts->transl_instr) & 0x1) {
		BT_ERR(true, "mode:[%s]:ts->transl_instr (0x%8x) is not 2 bytes aligned",
				target_mode[t_mode],
				(u4)ts->transl_instr);
	}
#endif

	/* to make sure that jump target is 4 bytes aligned */
	if ((u4)(ts->transl_instr) & 0x3) {
		// if (t_mode == ARM_MODE_ARM) {
		//     BT_ERR(true, "mode:[%s]: ts->transl_instr (0x%8x) is not 4 bytes aligned",
		//                                                 target_mode[t_mode],
		//                                                 ts->transl_instr);
		// }

		BT_DEBUG("mode:[%s]: ts->transl_instr (0x%8x) is not 4 bytes aligned."
				" padding with bkpt.", target_mode[t_mode], (u4)ts->transl_instr);

		//fill bkpt instruction 0xbe00
		memset((void *)(ts->transl_instr + 2), 0xbe00, 0x2);
		ts->transl_instr += 2;
	}

	BT_DEBUG("tld->ts.transl_instr: 0x%8x", (u4)(ts->transl_instr));

	/* add entry to ccache index */
	fbt_ccache_add_entry(tld, orig_address, ts->transl_instr);

	/* look up address in translation cache index */
	void *transl_address = ts->transl_instr;

	int bytes_translated = 0;
	//how many space we can use?
	int space_in_code_cache = ts->code_cache_end - ts->transl_instr;

	/* we translate as long as we
		 - stay in the limit (MAX_BLOCK_SIZE)
		 - or if we do not hit indirect jump
		 */

	unsigned char * ooold_transl_instr = ts->transl_instr;

	while (((space_in_code_cache > 0) && (tu_state == NEUTRAL)) ||
			(tu_state == OPEN)) {
		/* translate an instruction */
		unsigned char *old_transl_instr = ts->transl_instr;

		tu_state = fbt_translate_instr(ts, t_mode);

		bytes_translated += (ts->transl_instr - old_transl_instr);
		space_in_code_cache -= (ts->transl_instr - old_transl_instr);
	}

	/* if the TU was finished because the number of instructions hit the limit, we
		 have to add glue code to the TU */
	if (tu_state != CLOSE) {
		BT_ERR(true,"*******************TODO********************");
	}

	g_bytes_translated += bytes_translated;
	/*if(g_code_size > 0) {
		hit_code_rate = (float)g_bytes_translated / (float)g_code_size;
	}

	BT_INFO("%d/%d (%5f) of all codes have been hit.", 
			g_bytes_translated, g_code_size, hit_code_rate);*/
	
	assert((void*)(ts->transl_instr) < (void*)(ts->code_cache_end +
				TRANSL_GUARD));

	BT_DEBUG("-> 0x%8x,   next_tu=0x%8x (len: 0x%-8x)", (u4)transl_address,
			(u4)(ts->next_instr), bytes_translated);

	//http://blogs.arm.com/software-enablement/141-caches-and-self-modifying-code/
	BT_DEBUG_CLEAN("clear cache %x - %x ", (u4)ooold_transl_instr,
			(u4)ts->transl_instr );

	cacheflush((u4)ooold_transl_instr, (u4)ts->transl_instr, 0);

	//Todo: make the translation cache rx (remove w)

	BT_DEBUG_CLEAN("\n[DIS]********** translate end **********\n");
	TRACE_EXIT;
	return transl_address;
}


/* called from assembly code */
void * fbt_translate_noexecute_bridge(void *orig_address,
		struct thread_local_data *tld) {
	TRACE_ENTER;
	int t_mode = (((u4)orig_address & 0x1) == 1 ? ARM_MODE_THUMB:ARM_MODE_ARM);

	BT_DEBUG_CLEAN("\n[DIS]********** translate begin **********\n");

	BT_DEBUG("DEBUG: orig_address [0x%8x], tld: [0x%8x], mode: %s ",
			(u4)orig_address, (u4)tld,
			target_mode[t_mode]);

	/* mask last 1 bit*/
	u4 ret_addr = (u4)fbt_translate_noexecute((void*)((u4)orig_address & (~0x1)),
			tld, t_mode);

	//put last bit of original address to jump target so that
	//we can switch the mode automatically
	ret_addr |= (u4)orig_address & 0x1;
	BT_DEBUG("DEBUG: orig_address [0x%8x] target_address [0x%8x], mode: %s ",
			(u4)orig_address, (u4)ret_addr, target_mode[t_mode]);
	TRACE_EXIT;
	return (void*)ret_addr;
}

/* signal handler */
void sigsegv_handler(int signo, siginfo_t *si, void *arg){

	ucontext_t *ctx = (ucontext_t *)arg;
	u4 arm_pc = (u4) ctx->uc_mcontext.arm_pc;
	u4 arm_lr = (u4) ctx->uc_mcontext.arm_lr;
	u4 arm_sp = (u4) ctx->uc_mcontext.arm_sp;

	u4 insn = *((u4*)arm_pc);

	BT_ERR(0, "[x] [%s:%d]: Handler captured signal %d with pc: 0x%8x, lr: 0x%8x, sp: 0x%8x, insn: 0x%8x",
			FILE, LINE, signo, arm_pc, arm_lr, arm_sp, insn);

	if (((arm_pc > sbox.sandbox_start + UNTRUSTED_LIB_START)
				&& (arm_pc < sbox.sandbox_start + UNTRUSTED_LIB_END))
			&& ((arm_lr < sbox.sandbox_start + UNTRUSTED_LIB_START)
				||(arm_lr > sbox.sandbox_start + UNTRUSTED_LIB_END))) {
		arm_sp -= 4;
		/* push original addess into stack */
		ctx->uc_mcontext.arm_sp = arm_sp;
		//ctx->uc_mcontext.arm_pc = arm_lr;
		if((insn & 0xfe00) == 0xb400){
			arm_pc |= 0x1;
			ctx->uc_mcontext.arm_pc = (u4)&sandbox_callback_trampoline_thumb;
		} else {
			ctx->uc_mcontext.arm_pc = (u4)&sandbox_callback_trampoline;
		}
		*((u4 *)arm_sp) = arm_pc;
		
		BT_DEBUG("[x] [%s:%d]: jump to callback trampoline 0x%8x (sp 0x%8x) (insn: 0x%8x dst: 0x%8x)",
				FILE, LINE,
				(u4)ctx->uc_mcontext.arm_pc,
				(u4)ctx->uc_mcontext.arm_sp,
				*(u4*)ctx->uc_mcontext.arm_pc,
				arm_pc);

		/*BT_DEBUG("r0: 0x%8x, r1: 0x%8x, r2: 0x%8x, r3: 0x%8x",
				(u4)ctx->uc_mcontext.arm_r0,
				(u4)ctx->uc_mcontext.arm_r1,
				(u4)ctx->uc_mcontext.arm_r2,
				(u4)ctx->uc_mcontext.arm_r3);
		BT_DEBUG("r4: 0x%8x, r5: 0x%8x, r6: 0x%8x, r7: 0x%8x",
				(u4)ctx->uc_mcontext.arm_r4,
				(u4)ctx->uc_mcontext.arm_r5,
				(u4)ctx->uc_mcontext.arm_r6,
				(u4)ctx->uc_mcontext.arm_r7);
		BT_DEBUG("r8: 0x%8x, r9: 0x%8x, r10: 0x%8x, fp: 0x%8x, lr: 0x%8x",
				(u4)ctx->uc_mcontext.arm_r8,
				(u4)ctx->uc_mcontext.arm_r9,
				(u4)ctx->uc_mcontext.arm_r1,
				(u4)ctx->uc_mcontext.arm_fp,
				(u4)ctx->uc_mcontext.arm_lr);*/
	
	} else{
		BT_ERR(0, "[x] [%s:%d]: unknown signal.",
				FILE, LINE);
		BT_ERR(0, "r0: 0x%8x, r1: 0x%8x, r2: 0x%8x, r3: 0x%8x",
				(u4)ctx->uc_mcontext.arm_r0,
				(u4)ctx->uc_mcontext.arm_r1,
				(u4)ctx->uc_mcontext.arm_r2,
				(u4)ctx->uc_mcontext.arm_r3);
		BT_ERR(0, "r4: 0x%8x, r5: 0x%8x, r6: 0x%8x, r7: 0x%8x",
				(u4)ctx->uc_mcontext.arm_r4,
				(u4)ctx->uc_mcontext.arm_r5,
				(u4)ctx->uc_mcontext.arm_r6,
				(u4)ctx->uc_mcontext.arm_r7);
		BT_ERR(0, "r8: 0x%8x, r9: 0x%8x, 10: 0x%8x, ip: 0x%8x",
				(u4)ctx->uc_mcontext.arm_r8,
				(u4)ctx->uc_mcontext.arm_r9,
				(u4)ctx->uc_mcontext.arm_r1,
				(u4)ctx->uc_mcontext.arm_ip);
		BT_ERR(0, "fp: 0x%8x, lr: 0x%8x, pc: 0x%8x",
				(u4)ctx->uc_mcontext.arm_fp,
				(u4)ctx->uc_mcontext.arm_lr,
				(u4)ctx->uc_mcontext.arm_pc);
		//signal(signo, SIG_DFL);
		//raise(signo);
		raise(SIGABRT);
		//ctx->uc_mcontext.arm_pc = ctx->uc_mcontext.arm_lr;
	}
}
