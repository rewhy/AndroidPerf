#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <asm/sigcontext.h>

#include "ba/ba.h"
#include "sandbox.h"
#include "asm.h"
#include "global.h"


#include "bt.h"
#include "bt_code_cache.h"
#include "bt_asm_macros.h"

#include "uafdetect/uafdetect.h"

/*
 *
 *  For pc relative load:
 *      since we do not mix data/code in translated code, so we just load
 *      the data from original code and then return this value.
 *
 */

/* todo: optimization for indirect jump !!! */

/* thumb: see document. ARM DDI 0100D chapter A6. doc1 in the following */
/* thumb2: see document. ARM DDI 0308D. doc2 in the following */

/* thumb2 decoder is borrowing from qemu 1.2.0 */
/* translate the thumb code */



//thumb nop
//0x46c0      /* mov r8, r8 */


/*arm_transl_instr is already 2 bytes aligned */
#define ALIGN_4bytes(arm_transl_instr) \
	do {if ((u4)(arm_transl_instr) & 0x3) { \
		*((u2*)(arm_transl_instr)) = 0x46c0; \
		arm_transl_instr += 2; \
	} \
	} while (0)

extern ins_type gen_vldstr(struct translate *ts, u4	insn, u4 pc_value);

/* get a reg
 *  reg_mask: 1111  -> do not get reg 0123
 *
 */
static inline int get_reg(int reg_mask, int max_reg) {
	int i = 0;
	for (i = 0 ; i < max_reg; i ++) {
		if (((1<<i) & (reg_mask)) == 0)
			return i;
	}
	BT_ERR(true, "can not find a random reg");

	return -1;
}

//put 32 bits imm into reg r
static inline void gen_put_reg_imm32(struct translate *ts,
		int r, u4 imm32) {
	//the translated code should be 4 bytes aligned
	//since we will use 32bit thumb2 instructions in the following
	// BT_DEBUG_CLEAN("current code cache 0x%8x", ts->transl_instr);
	ALIGN_4bytes(ts->transl_instr);
	/* put load_address into rd */
	//lower 16 bits
	THUMB2_MOVW_IMM(ts->transl_instr, r, imm32 & 0xffff);
	//higher 16 bits
	THUMB2_MOVT_IMM(ts->transl_instr, r,
			((imm32 & 0xffff0000)>>16));
}

/*
 * We are in thumb mode and the indirect jump trampoline is in ARM mode.
 *  (1) the target mode after jumping is determined by last 2 bits of jump target
 *          01 11 -> thumb   00 ->arm. 10 ->undefined
 *   When jumping back to translated code, we put the last bit of original target
 *   into destination address in code cache, so that it will switch to same mode
 *   with original code..
 *
 *  (2) we need to switch to ARM mode when jumping to ijump trampoline.
 *      that's easy because the trampoline is 4 bytes aligned. jump to this address
 *      automatically switch the mode to ARM
 *
 */



/* returned total spaces revered on stack (pushed regs*4) */
static inline int gen_ijump_reg_thumb_prologue(struct translate *ts, int rd) {
	/*
	 * 1. reserve a space for returned target address
	 * 2. push ip/lr into stack
	 * 3. save flags into stack
	 */
	/* before saving flags, the translated instruction can not change flags!!*/
	/* add sp, sp, -4*/
	THUMB_SP_SUB_OFFSET(ts->transl_instr, 4);
	ALIGN_4bytes(ts->transl_instr);
	/* push ip, lr into stack */
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP) | (1<<ARMREG_LR));
	THUMB2_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP));

	if (rd == ARMREG_IP) {
		//ldr ip, [sp, 4]
		THUMB2_LDR_IMM8(ts->transl_instr, ARMREG_IP, ARMREG_SP, 4, 1, 1, 0);
	}

	return 16;
	//even we have pushed 3 regs, the offset to put target address is [sp + 8],
	// not [sp + 12]
}

/*  returning from trampoline (r0 -r3 has been popped before code can reach
 *  here).
 *
 *   garbage_space: the space on stack which needs to be discarded before jumping
 *                 to real target.
 *   Why we need the garbage space?
 *
 *   Let's see pop {reglist, pc} instruction. In order to process this instruction,
 *   we first generate pop {reglist} then treat pop {pc} as indirect jump.
 *
 * original stack:
 *   |pc
 *   |reglist
 *
 *
 * stack that after instructions in gen_ijump_reg_thumb_prologue
 *    (reglist has been popped)
 *
 *       | pc
 *       | reserved for returned target address
 *       | saved lr
 *       | saved ip
 *       | saved flags
 *       | pushed reg rx1
 *       | pushed reg rx2
 *
 * when calling instructions in epilogue:
 *
 *
 *high
 *       | garbage_space
 *       | reserved for returned target address
 *       | saved lr
 *       | saved ip
 *       | saved flags
 *       | pushed reg rx1
 *       | pushed reg rx2  _______________ current sp
 *
 *   So before jumping to "returned target address", we need to set sp up
 *   to garbage space and then use LDR to jump to target.
 *
 *
 */
static inline void gen_ijump_reg_thumb_epilogue(struct translate *ts, int garbage_space) {

	/*
	 *  1. restore flags
	 *  2. restore ip/lr
	 *  3. discard garbage space (by changing sp)
	 *  4. jump to saved target address
	 *
	 */
	ALIGN_4bytes(ts->transl_instr);
	/* pop saved flags into ip */
	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP));
	/* put ip -> apsr */
	//0x8: means nzcvq
	THUMB2_MSR_REG(ts->transl_instr, ARMREG_IP, 0x8);
	/* pop to ip again */
	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP)| (1<<ARMREG_LR));
	if (garbage_space == 0) {

		//DEBUG -> load from 0
		// ALIGN_4bytes(ts->transl_instr);
		// THUMB2_MOVW_IMM16(ts->transl_instr, ARMREG_R4, 0);
		// // //load from r4
		// THUMB2_LDR_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_R4, 0, 1, 0, 0);

		//if garbage_space == 0, we just pop {pc}
		THUMB_POP(ts->transl_instr, 0x0, 1);
	} else if (garbage_space > 0){
		/* discard garbage space
		 * sp = sp + garbage_space + 4 (target address)
		 */
		THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, garbage_space + 4);
		/* jump to target. target = mem[sp - garbage_space -4] */
		//ldr pc, [sp, - (garbage_space + 4)]
		THUMB2_LDR_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_SP, garbage_space + 4, 1, 0, 0);
	} else {
		//garbage_space == -1, means we do not need to restore stack and
		//jump to target. The caller will take care this.
	}
}

/*
 * indirect jump the jump target is in reg rd
 * ret_reg_offset: the offset from sp that the trampoline should write the jump
 *                 target in code cache.
 *
 *
 *  before calling this function (gen_ijump_reg_thumb)
 *
 * high  | reserved for returned target address
 *       | saved lr
 *       | saved ip
 *       | saved flags
 *       | pushed temp reg rx1 (if pushed)
 *       | pushed temp reg rx2  _______________ current sp
 *
 *
 *  (before entering trampoline)
 *
 * high  | reserved for returned target address
 *       | saved lr
 *       | saved ip
 *       | saved flags
 *       | pushed temp reg rx1
 *       | pushed temp reg rx2
 *       | pushed reg r3
 *       | pushed reg r2
 *       | pushed reg r1
 *       | pushed reg r0  _______________ current sp
 *
 *
 *  (just returning from trampoline)
 *
 * high  | reserved for returned target address
 *       | saved lr
 *       | saved ip
 *       | saved flags
 *       | pushed temp reg rx1
 *       | pushed temp reg rx2
 *       | pushed reg r3
 *       | pushed reg r2
 *       | pushed reg r1
 *       | pushed reg r0  _______________ current sp
 */
static inline void gen_ijump_reg_thumb(struct translate *ts, int rd, int ret_reg_offset) {
	/*
	 *   //push r0,r1,r2,r3 into stack
	 *   push {r0,r1,r2,r3}
	 *   //put the target address into r0
	 *   move from reg rd to r0
	 *   //put address of tld into r1
	 *   movw r1, tld&0xffff
	 *   movt r1, tld & 0xffff0000 >> 16
	 *   //put jump_trampoline into r2
	 *   //ldr r2, [r1, #TLD_OFFSET_IJUMP_TRAMPOLINE_ARM]
	 *   movw r1, tld&0xffff
	 *   movw r1, tld&0xffff
	 *   //put pushed_reg_list to lower 16 bits of r3
	 *   movw r3, pushed_reg_list&0xffff
	 *   jump to jump_trampoline
	 *   blx  r2
	 *   pop {r0- r3}
	 *
	 */

	/*push {r0,r1,r2,r3}*/
	THUMB_PUSH(ts->transl_instr, 0xf, 0);

	if (rd != 0) {
		/* add r0, rd, #0  = mov r0, rd*/
		/* THUMB_ADD_REG_IMM(ts->transl_instr, ARMREG_R0, rd, 0); */
		/* MOV r0, rd. rd can be high register r8 - r 15 */
		THUMB_MOV_HI_REG_REG(ts->transl_instr, ARMREG_R0, rd);
	}

	/* put tld -> r1
	 *
	 * translated code is shared by all threads. So we can not put the address
	 *  of tld into code.
	 *  tld will be calculated by calling get_tld function
	 *
	 */
	//gen_put_reg_imm32(ts, ARMREG_R1, (u4)(ts->tld));

	/* load ijump trampoline */
	gen_put_reg_imm32(ts, ARMREG_R2, sbox.sandbox_start + IJUMP_TRAMPOLINE_START);

	ALIGN_4bytes(ts->transl_instr);
	//put ret_reg_offset + 16 (pushed in this function) into r3
	THUMB2_MOVW_IMM16(ts->transl_instr, ARMREG_R3, (ret_reg_offset + 16) & 0xffff);
	/* jump to jump_trampoline */
	THUMB_BLX(ts->transl_instr, ARMREG_R2);
	/*trampoline returns. The actual target has been pushed on stack. Now
	 * restore state and jump to target in code cache.
	 */
	/*pop r0 - r3*/
	THUMB_POP(ts->transl_instr, 0xf, 0);
}

/*
 * generate pop {reglist} and cause indirect jump
 */
static inline void gen_pop_thumb(struct translate *ts, u4 rlist) {
	u4 offset = 0;

	if (rlist&0xff){
		//pop the registers (other than pc) first!
		THUMB_POP(ts->transl_instr, rlist&0xff, 0);
	}
	//debug
	// gen_put_reg_imm32(ts, ARMREG_R0, 0);
	// THUMB_LDR_IMM_OFFSET(ts->transl_instr, ARMREG_R0, ARMREG_R0, 0);

	//sp = sp - 4. skip the original jump target
	// THUMB_SP_SUB_OFFSET(ts->transl_instr, 4);

	offset = gen_ijump_reg_thumb_prologue(ts, -1);

	u4 temp_reg = 0;
	//1. push temp_reg
	THUMB_PUSH(ts->transl_instr, 1 << temp_reg, 0);
	offset += 4;

	/*
	 *       | pc
	 *       | reserved for returned target address
	 *       | saved lr
	 *       | saved ip
	 *       | saved flags
	 *       |saved temp_reg ___________current_sp
	 */
	//2. put pc to temp_reg
	/*  sp + offset : pc . which will be put into temp_reg */
	THUMB_LDR_SP_IMM(ts->transl_instr, temp_reg, offset);
	//3. jump to temp_reg
	//third argument: ret_reg_offset = the offset from current sp to the location
	// that returned target address will be written.
	//  = offset - 4  (offset: includes offset of prologue and pushed temp regs)
	gen_ijump_reg_thumb(ts, temp_reg, offset - 4);
	//4. pop temp_reg
	THUMB_POP(ts->transl_instr, 1 << temp_reg, 0);

	//debug
	// gen_put_reg_imm32(ts, ARMREG_R0, 0);
	// THUMB_LDR_IMM_OFFSET(ts->transl_instr, ARMREG_R0, ARMREG_R0, 0);

	//5. pop up saved flags, ip, discard garbage space and jump to target.
	gen_ijump_reg_thumb_epilogue(ts, 4);
}


/*
 * direct and indirect jump to target address jump_target.
 *
 */
static inline void gen_jump_thumb(struct translate *ts, u4 jump_target, int avoidregmask, int thumb2) {

	u4 temp_reg = 0;

	if (thumb2)
		temp_reg = get_reg(avoidregmask, 16);
	else
		temp_reg = get_reg(avoidregmask, 8);

	u4 offset = gen_ijump_reg_thumb_prologue(ts, temp_reg);
	//1. push temp_reg
	THUMB_PUSH(ts->transl_instr, 1 << temp_reg, 0);
	//2. put jump_address to temp_reg
	gen_put_reg_imm32(ts, temp_reg, jump_target);
	//since we have pushed another regs
	offset += 4;

	//3. jump to jump_address
	// we need to (-4) here since the offset to put jump address
	// is sp + offset - 4 (draw the stack then you will get it.)
	gen_ijump_reg_thumb(ts, temp_reg, (offset - 4)) ;
	//4. pop temp_reg
	THUMB_POP(ts->transl_instr, 1 << temp_reg, 0);
	//5. pop up saved flags, ip, discard garbage space and jump to target.
	gen_ijump_reg_thumb_epilogue(ts, 0);

}

//todo: optimize this function
static inline int bit_count(int regs) {
	int i = 0;
	for (i = 0; i< 16; i ++) {
		if (regs & (1<<i)){
			i += 1;
		}
	}
	return i;
}

//STRMB, STRIA
/*
 * STMDB<c> <Rn>{!},<registers>
 *      (1) first address = R[n] - 4*BitCount(registers)
 *      (2) for i = 0 to 14
 *            if reg[i] in registers
 *              mem[address] = R[i]
 *              address += 4
 *      (3) if wb, then r[n] = R[n] - 4*BitCount(registers)
 *
 * STMIA<c> <Rn>{!},<registers>
 *      (1) address = R[n]
 *      (2) if wb, R[n] = R[n] + 4*BitCount(registers)
 *      (3) for i = 0 to 14
 *            if reg[i] in registers
 *              mem[address] =R[i]
 *              address += 4
 *
 */

//Counting bits set, Brian Kernighan's way
static inline int count_bit_set(u4 reglist){
	unsigned int c; // c accumulates the total bits set in v
	for (c = 0; reglist; c++)
	{
		reglist &= reglist - 1; // clear the least significant bit set
	}

	return c;
}

/* In fact, we do not care about store since pc can not be base register
 *  and pc can not be in reglist!!!
 */
//LDMDB, LDMIA. and pc in registers.
//
static inline ins_type gen_multi_load(struct translate *ts, u4 insn) {
	/*
	 * LDMDB<c><q><Rn>{!}, <registers>
	 *      (1) first address = R[n] - 4*BitCount(registers)
	 *      (2) if wb, then r[n] = address
	 *      (3) for i = 0 to 14
	 *            if reg[i] in registers
	 *              R[i] = mem[address]
	 *              address += 4
	 *
	 * LDMIA<c>.W <Rn>{!},<registers>
	 *      (1) address = R[n]
	 *      (2) if wb, R[n] = R[n] + 4*BitCount(registers)
	 *      (3) for i = 0 to 14
	 *            if reg[i] in registers
	 *              R[i] = mem[address]
	 *              address += 4
	 *
	 */

	/*fast path: store is fine */
	if (!(insn & (1 << 20))) {
		return INS_COPY;
	}

	/*fast path: instruction without pc in the list*/
	if (!(insn & 0x8000)) {
		return INS_COPY;
	}

	//load: with pc in register list
	u4 reglist = (insn & 0xffff);
	u4 regcnt = count_bit_set(reglist);
	/* base register */
	u4 rn = (insn >> 16) & 0xf;

	u4 tempreg = -1;
	u4 tempinsn = insn;

	ALIGN_4bytes(ts->transl_instr);

	if (rn != ARMREG_SP) {
		/* base register is not sp */

		//1. find a temp register
		tempreg = get_reg((1<<rn) | (reglist), 10);

		//2. save temp register
		THUMB2_PUSH(ts->transl_instr,  (1<<tempreg));

		//3. load memory into temp register
		//mask out bit 15
		tempinsn = (tempinsn & 0xffff7fff);
		//set bit temp register
		tempinsn |= (1<<tempreg);
		THUMB2_RAW(ts->transl_instr, tempinsn);

		//4. jump to temp register
		u4 jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, tempreg);
		gen_ijump_reg_thumb(ts, tempreg, jump_prologue_offset - 4);
		gen_ijump_reg_thumb_epilogue(ts, -1);

		//5. restore temp register, sp and jump to real target
		//sp = sp + 4
		THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);
		//pop temp register
		THUMB2_POP(ts->transl_instr, (1<<tempreg));
		//now sp and temp register is restored, jump to target
		//target = [sp - 8]
		// index: true, add: false, wb: false
		THUMB2_LDRW_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_SP, 8, 1, 0, 0);

		return INS_PROCESSED | INS_INDIRECT_JUMP;
	}

	//rn = sp
	/*
	 *
	 * When sp is base register, we can not manipulate stack now since it
	 * will corrupt the memory content around sp.
	 *
	 *  one idea case is LDMIA SP!, {reglist}  -> pop instruction!
	 *
	 *   in this case, we can reuse the stack (and assume that memory
	 *   space under sp can be corrupted without any problem)
	 *
	 *
	 */

	bool decrement = (insn & (1<<23))?false:true;
	bool increment = !decrement;
	bool wback = (insn & (1<<21))?true:false;

	if ((increment) && (wback)) {
		//first load other registers
		if (regcnt != 1) {
			//mask out bit 15
			tempinsn = (tempinsn & 0xffff7fff);
			THUMB2_RAW(ts->transl_instr, tempinsn);
		}

		// if ((u4)ts->cur_instr == (u4)(0x6f21f382)) {
		//     gen_put_reg_imm32(ts, ARMREG_R0, 0);
		//     THUMB_LDR_IMM_OFFSET(ts->transl_instr, ARMREG_R0, ARMREG_R0, 0);
		// }

		//1. get a temp register
		tempreg = get_reg((1<<rn), 10);
		//2. save temp register
		THUMB2_PUSH(ts->transl_instr, (1<<tempreg));
		//3. jump target -> temp register
		// index: true, add: true, wb: false
		THUMB2_LDRW_IMM8(ts->transl_instr, tempreg, ARMREG_SP, 4, 1, 1 , 0);

		/*
		 *
		 *   |jump target
		 *   |temp register ___current sp
		 *
		 *
		 */
		//4. jump to temp register
		u4 jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, tempreg);
		gen_ijump_reg_thumb(ts, tempreg, jump_prologue_offset - 4);
		gen_ijump_reg_thumb_epilogue(ts, -1);

		/*
		 *                  __ the expected sp after this instruction
		 *   |jump target
		 *   |temp register
		 *   |real target ___current sp
		 *
		 *
		 */

		//5. restore temp register, sp and jump to real target
		//sp = sp + 12
		THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 12);
		//restore temp register
		// temp = [sp - 8]
		// index: true, add: false, wb: false
		THUMB2_LDR_IMM8(ts->transl_instr, tempreg, ARMREG_SP, 8, 1, 0 , 0);


		//now sp and temp register is restored, jump to target
		//target = [sp - 12]
		// index: true, add: false, wb: false
		THUMB2_LDRW_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_SP, 12, 1, 0, 0);

		return INS_PROCESSED | INS_INDIRECT_JUMP;
	} else {
		goto todo;
	}

todo:
	//other case: use sp as base register
	BT_ERR(true, "todo thumb2 instruction 0x%-8x ", insn);
	return INS_TODO;
}


/* load and store single item */
/* see page 3-26 on doc2 */
static inline ins_type gen_ldst(struct translate *ts, u4 insn, u4 pc_value) {
	/* fast path: store is ok */
	if (!(insn & (1 << 20))) {
		//store
		return INS_COPY;
	}

	/*fast path: load(b/h) is ok: bit [22 21] == [0 x] */
	if (!(insn & (1 << 22))) {
		return INS_COPY;
	}

	u4 rn = (insn >> 16) & 0xf;
	u4 rt = (insn >> 12) & 0xf;

	/* fast path: load and r15 is not in rt and rn */
	if ((rn != ARMREG_PC) && (rt != ARMREG_PC)) {
		return INS_COPY;
	}


	//load: pc in src or dst!
	u4 rm = insn & 0xf;
	u4 temprn = get_reg((1<<rn) | (1<<rt) | (1<<rm), 10);
	u4 temprt = get_reg((1<<rn) | (1<<rt) | (1<<rm) | (1<<temprn), 10);

	bool rt_pc = (rt == ARMREG_PC)? true : false;
	bool rn_pc = (rn == ARMREG_PC)? true : false;
	bool rt_sp = (rt == ARMREG_SP)? true : false;
	bool rn_sp = (rn == ARMREG_SP)? true : false;

	u4 tempinsn = insn;

	ALIGN_4bytes(ts->transl_instr);

	//base register is pc
	if (rn_pc) {
		/* push temp registers */
		THUMB2_PUSH(ts->transl_instr, (1<< temprt) | (1<< temprn));

		/*
		 * if pc as base register, the real value used in align(pc,4)
		 *  see page A8-123 on doc (DDI 0406A). See we need to mask out
		 *  last 2 bits of pc_value
		 */

		/* pc -> temprn */
		gen_put_reg_imm32(ts, temprn, pc_value & (~0x3));

		tempinsn = (tempinsn & (~0xf0000)) | (temprn<<16);
		tempinsn = (tempinsn & (~0xf000)) | (temprt<<12);

		//patch original instruction
		THUMB2_RAW(ts->transl_instr, tempinsn);

		//if rt_pc, indirect jump
		if (rt_pc) {
			u4 jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, temprt);
			gen_ijump_reg_thumb(ts, temprt, jump_prologue_offset - 4);
			gen_ijump_reg_thumb_epilogue(ts, -1);

			//restore temp register
			// wback is false. [if pc is base register, wback can not be true]
			//sp = sp + 4
			THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);
			THUMB2_POP(ts->transl_instr, (1<< temprt) | (1<< temprn));
			//load target into pc
			//target = [sp - 12]
			// index: true, add: false, wb: false
			THUMB2_LDRW_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_SP, 12, 1, 0, 0);
			return INS_PROCESSED | INS_INDIRECT_JUMP;
		} else if (rt_sp) {
			//sp is destination register
			BT_DEBUG("sp as destination");
			goto todo;
		} else {
			//put temprt -> destination register
			THUMB2_MOVW_REG(ts->transl_instr, rt, temprt);
			THUMB2_POP(ts->transl_instr, (1<< temprt) | (1<< temprn));
			return INS_PROCESSED;
		}
	}

	//rn is not pc.  rt is pc

	/* push temp registers */
	THUMB2_PUSH(ts->transl_instr, (1<< temprt) | (1<< temprn));

	tempinsn = (tempinsn & (~0xf000)) | (temprt<<12);
	//patch original instruction
	THUMB2_RAW(ts->transl_instr, tempinsn);

	//indirect jump. target is in temprt
	u4 jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, temprt);
	gen_ijump_reg_thumb(ts, temprt, jump_prologue_offset - 4);
	gen_ijump_reg_thumb_epilogue(ts, -1);

	//restore temp register
	// wback can be true only for imm8!!
	bool wback = false;

	switch ((insn >> 8) & 0xf) {
		case 0x9:
		case 0xb:
			wback = true;
			break;
	}

	if ((wback) && (rn_sp)) {
		BT_DEBUG("sp as base and write back");
		goto todo;
	}

	//sp = sp + 4
	THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);

	if (wback) {
		//temprn -> rn
		THUMB2_MOVW_REG(ts->transl_instr, rn, temprn);
	}
	//restore temp register
	THUMB2_POP(ts->transl_instr, (1<< temprt) | (1<< temprn));

	//load target into pc
	//target = [sp - 12]
	// index: true, add: false, wb: false
	THUMB2_LDRW_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_SP, 12, 1, 0, 0);
	return INS_PROCESSED | INS_INDIRECT_JUMP;



todo:
	//other case: use sp as base register
	BT_ERR(true, "todo thumb2 instruction 0x%-8x ", insn);
	return INS_TODO;
}

bool is_thumb2_insn(u4 insn) {
	u4 bits_15_12 = insn >> 12;

	if ((bits_15_12 == 15) || ((bits_15_12 == 14) &&  (insn & (1 << 11)))) {
		return true;
	}
	return false;
}

/* LLDD/FLDMD/FLDMS/FLDMX/FLDS  FSTD/FLTMD/FLTMS/FLTMX/FSTS C3-14 */
#ifdef DO_UAF_DETECT
void verify_fldst_vfp_thumb(struct translate *ts, u4 insn, u4 pc_value) {
	u4 rn = (insn >> 16) & 0xf;
	//u4 fd = (insn >> 12) & 0xf;
	u4 imm8 = insn & 0xff;
	//u4 cpnum = (insn >> 8) & 0xf;
	u4 puw = ((insn >> 22) & 0x6) | ((insn >> 21) & 0x1);
	//u4 add = (insn >> 20) & 0x1;
	//
	if(rn == ARMREG_SP || rn == ARMREG_PC){
		return;
	}

	if(puw == 0){
		UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x error", FILE, LINE, insn, pc_value);
		return;
	}
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP) | (1<<ARMREG_LR));
	/* push {r0, r1, r2, r3} */
	THUMB2_PUSH(ts->transl_instr, 0xf);

	UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x imm=0x%x", FILE, LINE, insn, pc_value, (imm8 << 2));
	
	switch(puw) {
		case 0x1: // post-indexed
			/* start_addr = rn */
		case 0x2: // Unindexed
			/* start_addr = rn */
		case 0x3: // post-indexed
			/* start_addr = rn */
			if(rn != ARMREG_R0){
				THUMB2_MOVW_REG(ts->transl_instr, ARMREG_R0, rn);
			}
			break;
		case 0x4: // Negative offseta
				/* addr = rn - offset * 4 */
		case 0x5: // pre-indexed
				/* start_addr = rn - offset * 4 */
				THUMB2_SUBW_IMM12(ts->transl_instr, ARMREG_R0, rn, (imm8 << 2));
				break;
		case 0x6: // Positive offset
				/* addr = rn + offset * 4 */
		case 0x7: // pre-indexed
				/* start_addr = rn + offset * 4 */
				THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, (imm8 << 2));
				break;
		default:
				UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x error", FILE, LINE, insn, pc_value);
				break;
	}
	THUMB2_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP));
	
	
	/* Do check */
#ifdef DEBUG_UAF_CHECK
	gen_put_reg_imm32(ts, ARMREG_R1, UAF_CHECK_ADDR_VFP_THUMB);
#endif
	gen_put_reg_imm32(ts, ARMREG_R2, (u4)addr_check);
	THUMB_BLX(ts->transl_instr, ARMREG_R2);
	
	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP));
	/* put ip -> apsr */
	//0x8: means nzcvq
	THUMB2_MSR_REG(ts->transl_instr, ARMREG_IP, 0x8);
	/* pop {r0, r1, r2, r3} */
	THUMB2_POP(ts->transl_instr, 0xf);
	/* pop to ip again */
	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP)| (1<<ARMREG_LR));
}
#endif
/* for future extension */
ins_type gen_coproc_insn(struct translate *ts, u4 insn, u4 pc_value) {
	int cpnum = (insn >> 8) & 0xf;
	ins_type ret = INS_TODO;

	switch (cpnum) {
		case 10:
		case 11:
			/* vfp */
			//ret = INS_COPY | INS_VFP;
			ret = INS_VFP;
			if(((insn >> 20) & 0x2) != 0x0) {
				ret |= INS_COPY;
				break;
			}
			if(((insn >> 8) & 0xa) != 0xa) {
				ret |= INS_COPY;
				break;
			}
			//u4 rd = (insn >> 12) & 0xf;
			u4 rn = (insn >> 16) & 0xf;
			//u4 offset = insn & 0xff;

			if(rn != ARMREG_PC)
			{
				ret |= INS_COPY;
				break;
			}

			/* reserve three temp registers (even 2 registers are enough for ldr imm) */
			u4 temprn = get_reg((1<<rn) | (1<<rn) | (1<<rn), 10);

			/* push temp registers */
			THUMB2_PUSH(ts->transl_instr, (1<< temprn));

			gen_put_reg_imm32(ts, temprn, pc_value & (~0x3));

			u4 tempinsn = (insn & (~(0xf << 16))) | (temprn << 16);

			THUMB2_RAW(ts->transl_instr, tempinsn);

			THUMB2_POP(ts->transl_instr, (1 << temprn));
			ret |= INS_PROCESSED;
			break;
		case 15:
			/* MRC */
			ret = INS_COPY;
			break;
		default:
			goto illegal;
	}

	return ret;

illegal:
	BT_ERR(true, "illegal thumb2 instruction 0x%-8x ", insn);
	return INS_TODO;
}



/*
 *  For conditional branch:
 *
 *      db03        blt.n   1ebd2 <vsnprintf+0x26>
 *
 *   ----->
 *
 *      bge  end
 *            xxxx -> generated indirect jump
 *      .end
 *
 *   We need to translate other instructions if branch
 *   is not taken. So we need to put something from .end
 *
 */

void gen_call_translate_function(struct translate *ts, u4 original_pc) {
	unsigned translate_bridge = (u4)fbt_translate_noexecute_bridge;

	ALIGN_4bytes(ts->transl_instr);

	//push r0, r1, r2, ip
	THUMB2_PUSH(ts->transl_instr, 0x7 | (1<<ARMREG_IP) | (1<<ARMREG_LR));

	/*
	 * we are in thumb mode now. target mode is also thumb
	 * so we set last bit to 1 so that fbt_translate_noexecute_bridge() will
	 * know that the jump target is in thumb mode.
	 *
	 */
	gen_put_reg_imm32(ts, ARMREG_R0, original_pc | 1);
	gen_put_reg_imm32(ts, ARMREG_R1, (u4)(ts->tld));
	gen_put_reg_imm32(ts, ARMREG_R2, (u4)translate_bridge);

	//call function, bx r2
	THUMB_BLX(ts->transl_instr, ARMREG_R2);

	// //r2 = r0 = translated code address
	// THUMB2_MOVW_REG(ts->transl_instr, ARMREG_R2, ARMREG_R0);

	//now r0 = translated code address. push r0 into stack
	THUMB_PUSH(ts->transl_instr, 1<<ARMREG_R0, 0);

	ALIGN_4bytes(ts->transl_instr);

	//add stack +4
	THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);

	//pop registers
	THUMB2_POP(ts->transl_instr, 0x7 | (1<<ARMREG_IP)| (1<<ARMREG_LR));

	//jump to translated code cache
	//load target into pc
	//target = [sp - 20]
	// index: true, add: false, wb: false
	THUMB2_LDRW_IMM8(ts->transl_instr, ARMREG_PC, ARMREG_SP, 20, 1, 0, 0);
}



/* the dumped buffer can be disassembled by ODA
 *
 * http://www.onlinedisassembler.com/odaweb/run_hex
 *
 *
 */

//#define DIS_THUMB_INSTRUCTION

#ifdef  DIS_THUMB_INSTRUCTION
char dump_buffer[1024];
static void dump_translated_buffer(unsigned char * buf_start, u4 size) {
	unsigned char * c_buf;
	u4 index = 0;
	u4 temp_insn;

	for (c_buf = buf_start; c_buf < buf_start + size; ) {
		temp_insn = *(u2*)(c_buf);

		if (is_thumb2_insn(temp_insn)) {
			temp_insn = (temp_insn << 16) | *(u2*)(c_buf + 2);
			c_buf += 4;
		} else {
			c_buf += 2;
		}

		index += sprintf(dump_buffer + index, "%x ", temp_insn);

	}

	BT_DEBUG_CLEAN("[DIS] %s", dump_buffer);
}



/* disassemble translated instruction */
static void disassemble_translated_buffer(unsigned char * buf_start, u4 size) {
	u4 temp_insn;
	unsigned char * c_buf;

	for (c_buf = buf_start; c_buf < buf_start + size; ) {
		temp_insn = *(u2*)(c_buf);
		if (is_thumb2_insn(temp_insn)){
			temp_insn = (temp_insn << 16) | *(u2*)(c_buf + 2);
			dis_thumb2_instruction((u4)c_buf, temp_insn);
			c_buf += 4;
		} else {
			dis_thumb_instruction((u4)c_buf, (u2)temp_insn);
			c_buf += 2;
		}
	}
}
#endif


static void thumb_debug_translation(struct translate *ts,
		unsigned char * old_transl_instr, u4 insn) {
#ifdef  DIS_THUMB_INSTRUCTION
	if (is_thumb2_insn(insn)){
		u2 insn_lw = *((u2 *)((u4)ts->cur_instr));
		insn = (insn << 16) | insn_lw;

		BT_DEBUG_CLEAN("[DIS] original instruction 0x%-8x: 0x%-8x",
				(u4)ts->cur_instr - 2, insn);
		/* disassemble original instruction */
		dis_thumb2_instruction((u4)ts->cur_instr - 2, insn);
	} else {
		BT_DEBUG_CLEAN("[DIS] original instruction 0x%-8x: 0x%-8x",
				(u4)ts->cur_instr, insn);
		/* disassemble original instruction */
		dis_thumb_instruction((u4)ts->cur_instr, insn);
	}

	BT_DEBUG_CLEAN("[DIS]\t------------> ");

	dump_translated_buffer(old_transl_instr, (u4)(ts->transl_instr) -
			(u4)old_transl_instr);

	/* disassemble translated instruction */
	disassemble_translated_buffer(old_transl_instr, (u4)(ts->transl_instr) -
			(u4)old_transl_instr);

	BT_DEBUG_CLEAN("[DIS]\n\n");
#endif
}

#ifdef DO_UAF_DETECT
void verify_ldstwb_thumb2(struct translate *ts, u4 insn, u4 pc_value) {
	u4 rn = (insn >> 16) & 0xf;
	//u4 rt = (insn >> 12) & 0xf;
	if(rn == ARMREG_SP || rn == ARMREG_PC)
		return;
	u4 imm12 = insn & 0xfff;
	u4 imm8 = insn & 0xff;

	u4 type = (insn >> 25) & 0x7f;
	//u4 size = (insn >> 21) & 0x3;

	if((type & 0x74) != 0x74){
		return;
	}
	u4 shift, rm;

	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP) | (1<<ARMREG_LR));
	/* push {r0, r1, r2, r3} */
	THUMB2_PUSH(ts->transl_instr, 0xf);

	UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x imm5=0x%x", FILE, LINE, insn, pc_value, imm8);
	switch(type) {
		case 0x7c: /* Load and store single data item, memory hints 3-26 */
			if(rn == 0xf) {
				/*
				 * PC +/- imm12 or Reserved
				 */
				break;
			}
			if((insn >> 23) & 0x1) {
				/*
				 * Rn + imm12
				 */
				THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm12);
			} else {
				switch((insn >> 8) & 0xd){
					case 0x0:
						if(((insn >> 6) & 0x3f) == 0) 
						{
							/* Rn + shifted register 
							 * LDR<c>.W <Rt>, [<Rn>, <Rm>{, LSL, $<shift>}]
							 * */
							shift = (insn >> 4) & 0x3;
							rm = insn & 0xf;
							THUMB2_ADDW_REG(ts->transl_instr,ARMREG_R0, rn, rm, SHIFT_LSL, shift);	
						}
						break;
					case 0xc:
						if((insn >> 9) & 0x1){ /* Rn + imm8, User privilege */
							THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
						} else { /* Rn - imm8 */
							THUMB2_SUBW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
						}
						break;
					case 0x9: /* Rn post-indexed by +/- imm8 */
					case 0xd: /* Rn pre-indexed by +/- imm8 */
						if(insn & 0x100) { // ADD
							THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
						} else {
							THUMB2_SUBW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
						}
						break;
					default: /* Reserved */
						UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x revserved address", FILE, LINE, insn, pc_value);
						break;
				}
			}
			break;
		case 0x74:
			if (insn & (0x1 << 22)) { 
				/* Load and Store, Double and Exclusive, and Table Branch 3-28 */
				//rt2 = (insn >> 8)&0xf;
				if( insn & (0x9 << 21)) { /* PW!=0b00, Load and Store Double 4-114 */
					/* LDRD<c> <Rt>, <Rt2>, [<Rn>, #+/-<imm>]{!} 
					 * LDRD<c> <Rt>, <Rt2>, [<Rn>], #+/-<imm>
					 * */
					if(insn & (0x1 << 23)){ // ADD
						THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
					} else { // SUB
						THUMB2_SUBW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
					}
				} else {
					if((insn >> 23) & 0x1) { 
						/* Load and Store Exclusive Bytes ... 
						 * LDREXB<c> <Rt>, [<Rn>]
						 * LDREXD<c> <Rt>, <Rt2>, [<Rn>]
						 * LDREXH<c> <Rt>, [<Rn>]
						 * */
						if(rn != ARMREG_R0){
							THUMB2_MOVW_REG(ts->transl_instr, ARMREG_R0, rn);
						}
					} else { 
						/* Load and Store Exclusive 
						 * LDREX<c> <Rt>, [<Rn>{,#<imm>}]
						 * 4-116 */
						THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm8);
					}
				}
			} else { 
				/* Load and Store Multiple, RFE and SRS 3-30 */
				if(insn & (0x1 << 22)) {
					//Error
				} else {
				if(rn != ARMREG_R0) {
						THUMB2_MOVW_REG(ts->transl_instr, ARMREG_R0, rn);
					}
				}
			}
			break;
		default:
			UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x revserved address", FILE, LINE, insn, pc_value);
			break;
	}
	THUMB2_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP));
	
	/* Do check */
#ifdef DEBUG_UAF_CHECK
	gen_put_reg_imm32(ts, ARMREG_R1, UAF_CHECK_ADDR_THUMB2);
#endif
	gen_put_reg_imm32(ts, ARMREG_R2, (u4)addr_check);
	THUMB_BLX(ts->transl_instr, ARMREG_R2);


	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP));
	/* put ip -> apsr */
	//0x8: means nzcvq
	THUMB2_MSR_REG(ts->transl_instr, ARMREG_IP, 0x8);
	/* pop {r0, r1, r2, r3} */
	THUMB2_POP(ts->transl_instr, 0xf);
	/* pop to ip again */
	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP)| (1<<ARMREG_LR));
}
#endif
/*
 * In ARM instructions, a value of 0b1111 in a register specification
 * normally specifies the PC. This usage is not normally permitted
 * in Thumb-2.
 */
ins_type fbt_translate_instr_thumb2(struct translate *ts, u4 insn_hw) {
	TRACE_ENTER;
	unsigned char *cur = (ts->cur_instr = ts->next_instr);

	u2 insn_lw = *((u2 *)cur);
	u4 insn = insn_lw;
	u4 rn, rs, rd, rm, imm, op;
	u4 load;

	/* this must be signed type!!!*/
	s4 offset;

	u4 jump_address = 0;

	insn |= (insn_hw << 16);
	/* add another 2 bytes */
	ts->next_instr = cur + 2;

	rn = (insn >> 16) & 0xf;
	rs = (insn >> 12) & 0xf;
	rd = (insn >> 8) & 0xf;
	rm = insn & 0xf;

	ins_type ret = 0;

	/*
	 *  c7a:    f7ff efc6
	 *
	 *  the pc value at c7a is c7a + 4 = c7e.
	 *
	 *  since it's thumb2 instruction, we already added 2 when entering this
	 *  function. So we just need to add another 2 bytes!!!
	 *
	 */
	u4 pc_value = (u4)(ts->cur_instr) + 2;
	u4 addr;
	u4 temp_reg, temp_reg1;
	u4 temp_insn;

	u4 jump_prologue_offset = 0;

	// unsigned char * old_transl_instr = ts->transl_instr;

	switch ((insn >> 25) & 0xf) {
		case 0:
		case 1:
		case 2:
		case 3:
			/* 16-bit instructions.  Should never happen.  */
			goto illegal;
		case 4:
#ifdef DO_UAF_DETECT
			verify_ldstwb_thumb2(ts, insn, pc_value);
#endif
			load = (insn & (1 << 20));
			if ((insn & (1 << 22))) {
				/* see 3-28 in doc2 */
				/* Load/store doubleword.  */

				if ((insn & 0x01200000)) {
					/* Load/store doubleword.  */
					/* ldrd <rs>, <rd>, [rn, #imm]
					 *
					 * rs/rd can not be pc. rn can be pc
					 */

					ret = INS_COPY;

					/* for store, all registers can not be pc
					 * for load, base register can be pc. (and wback can not be true)
					 */
					if ((load) && (rn == 15)) {

						if (insn & (1 << 21)) {
							goto illegal;
						}
						// offset = (insn & 0xff) * 4;
						// if ((insn & (1 << 23)) == 0)
						//     offset = -offset;

						/* PC based load or store*/
						// addr = (pc_value & (~0x3)) + offset;

						//put pc to rd (or rs)
						gen_put_reg_imm32(ts, rd, (pc_value & (~0x3)));
						/*patch rn as rd*/
						temp_insn = ((insn & (~0xf0000)) | (rd << 16));
						/* ldrd <rs>, <rd>, [rd], +/ imm  */
						THUMB2_RAW(ts->transl_instr, temp_insn);

						ret = INS_PC_RELATIVE_LOAD | INS_PROCESSED;
					}

				} else if ((insn & (1 << 23)) == 0) {
					/* Load/store exclusive word.  */
					/* LDREX<c> <rs>,[<Rn>{,#<imm>}] */
					//rn/rs can not be reg 15. so its ok
					ret = INS_COPY | INS_LOAD;
				} else if ((insn & (1 << 6)) == 0) {
					/* Table Branch. */
					/* target branch is also implicit jumping */


					temp_reg = get_reg((1<<rn) | (1<<rm) , 10);
					temp_reg1 = get_reg((1<<rn) | (1<<rm) | (1<<temp_reg) , 10);

					jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, temp_reg1);

					//two temp regs are pushed
					jump_prologue_offset += 8;

					THUMB2_PUSH(ts->transl_instr, (1<<temp_reg) | (1<<temp_reg1));

					//TBB.W [Rn, Rm]
					//TBH.W [RN, RM, LSL #1]
					addr = pc_value;
					/*
					 *  tricky: here, we need to put last bit of target to 1
					 *  so that when jumping back from trampoline (arm) it can
					 *  switch back to THUMB mode
					 *
					 */
					//pc + 1 -> temp_reg1
					gen_put_reg_imm32(ts, temp_reg1, addr + 1);

					// rn -> temp_reg
					if (rn == 15) {
						/* pc -> temp_reg */
						gen_put_reg_imm32(ts, temp_reg, addr);
					} else {
						/* mov temp_reg, rn */
						THUMB2_MOVW_REG(ts->transl_instr, temp_reg, rn);
					}

					//now  reg[temp_reg]  == reg[rn]
					if (insn & (1 << 4)) {
						/* tbh */
						//LDRH.W temp_reg [temp_reg, rm, LSL 1]
						THUMB2_LDRH_REG(ts->transl_instr, temp_reg, temp_reg, rm, 1);
					} else {
						/* tbb */
						//LDRb.W temp_reg [temp_reg, rm]
						THUMB2_LDRB_REG(ts->transl_instr, temp_reg, temp_reg, rm, 0);
					}

					//put destination address into temp_reg1
					//PC = PC + 2* MEM[REG[RN] + REG[RM]]
					// reg[temp_reg1] = pc, reg[temp_reg]= MEM[REG[RN] + REG[RM]]
					THUMB2_ADDW_REG(ts->transl_instr,temp_reg1, temp_reg1, temp_reg, SHIFT_LSL, 1);

					//now jump target is in temp_reg1
					//jump! it's ok to use thumb jump function.
					gen_ijump_reg_thumb(ts, temp_reg1, jump_prologue_offset - 4);

					//make code cache is 4 bytes aligned since we generate thumb instructions before.
					ALIGN_4bytes(ts->transl_instr);

					//ok. pop registers
					THUMB2_POP(ts->transl_instr, (1<<temp_reg) | (1<<temp_reg1));
					gen_ijump_reg_thumb_epilogue(ts, 0);

					return INS_INDIRECT_JUMP | INS_PROCESSED;
				} else {
					/* Load/store exclusive byte/halfword/doubleword.  */
					// destination/src reg can not be pc
					op = (insn >> 4) & 0x3;
					if (op == 2) {
						goto illegal;
					}
					ret = INS_COPY | INS_LOAD;
				}
			} else {
				/* Load/store multiple, RFE, SRS.  */
				if (((insn >> 23) & 1) == ((insn >> 24) & 1)) {
					/* RFE, SRS.*/
					/* Not available in user mode.  */
					goto illegal;
				} else {

					if (insn & (1 << 21)) {
						/* Base register writeback.  */
						if (insn & (1 << rn)) {
							/* Fault if writeback register is in register list.  */
							goto illegal;
						}
					}

					/* Load/store multiple.  */
					if (load) {
						/* LDMDB/LDMEA*/
						/* LDMIA/LDMFD */
						/*
						 *  pc can be destination register!! see 4-96 in doc2
						 *  pc can NOT be base register
						 */
						ret = gen_multi_load(ts, insn);
						// if (insn & (1<< ARMREG_PC)) {
						//     gen_multi_load(ts, insn, rn, insn & 0xffff);
						// } else {
						//     //just load. pc is not in regelist
						//     ret = INS_LOAD | INS_COPY;
						// }
					} else {
						/* store */
						/* STMDB / STMFD */
						/* STMIA / STMEA */
						//pc can not be base register!
						//pc can not be in reg list!!
						ret = INS_STORE | INS_COPY;
					}
				}
			}
			break;

		case 5:
			op = (insn >> 21) & 0xf;
			if (op == 6) {
				/* Halfword pack.  */
				/* it's ok since destination reg can not be pc */
				ret = INS_COPY;
			} else {
				/* Data processing register constant shift. 3-18 in doc2  */
				// if ((op == 0x8) || (op == 13) || (op == 4) || (op ==0)) {
				//     if ((rd == ARMREG_PC) && (1<< 20)) {
				//         //ADD WITH RD = 15, S = 1 -> CMP (register)
				//         //SUB WITH RD = 15, S = 1 -> CMP (register)
				//         //EOR WITH RD = 15, S = 1 -> TEQ (register)
				//         //AND WITH RD = 15, S = 1 -> TST (register)
				//         ret = INS_NORMAL;
				//     }
				// } else if (rd == ARMREG_PC) {
				//     BT_ERR(true, "TODO** destination is 15. instruction 0x%-8x", insn);
				// }
				//every instruction is ok except MOV. the destination can be pc
				if ((op == 2) && ((insn & 0x70c0) == 0x0) && (rd == 15)) {
					//MOV rd, rm
					//implicit jump. rm can not be 13 here when rd ==15 . See 4-168 in doc2
					//destination is in rm
					jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, rm);
					gen_ijump_reg_thumb(ts, rm, jump_prologue_offset - 4);
					gen_ijump_reg_thumb_epilogue(ts, 0);
					ret = INS_INDIRECT_JUMP | INS_PROCESSED;
				} else {
					ret = INS_COPY;
				}
			}
			break; //case 5

		case 13:
			/* Misc data processing.   */
			op = ((insn >> 22) & 6) | ((insn >> 7) & 1);
			if (op < 4 && (insn & 0xf000) != 0xf000) {
				goto illegal;
			}
			switch (op) {
				case 0:
					/* Register controlled shift. see 3-19 in doc2 */
					/* src/dst can not be pc. So its' ok */
				case 1:
					/* Sign/zero extend.  */
					/*it's fine*/
				case 2:
					/* SIMD add/subtract.  */
					/*it's fine*/
				case 3:
					/* Other data processing.  */
				case 4:
				case 5:
					/* 32-bit multiply.  Sum of absolute differences.  */
					ret = INS_COPY;
					break;
				case 6:
				case 7: /* 64-bit multiply, Divide.  */
					/* Coprocessor.  */
					// goto illegal;
					ret = INS_COPY;
					break;
			}
			break;
		case 6:
		case 7:
		case 14:
		case 15:
			if (((insn >> 24) & 3) == 3) {
				/* neon */
				ret = INS_NEON;
			} else {
				/* Coprocessor.  */
				if(((insn >> 25) & 0x7) == 0x6) {
#ifdef DO_UAF_DETECT
					verify_fldst_vfp_thumb(ts, insn, pc_value);
#endif
				}
				ret = gen_coproc_insn(ts, insn, pc_value);
			}
			break;
		case 8:
		case 9:
		case 10:
		case 11:
			if (insn & (1 << 15)) {
				/* Branches, misc control.  see 3-31 in doc2*/
				if (insn & 0x5000) {
					/* unconditional branch */
					/* signextend(hw1[10:0]) -> offset[:12].  */
					offset = ((s4)insn << 5) >> 9 & ~(s4)0xfff;
					/* hw1[10:0] -> offset[11:1].  */
					offset |= (insn & 0x7ff) << 1;
					/* (~hw2[13, 11] ^ offset[24]) -> offset[23,22]
						 offset[24:22] already have the same value because of the
						 sign extension above.  */
					offset ^= ((~insn) & (1 << 13)) << 10;
					offset ^= ((~insn) & (1 << 11)) << 11;

					jump_address = pc_value + offset;

					/*
					 *  For b, it's branchWithPC. So we need to apply 1 to last
					 *  bit so that when jumping back from trampoline, it will
					 *  switch to thumb mode.
					 *
					 *
					 *  For bl, the target mode is Thumb. So we also need to
					 *    apply 1 to last bit
					 *
					 *  For blx, the target mode is ARM. So it is ok.
					 *         because when jumping back from trampoline,
					 *         the jump target in code cache is already 4 bytes aligned.
					 *
					 *
					 */
					if (insn & (1 << 12)) {
						//b/bl.
						/* set last bit as 1 */
						jump_address |= 0x1;
					} else {
						//blx
						jump_address &= ~(u4)2;
					}
					//bit 14  = 1
					if (insn & (1 << 14)) {
						//bl/blx
						//todo: optimization: instead of set lr as original
						//lr, we can put the real address in code cache to lr
						//now. we just put the original value into reg 14

						// pc_value = (u4)(ts->cur_instr) + 2.
						// already points to next thumb instruction.
						// also we need to change last bit to 1 so that
						// bx lr will switch to correct mode.
						// see page A8-59 on doc. set last bit of lr to 1.
						gen_put_reg_imm32(ts, ARMREG_LR, (u4)(pc_value | 1));
					}

					//now jump to target
					gen_jump_thumb(ts, jump_address, 0xf000 ,1);

					ret = INS_DIRECT_JUMP | INS_PROCESSED;
				} else if (((insn >> 23) & 7) == 7) {
					/* Misc control */
					/* not implementation */
					goto illegal;
				} else {
					/* Conditional branch.  */

					/* offset[11:1] = insn[10:0] */
					offset = (insn & 0x7ff) << 1;
					/* offset[17:12] = insn[21:16].  */
					offset |= (insn & 0x003f0000) >> 4;
					/* offset[31:20] = insn[26].  */
					offset |= ((int32_t)((insn << 5) & 0x80000000)) >> 11;
					/* offset[18] = insn[13].  */
					offset |= (insn & (1 << 13)) << 5;
					/* offset[19] = insn[11].  */
					offset |= (insn & (1 << 11)) << 8;

					jump_address = pc_value + offset;

					u4 cond = (insn >> 22) & 0xf;
					u4 notcond = cond ^ 1;

					/* if not condition, then jump to end*/
					/* offset will be patched later*/
					u4 original_transl = (u4)(ts->transl_instr);

					THUMB2_CONB_IMM20(ts->transl_instr, notcond, 0);

					/* condition == true, then jump to jump_address*/
					//set last bit of jump_target as 1
					// so that when jumping back from trampoline (Arm mode), the mode
					// can be changed to thumb automatically
					jump_address |= 0x1;
					gen_jump_thumb(ts, jump_address, 0x0, 1);

					//now patch the offset.
					u4 toffset = (u4)ts->transl_instr - original_transl;

					BT_DEBUG(" transl 0x%x - 0x%x", (u4)original_transl, (u4)ts->transl_instr);


					toffset = (toffset - 4) >> 1;

					BT_DEBUG("toffset 0x%x", toffset);

					//caution: be careful with the higher and lower bits of thumb2
					//instruction!!! see THUMB2_EMIT
					// 8bits offset is enough.
					/* why do we need to << 16 of the offset?
					 * because lower 16 bits of thumb2 instruction is
					 * on high address in memory. see THUMB2_EMIT
					 */

					BT_DEBUG("before patched insn 0x%x",  *(u4 *)original_transl);
					*(u4 *)original_transl = (*(u4 *)original_transl)
						| ((toffset & 0xff) <<16);

					BT_DEBUG("after patched insn 0x%x",  *(u4 *)original_transl);

					ret = INS_DIRECT_JUMP | INS_PROCESSED | INS_CONDITIONAL_JUMP;
				}
			} else { /* 1<< 15*/
				/* Data processing immediate.  */
				if (insn & (1<<25)) {
					if (insn & (1<<24)) {
						if (insn & (1<<20))
							goto illegal;
						/* Bitfield/Saturate.  */
						op = (insn >> 21) & 7;
						imm = insn & 0x1f;
						//shift = ((insn >> 6) & 3) | ((insn >> 10) & 0x1c);
						switch (op) {
							case 2:
								/* Signed bitfield extract.  */
							case 6:
								/* Unsigned bitfield extract.  */
							case 3:
								/* Bitfield insert/clear.  */
								/* IF RN=15, -> BFC */
								ret = INS_COPY;
								break;
							case 7:
								goto illegal;
							default: /* Saturate.  */
								ret = INS_COPY;
								break;
						}
					} else { /* bit 24 == 0*/
						/* bit 24 = 0. see 3-13 in doc2. 3-15 */
						imm = ((insn & 0x04000000) >> 15)
							| ((insn & 0x7000) >> 4) | (insn & 0xff);
						if (insn & (1 << 22)) {
							//16 bits imm
							/* movt */
							/* movw */
							ret = INS_COPY;
						} else {
							/* Add/sub 12-bit immediate.  */
							if (rn == 15) {
								/*adr. see 4-28 in doc2*/
								imm = ((insn & 0x04000000) >> 15)
									| ((insn & 0x7000) >> 4) | (insn & 0xff);
								offset = pc_value & ~(uint32_t)3;
								if (insn & (1 << 23))
									offset -= imm;
								else
									offset += imm;
								//put into reg rd
								gen_put_reg_imm32(ts, rd, offset);
								ret = INS_PC_ALU | INS_PROCESSED;
							} else {
								ret = INS_COPY;
							}
						}
					}
				}  else { //bit 25 == 0
					/* modified 12-bit immediate.  */
					/* SEE 3-14 in doc2*/
					ret = INS_COPY;
				}
			}
			break;
		case 12:
#ifdef DO_UAF_DETECT
			verify_ldstwb_thumb2(ts, insn, pc_value);
#endif
			/* Load/store single data item.  */
			if ((insn & 0x01100000) == 0x01000000) {
				goto illegal;
			}
			//op: S:Size
			op = ((insn >> 21) & 3) | ((insn >> 22) & 4);
			// if (insn & (1<< 20)) {
			//     ret = INS_LOAD;
			// } else {
			//     ret = INS_STORE;
			// }
			if (rs == 15) {
				if (!(insn & (1 << 20))) {
					goto illegal;
				}

				if (op != 2) {
					/* Byte or halfword load space with dest == r15 : memory hints.
					 * Catch them early so we don't emit pointless addressing code.
					 * This space is a mix of:
					 *  PLD/PLDW/PLI,  which we implement as NOPs (note that unlike
					 *     the ARM encodings, PLDW space doesn't UNDEF for non-v7MP
					 *     cores)
					 *  unallocated hints, which must be treated as NOPs
					 *  UNPREDICTABLE space, which we NOP or UNDEF depending on
					 *     which is easiest for the decoding logic
					 *  Some space which must UNDEF
					 */
					if (op & 2) {
						goto illegal;
					}
					if (rn == 15) {
						/* UNPREDICTABLE, unallocated hint or
						 * PLD/PLDW/PLI (literal)
						 */
						return INS_SKIP;
					}
					int op1 = (insn >> 23) & 3;
					int op2 = (insn >> 6) & 0x3f;

					if (op1 & 1) {
						return INS_SKIP; /* PLD/PLDW/PLI or unallocated hint */
					}
					if ((op2 == 0) || ((op2 & 0x3c) == 0x30)) {
						return INS_SKIP; /* PLD/PLDW/PLI or unallocated hint */
					}
					/* UNDEF space, or an UNPREDICTABLE */
					goto undefined;
				}
			}

			ret = gen_ldst(ts, insn, pc_value);

			//rn : base reg.  rs: target reg
#if 0
			if (rn == 13) {
				//sp as base register!!!
				BT_DEBUG("sp as base");
				goto todo;
			}
			//load
			if (insn & (1 << 20)) {
				if (rn == 15) {
					/* PC Relative load.*/
					if (rn == 15) {
						imm = pc_value & 0xfffffffc;
						if (insn & (1 << 23))
							imm += insn & 0xfff;
						else
							imm -= insn & 0xfff;
					}

					//we have put destination in imm
					/* indirect jump */
					if (rs == 15) {
						//jump to imm
						gen_jump_thumb(ts, imm, 0x0, 1);
						ret = INS_PC_RELATIVE_LOAD | INS_INDIRECT_JUMP | INS_PROCESSED;
					} else {
						//put value into reg rs
						gen_put_reg_imm32(ts, rs, imm);
						ret = INS_PC_RELATIVE_LOAD | INS_PROCESSED;
					}
				} else {
					//rn != 15 and rs = 15. indirect jump
					if (rs == 15) {
						//put jump target into another register.
						temp_reg = get_reg((1<<rn), 10);

						jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts);

						//1. push temp_reg
						THUMB2_PUSH(ts->transl_instr, 1 << temp_reg);
						jump_prologue_offset += 4;

						//patch instruction to change rs == temp_reg
						u4 temp_insn = (insn & (~0xf000)) | (temp_reg<<12);
						THUMB2_RAW(ts->transl_instr, temp_insn);
						//now temp_Reg : jump target
						gen_ijump_reg_thumb(ts, rm, jump_prologue_offset - 4);
						//pop reg
						THUMB2_POP(ts->transl_instr, 1 << temp_reg);
						gen_ijump_reg_thumb_epilogue(ts, 0);

						ret = INS_INDIRECT_JUMP | INS_PROCESSED;
					} else {
						ret = INS_COPY;
					}
				}

			} else {
				//store
				ret = INS_STORE | INS_COPY;
			}
#endif
			break;//case 12
		default:
			goto illegal;
	} //switch

	// BT_DEBUG("ret  0x%-8x ", ret);

	/* now process the instruction according to ret */
	if (ret & INS_COPY) {
		//be cautious about the sequence.  high 16 bits in lower address!!
		THUMB_EMIT(ts->transl_instr, insn_hw);
		THUMB_EMIT(ts->transl_instr, insn_lw);
	}

	//thumb2_debug_translation(ts, old_transl_instr, insn);
	TRACE_EXIT;
	return ret;

	//todo:
	//    BT_ERR(true, "todo thumb2 instruction 0x%-8x ", insn);
illegal:
	BT_ERR(true, "illegal thumb2 instruction 0x%-8x ", insn);
undefined:
	BT_ERR(true, "undefined thumb2 instruction 0x%-8x ", insn);
	return INS_TODO;
}



static bool it_block_prologue(struct translate *ts, bool * jump) {
	if (ts->it_cur_num > 0) {
		u4 cond = ts->condexec_cond[ts->it_index];

		BT_DEBUG("cond 0x%x ", cond);

		if (cond != 0xe) {
			u4 notcond = cond ^ 1;
			/* if not condition, then jump to end*/
			/* offset will be patched later*/
			// BT_DEBUG("original_transl 0x%x ", original_transl);
			THUMB_CONB_IMM(ts->transl_instr, notcond, 0);
			*jump = true;
		}

		ts->it_index += 1;

		ts->it_cur_num -= 1;

		return true;
	}
	return false;
}

static bool it_block_epilogue(struct translate *ts, bool ret, bool special_thumb) {

	if ((ret == INS_COPY) || (special_thumb == true)) {
		ts->insn_changed[ts->it_index-1] = false;
	}
	int i = 0;

	/* last instruction in it block */
	if (ts->it_cur_num == 0) {
		for (i = 0; i < ts->it_total_num; i ++) {
			if (ts->insn_changed[i] == true)
				break;
		}

		if (i == ts->it_total_num) {
			/* all instructions are unchanged! */
			/* we need to restore original it block! */

			/*
			 *  ts->next_instr: points to (original) next instruction of it block
			 *  ts->it_instr: points to (original) it instruction
			 *  ts->it_transl_instr: points to translated it block
			 */

			BT_DEBUG("[it] ts->next_instr 0x%x  ts->it_instr 0x%x", (u4)ts->next_instr,
					(u4)ts->it_instr);
			u4 size = ts->next_instr - ts->it_instr;
			u4 occupied_size = ts->transl_instr - ts->it_transl_instr;

			BT_DEBUG("[it] ts->transl_instr 0x%x  ts->it_transl_instr 0x%x", (u4)ts->transl_instr,
					(u4)ts->it_transl_instr);

			memcpy(ts->it_transl_instr, ts->it_instr, size);

			if (occupied_size > size) {
				/* reset other memory */
				memset(ts->it_transl_instr + size, 0xff, occupied_size - size);
			}

			//adjust ts->transl_instr
			ts->transl_instr = ts->it_transl_instr + size;

			//make it 4 bytes aligned?
			ALIGN_4bytes(ts->transl_instr);

			/*debug: dump the memory */
			for (i = 0; i < size; i += 2) {
				BT_DEBUG("[it] 0x%x: 0x%x", (u4)(ts->it_transl_instr + i),
						*(u2*)(ts->it_transl_instr + i));
			}

			return true;
		}
	}

	return false;
}


/* verify the address of the load/store intructions 
 * bits_15_12:	0x5			Load/store register offset
 *							0x6/0x7	Load/store	word/byte immediate offset
 *							0x8			Load/store	hafword immediate offset
 * */
#ifdef DO_UAF_DETECT
void verify_ldstwb_thumb(struct translate *ts, u2 insn, u4 pc_value) {
	u2 bits_15_12 = insn >> 12;
	u1 rd = insn & 0x7;
	u1 rn = (insn >> 3) & 0x7;

	if(rn == ARMREG_SP || rn == ARMREG_PC){
		return;
	}
	if(bits_15_12 < 0x5 || bits_15_12 > 0x8){
		return;
	}

	ALIGN_4bytes(ts->transl_instr);
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP) | (1<<ARMREG_LR));
	/* push {r0, r1, r2, r3} */
	THUMB_PUSH(ts->transl_instr, 0xf, 0);

	u2 rm = (insn >> 6) & 0x7;
	u2 imm5 = (insn >> 6) & 0x1f;

	UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x imm5=0x%x", FILE, LINE, insn, pc_value, imm5);

	switch(bits_15_12){
		case 0x5:
#if 0
			u2 opt = (insn_hw >> 9) & 0x7;
			switch (opt) {
				case 0x0: /* STR <Rd>, [<Rn>, <Rm>] */
				case 0x1: /* STRH <Rd>, [<Rn>, <Rm>] */
				case 0x2: /* STRB <Rd>, [<Rn>, <Rm>] */
				case 0x3: /* LDRSB <Rd>, [<Rn>, <Rm>] */
				case 0x4: /* LDR <Rd>, [<Rn>, <Rm>] */
				case 0x5: /* LDRH <Rd>, [<Rn>, <Rm>] */
				case 0x6: /* LDRB <Rd>, [<Rn>, <Rm>] */
				case 0x7: /* LDRSH <Rd>, [<Rn>, <Rm>] */
					break;
			}
#endif
			THUMB_ADD_REG_REG(ts->transl_instr, rd, rn, rm);
			break;
		case 0x6:
			/* bit11 == 1: LDR <Rd>, [<Rn>, #<immed_5> * 4]
				 STR <Rd>, [<Rn>, #<immed_5> * 4] */
			THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, (imm5<<2));
			break;
		case 0x7:
			/* bit11 == 1: LDRB <Rd>, [<Rn>, #<immed_5>]
0: STRB <Rd>, [<Rn>, #<immed_5>] */
			THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, imm5);
			break;
		case 0x8:
			/* bit11 == 1: LDRH <Rd>, [<Rn>, #<immed_5> * 2]
				 STRH <Rd>, [<Rn>, #<immed_5> * 2] */
			THUMB2_ADDW_IMM12(ts->transl_instr, ARMREG_R0, rn, (imm5<<1));
			break;
		default:
			UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x revserved address", FILE, LINE, insn, pc_value);
			break;
	}
	THUMB2_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	THUMB2_PUSH(ts->transl_instr, (1<<ARMREG_IP));
	
	/* Do check */
#ifdef DEBUG_UAF_CHECK
	gen_put_reg_imm32(ts, ARMREG_R1, UAF_CHECK_ADDR_THUMB);
#endif
	gen_put_reg_imm32(ts, ARMREG_R2, (u4)addr_check);
	THUMB_BLX(ts->transl_instr, ARMREG_R2);

	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP));
	/* put ip -> apsr */
	//0x8: means nzcvq
	THUMB2_MSR_REG(ts->transl_instr, ARMREG_IP, 0x8);
	/* pop {r0, r1, r2, r3} */
	THUMB_POP(ts->transl_instr, 0xf, 0);
	/* pop to ip again */
	THUMB2_POP(ts->transl_instr, (1<<ARMREG_IP)| (1<<ARMREG_LR));
}
#endif
/* since most thumb instruction can not access reg15, so it's ok
 * for most instruction
 */
ins_type fbt_translate_instr_thumb(struct translate *ts) {
	TRACE_ENTER;
	unsigned char *cur = (ts->cur_instr = ts->next_instr);

	u4 op, rm, rd, cond;
	// u4 jump_target;
	u4 load_address, origin_pc_value, val;
	u4 jump_address;
	u4 temp_reg;
	u4 rlist;

	/* this must be signed type!!!*/
	s4 offset;

	ins_type ret = INS_TODO;

	u4 jump_prologue_offset = 0;

	/* thumb2 instruction can be 4 bytes or 2 bytes. fetch first 2 bytes. */
	u2 insn_hw = *((u2 *)cur);

	u2 bits_15_12 = insn_hw >> 12;

	u4 insn = insn_hw;

	//u4 old_transl_instr = (u4)(ts->transl_instr);

	/* add 2 first */
	ts->next_instr = cur + 2;

	unsigned char * old_transl_instr = ts->transl_instr;

	BT_DEBUG("translating instruction [0x%-8x-0x%-4x]", (u4)cur, insn);

	u4 original_transl = (u4)(ts->transl_instr);
	bool condjmp = false;

	/* is it special thumb instruction which has different meanings
	 * in a IT block?
	 */
	bool special_thumb = false;

	bool in_it_block = it_block_prologue(ts, &condjmp);


#ifdef BDB_DEBUGGER
	gen_enter_debugger_thumb(ts);

	/* mapping between pc of translated code (except debugger trampoline) and original pc */
	send_pc_mapping((u4)ts->cur_instr, (u4)ts->transl_instr);

#endif

	/* here we only care two types of instructions:
	 *   (1) load and store
	 *   (2) (indirect) jump
	 */

	switch (bits_15_12) {
		case 0:
		case 1:
		case 2:
		case 3:

#ifdef BDB_DEBUGGER
			/* This is right, but not optimized. It needs two memory operations! */
			if (in_it_block) {
				ALIGN_4bytes(ts->transl_instr);
				THUMB2_PUSH(ts->transl_instr, 1<<ARMREG_R9);
				//mrs r9
				THUMB2_RAW(ts->transl_instr, 0Xf3ef8900);
				THUMB2_PUSH(ts->transl_instr, 1<<ARMREG_R9);

				THUMB_RAW(ts->transl_instr, insn);
				ALIGN_4bytes(ts->transl_instr);


				THUMB2_POP(ts->transl_instr, 1<<ARMREG_R9);
				//msr r9
				THUMB2_RAW(ts->transl_instr, 0Xf3898c00);
				THUMB2_POP(ts->transl_instr, 1<<ARMREG_R9);

				ret = INS_PROCESSED;
			} else {
				ret = INS_COPY;
			}
#else
			if (in_it_block) {

				ALIGN_4bytes(ts->transl_instr);

				u4 bits_15_11 = (insn >> 11) & 0x1f;

				rd = insn & 0x7;
				rm = (insn >> 3) & 0x7;
				u4 imm5 = (insn >>6) & 0x1f;

				u4 imm8 = insn & 0xff;
				u4 rd1 = (insn >> 8) & 0x7;
				u4 rn = (insn >>3) &0x7;

				special_thumb = true;

				switch (bits_15_11) {
					case 0x0:
						/*LSL immediate */
						THUMB2_RAW(ts->transl_instr, 0xea4f0000
								|  (rd<<8) | (rm)
								| ((imm5 & 0x3) << 6)
								| ((imm5 & 0x1c) << 10) )

							ret = INS_PROCESSED;
						break;
					case 0x1:
						/*LSR immediate*/
						THUMB2_RAW(ts->transl_instr, 0xea4f0010
								|  (rd<<8) | (rm)
								| ((imm5 & 0x3) << 6)
								| ((imm5 & 0x1c) << 10) );
						ret = INS_PROCESSED;
						break;

					case 0x2:
						/* ASR */
						THUMB2_RAW(ts->transl_instr, 0xea4f0020
								|  (rd<<8) | (rm)
								| ((imm5 & 0x3) << 6)
								| ((imm5 & 0x1c) << 10) );
						ret = INS_PROCESSED;
						break;

					case 0x3:
						op = (insn >>9) &0x3;
						rd = insn & 0x7;
						rm = (insn >>6) & 0x7;
						rn = (insn >>3) & 0x7;

						u4 imm3 = (insn>>6) & 0x7;

						if (op == 0) {
							/* ADD REG*/
							THUMB2_RAW(ts->transl_instr, 0xeb000000
									|  (rn<<16) | (rd<<8) | (rm) );
						} else if (op == 1) {
							/* ADD RD, RS, #OFFSET  (imm3)*/
							THUMB2_RAW(ts->transl_instr, 0xf2000000
									|  (rn<<16) | (rd<<8) | (imm3) );
						} else if (op == 2) {
							/* SUB REG*/
							THUMB2_RAW(ts->transl_instr, 0xeba00000
									|  (rn<<16) | (rd<<8) | (rm) );
						} else {
							/* SUB RD, RS, #OFFSET (imm3)*/
							THUMB2_RAW(ts->transl_instr, 0xf2a00000
									|  (rn<<16) | (rd<<8) | (imm3) );
						}
						ret = INS_PROCESSED;
						break;
					case 0x4:
						/* MOV rd, #0ffset8*/
						THUMB2_RAW(ts->transl_instr, 0xf2400000
								| (rd1<<8) | (imm8) );
						ret = INS_PROCESSED;
						break;
					case 0x5:
						/* CMP */
						ret = INS_COPY;
						break;
					case 6:
						/*ADD RD, #OFFSET 8*/
						THUMB2_RAW(ts->transl_instr, 0xf2000000
								| (rd1<<8) | (rd1<<16)| (imm8) );
						ret = INS_PROCESSED;
						break;
					case 0x7:
						/*SUB RDn, #0X8*/
						THUMB2_RAW(ts->transl_instr, 0xf2a00000
								| (rd1<<8) | (rd1<<16)| (imm8) );
						ret = INS_PROCESSED;
						break;
					default:
						goto todo;
				}
			} else {
				ret = INS_COPY;
			}
#endif   //BDB_DEBUGGER

			break;

		case 4:
			if (insn & (1 << 11)) {
				/* pc relative load. */
				/* see document. bit 1 of pc is ignored. */
				load_address = ((u4)(ts->cur_instr) + 4 + ((insn & 0xff) * 4));
				load_address &= (~0x2);
				rd = (insn >> 8) & 7;
				/* address: pc + imm. we do not need to check the range
				 * since the imm is 8 bits.
				 */
				/* reg[rd] = load_address */
				gen_put_reg_imm32(ts, rd, load_address);
				/* ldr.w rd, [rd, #0] */
				THUMB2_LDRW_IMM12(ts->transl_instr, rd, rd, 0);
				ret = INS_PC_RELATIVE_LOAD | INS_PROCESSED;
				break;
			}

			/* hi register operations /branch exchange */
			if (insn & (1 << 10)) {
				rd = (insn & 7) | ((insn >> 4) & 8);
				rm = (insn >> 3) & 0xf;
				op = (insn >> 8) & 3;

				/* op == 0: add
				 * op == 1: cmp
				 * op == 2: mov
				 * op == 3: bx
				 */

				switch (op) {
					case 0x0:
						/* reg[rd] = reg[rd] + reg[rm] */
						if (rd == ARMREG_PC) {
							goto todo;
						}

						if (rm == ARMREG_PC) {
							origin_pc_value = (u4)(ts->cur_instr) + 4;
							temp_reg = get_reg(1<<rd, 7);
							//1. push temp_reg
							THUMB_PUSH(ts->transl_instr, 1 << temp_reg, 0);
							//2. put pc to temp_reg
							gen_put_reg_imm32(ts, temp_reg, origin_pc_value);
							//3. reg[rd] = reg[rd] + reg[temp]
							THUMB_ADD_HI_REG(ts->transl_instr, rd, temp_reg);
							//4. pop temp_reg
							THUMB_POP(ts->transl_instr, 1 << temp_reg, 0);
							ret = INS_PC_ALU | INS_PROCESSED;
						} else {
							ret = INS_COPY;
						}
						break;
					case 0x2:
						/* reg[rd] = reg [rm] */
						if (rd == rm) {
							/* nop */
							ret = INS_SKIP;
						} else if (rd == ARMREG_PC) {
							//implicit branch
							// reg[pc] = reg[rm]
							jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, rm);
							gen_ijump_reg_thumb(ts, rm, jump_prologue_offset - 4);
							gen_ijump_reg_thumb_epilogue(ts, 0);
							ret = INS_INDIRECT_JUMP | INS_PROCESSED;
						} else {
							ret = INS_COPY;
						}
						break;
					case 0x3:
						/* branch to rm*/
						/* bx rm */
						/* TODO HERE. BLX. H1 = 1!!!!!*/
						if (insn & (1<<7)) {
							//BLX rm. put lr to lr
							// ts->cur_instr + 2
							val = (u4)(ts->cur_instr + 2) | 1;
							gen_put_reg_imm32(ts, ARMREG_LR, val);
						} else {
							//bx
						}
						if (rm != ARMREG_PC) {
							jump_prologue_offset = gen_ijump_reg_thumb_prologue(ts, rm);
							gen_ijump_reg_thumb(ts, rm, jump_prologue_offset - 4);
							gen_ijump_reg_thumb_epilogue(ts, 0);
						} else {
							//bx r15
							jump_address = (u4)(ts->cur_instr + 4);
							gen_jump_thumb(ts, jump_address, (1<<rm), 0);
						}

						ret = INS_INDIRECT_JUMP | INS_PROCESSED;
						break;
					default:
						ret = INS_COPY;
						break;
				}
			} else {
				/*data processing*/
				/*
				 *  data processing instruction has different meanings
				 *  when inside an IT block!
				 */
#ifdef BDB_DEBUGGER
				if (in_it_block) {
					ALIGN_4bytes(ts->transl_instr);
					THUMB2_PUSH(ts->transl_instr, 1<<ARMREG_R9);
					//mrs r9
					THUMB2_RAW(ts->transl_instr, 0Xf3ef8900);
					THUMB2_PUSH(ts->transl_instr, 1<<ARMREG_R9);

					THUMB_RAW(ts->transl_instr, insn);
					ALIGN_4bytes(ts->transl_instr);


					THUMB2_POP(ts->transl_instr, 1<<ARMREG_R9);
					//msr r9
					THUMB2_RAW(ts->transl_instr, 0Xf3898c00);
					THUMB2_POP(ts->transl_instr, 1<<ARMREG_R9);

					ret = INS_PROCESSED;
				} else /* in_it_block */ {
					ret = INS_COPY;
				}
#else
				if (in_it_block) {
					/*
					 * we use the thumb2 instruction to replace original
					 * instruction!
					 */

					op = (insn >> 6) & 0xf;
					rd = (insn & 0x7);
					rm = (insn >> 3) & 0x7;

					special_thumb = true;

					ALIGN_4bytes(ts->transl_instr);
					switch (op) {
						case 0x0:
							//ea000000: and.w xx
							THUMB2_RAW(ts->transl_instr, 0xea000000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x1:
							/*eor*/
							THUMB2_RAW(ts->transl_instr, 0xea800000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;

						case 0x2:
							/*LSL*/
							THUMB2_RAW(ts->transl_instr, 0xfa00f000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x3:
							/*LSR*/
							THUMB2_RAW(ts->transl_instr, 0xfa20f000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x4:
							/*ASR*/
							THUMB2_RAW(ts->transl_instr, 0xfa40f000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x5:
							/*ADC*/
							THUMB2_RAW(ts->transl_instr, 0xeb400000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x6:
							/*SBC*/
							THUMB2_RAW(ts->transl_instr, 0xeb600000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x7:
							/*ror*/
							THUMB2_RAW(ts->transl_instr, 0xfa60f000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0x9:
							/*rsb: be cautious with rd/rm*/
							THUMB2_RAW(ts->transl_instr, 0xf1c00000
									| (rd<<8) | (rm<<16));
							ret = INS_PROCESSED;
							break;
						case 0xc:
							/*orr*/
							THUMB2_RAW(ts->transl_instr, 0xea400000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0xd:
							/*mul: be cautious with rd/rm */
							THUMB2_RAW(ts->transl_instr, 0xfb00f000
									| (rd<<16) | (rm<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0xe:
							/*bic*/
							THUMB2_RAW(ts->transl_instr, 0xea200000
									| (rd<<16) | (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;
						case 0xf:
							/*mvn*/
							THUMB2_RAW(ts->transl_instr, 0xea6f0000
									| (rd<<8) | (rm));
							ret = INS_PROCESSED;
							break;

						default:
							special_thumb = false;
							ret = INS_COPY;
							break;
					}
				} else /* in_it_block */ {
					ret = INS_COPY;
				}
#endif //BDB_DEBUGGER

			}
			break;

		case 5:
			/* TODO: load/store with reg offset*/
			/* the destination reg is r0-r7. no implicit jump here */
#ifdef DO_UAF_DETECT
			verify_ldstwb_thumb(ts, insn, (u4)ts->cur_instr + 4);
#endif
			ret = INS_LOAD | INS_COPY;
			break;
		case 6:
		case 7:
		case 8:
			/* load/store. */
#ifdef DO_UAF_DETECT
			verify_ldstwb_thumb(ts, insn, (u4)ts->cur_instr + 4);
#endif
			ret = INS_LOAD | INS_COPY;
			break;

		case 9:
			/* sp relative load store (load/store to/from stack) */
			ret = INS_LOAD | INS_COPY;
			break;

		case 10:
			rd = (insn >> 8) & 7;
			/*pc sp relative load address */
			/* add rd, pc, #imm */
			if ((insn & (1 << 11)) == 0) {
				load_address = ((u4)(ts->cur_instr) + 4 + ((insn & 0xff) * 4));
				/* bit 1 is ignored. see doc */
				load_address &= ~0x2;
				/* reg[rd] = load_address */
				gen_put_reg_imm32(ts, rd, load_address);
				ret = INS_PC_RELATIVE_LOAD | INS_PROCESSED;
				break;
			} else {
				ret = INS_COPY;
			}
			break;
		case 11:
			/* misc */
			op = (insn >> 8) & 0xf;
			switch (op) {
				case 0x2:
					/*uxtb*/
					ret = INS_COPY;
				case 0x4:
					/* push. reglist is between r0-r7 */
					ret =  INS_STORE | INS_COPY;
					break;

				case 0x5:
					/* push. lr in reg list*/
					//debug
					// gen_put_reg_imm32(ts, ARMREG_R0, 0);
					// THUMB_LDR_IMM_OFFSET(ts->transl_instr, ARMREG_R0, ARMREG_R0, 0);
					ret =  INS_STORE | INS_COPY;
					break;

				case 0xc:
					/*pop. reglist is between r0-r7*/
					ret = INS_LOAD | INS_COPY;
					break;

				case 0xd:
					/* pop to pc */
					/* this is indirect jump. address is on stack. */
					/* pop {rlist, pc}*/
					rlist = insn & 0xff;
					gen_pop_thumb(ts, rlist);
					ret = INS_INDIRECT_JUMP | INS_PROCESSED;
					break;
				case 15: /* IT, nop-hint.  */
					if ((insn & 0xf) != 0) {
						/* we need to emulate IT block since
						 * one instruction in original IT block
						 * can become several instructions
						 *
						 * For example
						 *  lw  r0, [pc]
						 *
						 *  in IT block can be translated into 5 instructions
						 *
						 *   push temp
						 *   movt  pc_top
						 *   movw  pc_low
						 *   lw r0, [temp]
						 *   pop temp
						 *
						 */
						// ts->condexec_cond = (insn >> 4) & 0xf;
						// u4 condexec_mask = insn & 0xf;

						//clear last bit
						int cond_temp = (insn >> 4) & 0xe;
						int mask_temp = insn & 0xf;

						ts->condexec_cond[0] = (insn >> 4) & 0xf;
						ts->condexec_cond[1] = 0xe;
						ts->condexec_cond[2] = 0xe;
						ts->condexec_cond[3] = 0xe;

						ts->insn_changed[0] = false;
						ts->insn_changed[1] = false;
						ts->insn_changed[2] = false;
						ts->insn_changed[3] = false;

						ts->it_transl_instr = ts->transl_instr;
						ts->it_instr = ts->cur_instr;

						if ((insn & 0x1) == 0x1) {
							ts->condexec_cond[1] = cond_temp | ((mask_temp >> 3) & 1);
							ts->condexec_cond[2] = cond_temp | ((mask_temp >> 2) & 1);
							ts->condexec_cond[3] = cond_temp | ((mask_temp >> 1) & 1);
							ts->it_total_num = 4;
						} else if ((insn & 0x3) == 0x2) {
							ts->condexec_cond[1] = cond_temp | ((mask_temp >> 3) & 1);
							ts->condexec_cond[2] = cond_temp | ((mask_temp >> 2) & 1);
							ts->it_total_num = 3;
						} else if ((insn & 0x7) == 0x4) {
							ts->condexec_cond[1] = cond_temp | ((mask_temp >> 3) & 1);
							ts->it_total_num = 2;
						} else {
							ts->it_total_num = 1;
						}

						ts->it_index = 0;
						ts->it_cur_num = ts->it_total_num;

						ret = INS_SKIP;
					} else {
						/* nop hint */
						goto todo;
					}
					break;
				case 1: case 3: case 9: case 11:
					/* czb */
					rm = insn & 0x7;

					original_transl = (u4)(ts->transl_instr);

					if (insn & (1 << 11)) {
						/* if rm != 0, jump.
						 * In translated code, we need to jump over if rm == 0
						 *  offset will be patched later
						 */
						THUMB_CBZ(ts->transl_instr, rm, 0);
					} else {
						THUMB_CBNZ(ts->transl_instr, rm, 0);
					}

					jump_address = ((u4)(ts->cur_instr) + 4);
					offset = ((insn & 0xf8) >> 2) | (insn & 0x200) >> 3;
					jump_address += offset;

					/* condition == true, then jump to jump_address*/
					//set last bit of jump_target as 1
					// so that when jumping back from trampoline (Arm mode), the mode
					// can be changed to thumb automatically
					jump_address |= 0x1;
					gen_jump_thumb(ts, jump_address, (1<<rm), 0);

					//now patch the offset.
					u4 toffset = (u4)ts->transl_instr - original_transl;
					toffset = (toffset - 4) >> 1;
					*(u2 *)original_transl = (*(u2 *)original_transl)
						| ((toffset & 0x1f) << 3)
						| ((toffset& 0x20) << 4);

					ret = INS_DIRECT_JUMP | INS_PROCESSED | INS_CONDITIONAL_JUMP;
					break;
				case 0xe:
					/*bkpt*/
					goto todo;
				case 0xa:
					/*rev*/
				case 0x0:
					/* adjust stack pointer */
					ret = INS_COPY;
					break;
				default:
					goto undef;
			}
			break;

		case 12:
			/* multi load store*/
			/* ok since it can only access r0-r7 */
			if (insn & (1 << 11)) {
				ret = INS_LOAD | INS_COPY;
			} else {
				ret = INS_STORE | INS_COPY;
			}
			break;

		case 13:
			cond = (insn >> 8) & 0xf;
			if (cond == 0xf) {
				/*swi*/
				ret = INS_SYSCALL;
				goto syscall;
			} else if (cond == 0xe) {
				goto undef;
			} else {
				/* conditional branch*/
				jump_address = ((u4)(ts->cur_instr) + 4);
				offset = ((s4)insn << 24) >> 24;
				/* imm8 *2 (not 4). */
				jump_address += offset << 1;

				u4 notcond = cond - 1 ;
				if (cond % 2 == 0) {
					notcond = cond + 1;
				}

				/* if not condition, then jump to end*/
				/* offset will be patched later*/
				original_transl = (u4)(ts->transl_instr);
				THUMB_CONB_IMM(ts->transl_instr, notcond, 0);

				/* condition == true, then jump to jump_address*/
				//set last bit of jump_target as 1
				// so that when jumping back from trampoline (Arm mode), the mode
				// can be changed to thumb automatically
				jump_address |= 0x1;
				gen_jump_thumb(ts, jump_address, 0x0, 0);

				//now patch the offset.
				u4 toffset = (u4)ts->transl_instr - original_transl;
				toffset = (toffset - 4) >> 1;
				*(u2 *)original_transl = (*(u2 *)original_transl) | (toffset & 0xff);

				//gen_call_translate_function(ts, (u4)(ts->cur_instr) + 2);

				//ret = INS_DIRECT_JUMP | INS_PROCESSED;
				//We do not want to terminate translation since this is is
				//conditional jump.
				ret = INS_DIRECT_JUMP | INS_PROCESSED | INS_CONDITIONAL_JUMP;
			}
			break;
		case 14:
			if (insn & (1 << 11)) {
				ret = fbt_translate_instr_thumb2(ts, insn_hw);
				goto skip_emit;
			} else {
				/* unconditional branch */
				/* pc relative jump */
				jump_address = (u4)(ts->cur_instr);
				offset = ((s4)insn << 21) >> 21;
				jump_address += (offset << 1) + 4;
				//set last bit of jump_target as 1
				// so that when jumping back from trampoline (Arm mode), the mode
				// can be changed to thumb automatically
				jump_address |= 0x1;
				gen_jump_thumb(ts, jump_address, 0x0, 0);
				ret = INS_DIRECT_JUMP | INS_PROCESSED;
			}
			break;
		case 15:
			ret = fbt_translate_instr_thumb2(ts, insn_hw);
			/* check it block */
			if (in_it_block) {
				if (it_block_epilogue(ts, ret, special_thumb)) {
					ret = INS_PROCESSED;
					return ret;
				}
			}
			goto skip_emit;
			break;


		default:
			goto undef;
	}

	// BT_DEBUG("ret  0x%-8x ", ret);

#ifndef BDB_DEBUGGER
	/*
	 * if we enable BDB_DEBUGGER, we will add debugger trampoline
	 * before each instruction. In this case, we do not want to
	 * restore original it block. Instead, we use the branch one...
	 */
	if (in_it_block) {
		if (it_block_epilogue(ts, ret, special_thumb)) {
			ret = INS_PROCESSED;
			return ret;
		}
	}
#endif

	/* now process the instruction according to ret */
	if (ret & INS_COPY) {
		THUMB_EMIT(ts->transl_instr, insn);
	}

skip_emit:

	if (condjmp) {
		u4 offset = (u4)ts->transl_instr - original_transl;
		//actual pc is 4 bytes ahead, so we need to minus 4 from here.
		//the offset is 2 bytes aligned.
		offset = (offset - 4) >> 1;
		//patch original jump
		*(u2 *)original_transl = (*(u2 *)original_transl) | (offset & 0xff);
		BT_DEBUG("patch offset ");

		if (ret & (INS_DIRECT_JUMP | INS_INDIRECT_JUMP)) {
			ret |= INS_CONDITIONAL_JUMP;
		}
	}

	thumb_debug_translation(ts, old_transl_instr, insn);
	TRACE_EXIT;
	return ret;
syscall:
	BT_ERR(true, "syscall instruction 0x%-8x ", insn);
undef:
	BT_ERR(true, "undefined instruction 0x%-8x ", insn);
todo:
	BT_ERR(true, "TODO*****instruction 0x%-8x ", insn);

	return INS_TODO;
}



