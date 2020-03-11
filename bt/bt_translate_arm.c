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

/* The "doc" in this file means ARM DDI 0406A. */
/*
 * Be cautious with BranchWritePC() and BXWritePC()
 *
 *  See page A2-13 on doc. BranchWritePC does NOT change mode while
 *   BXWritePC MAY change mode!
 */
#ifdef DO_UAF_DETECT
static u4 func_addr_check = (u4)addr_check;
#endif

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
	/* put load_address into rd */
	//lower 16 bits
	ARM_MOVW_REG_IMM16(ts->transl_instr, r, imm32 & 0xffff);
	//higher 16 bits
	ARM_MOVT_REG_IMM16(ts->transl_instr, r, (imm32 & 0xffff0000)>>16);
}

/* returned total spaces revered on stack (pushed regs*4)
 *
 *  rd: the destination register
 *
 */
static inline int gen_ijump_reg_arm_prologue(struct translate *ts, int rd) {
	/*
	 * 1. reserve a space for returned target address
	 * 2. push ip/lr into stack
	 * 3. save flags into stack
	 */
	/* add sp, sp, -4*/
	ARM_SUB_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);
	/* push ip, lr into stack */
	ARM_PUSH2(ts->transl_instr, ARMREG_IP, ARMREG_LR);
	/* move flags into ip */
	ARM_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	ARM_PUSH1(ts->transl_instr, ARMREG_IP);

	/* if destination register is ip, we need to restore ip value */
	if (rd == ARMREG_IP) {
		/*
		 *   |saved lr
		 *   |saved ip
		 *   |saved flags __current sp
		 */
		ARM_LDR_IMM(ts->transl_instr, ARMREG_IP, ARMREG_SP, 4);
	}

	return 16;
}

static inline void gen_ijump_reg_arm_epilogue(struct translate *ts,
		int garbage_space) {

	/*
	 *  1. restore flags
	 *  2. restore ip/lr
	 *  3. discard garbage space (by changing sp)
	 *  4. jump to saved target address
	 *
	 */
	/* pop saved flags into ip */
	ARM_POP1(ts->transl_instr, ARMREG_IP);
	/* put ip -> apsr */
	//0x2: means nzcvq
	ARM_MSR_REG(ts->transl_instr, ARMREG_IP, 0x2);
	/* pop to ip,lr again */
	ARM_POP2(ts->transl_instr, ARMREG_IP, ARMREG_LR);
	if (garbage_space == 0) {
		//if garbage_space == 0, we just pop {pc}
		ARM_POP1(ts->transl_instr, ARMREG_PC);
	} else if (garbage_space > 0){
		/* discard garbage space
		 * sp = sp + garbage_space + 4 (target address)
		 */
		ARM_ADD_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, garbage_space + 4);
		/* jump to target. target = mem[sp - garbage_space -4] */
		//ldr pc, [sp, - (garbage_space + 4)]
		ARM_LDR_IMM(ts->transl_instr, ARMREG_PC, ARMREG_SP, -(garbage_space + 4));
	} else {
		//garbage_space == -1, means we do not need to restore stack and
		//jump to target here. The caller will take care.
	}
}

static inline void gen_ijump_reg_arm(struct translate *ts, int rd, int ret_reg_offset) {
	/*
	 *   //push r0,r1,r2,r3 into stack
	 *   push {r0,r1,r2,r3}
	 *   //put the target address into r0
	 *   mov r0, rd
	 *   //put jump_trampoline into r2
	 *   movw r2, xxx
	 *   movt r2, xxx
	 *   //put pushed_reg_list to lower 16 bits of r3
	 *   movw r3, pushed_reg_list&0xffff
	 *   jump to jump_trampoline
	 *   blx  r2
	 *   pop {r0 - r3}
	 *
	 */

	/*push {r0,r1,r2,r3}*/
	ARM_PUSH4(ts->transl_instr, ARMREG_R0,  ARMREG_R1, ARMREG_R2, ARMREG_R3);

	if (rd != 0) {
		/*  mov r0, rd*/
		ARM_MOV_REG_REG(ts->transl_instr, ARMREG_R0, rd);
	}


	/* put tld -> r1 (tld will be calculated at runtime)
	 *
	 * since the translated code will be shared by all thread. We can not
	 * hardcode tld into the code.
	 *
	 */
	// gen_put_reg_imm32(ts, ARMREG_R1, (u4)(ts->tld));

	/* load ijump trampoline */
	gen_put_reg_imm32(ts, ARMREG_R2, sbox.sandbox_start + IJUMP_TRAMPOLINE_START);

	//put ret_reg_offset + 16 (pushed in this function) into r3 (why?)
	ARM_MOVW_REG_IMM16(ts->transl_instr, ARMREG_R3, (ret_reg_offset + 16) & 0xffff);

	//debug: generate lw [0]
	// gen_put_reg_imm32(ts, ARMREG_R0, 0);
	// ARM_LDR_IMM(ts->transl_instr, ARMREG_R0, ARMREG_R0,
	//                     0);

	/* jump to jump_trampoline */
	ARM_BLX_REG(ts->transl_instr, ARMREG_R2);
	/*trampoline returns. The actual target has been pushed on stack. Now
	 * restore state and jump to target in code cache.
	 */
	/*pop r0 - r3*/
	ARM_POP4(ts->transl_instr, ARMREG_R0,  ARMREG_R1, ARMREG_R2, ARMREG_R3);
}

/*
 * direct and indirect jump to 32 bit target address jump_target.
 *
 */
static inline void gen_jump_arm(struct translate *ts, u4 jump_target, int avoidregmask) {

	u4 temp_reg = 0;

	temp_reg = get_reg(avoidregmask, 16);

	u4 offset = gen_ijump_reg_arm_prologue(ts, temp_reg);
	//1. push temp_reg
	ARM_PUSH1(ts->transl_instr, temp_reg);
	offset += 4;

	//2. put jump_address to temp_reg
	gen_put_reg_imm32(ts, temp_reg, jump_target);
	//3. jump to jump_address
	gen_ijump_reg_arm(ts, temp_reg, offset - 4);
	//4. pop temp_reg
	ARM_POP1(ts->transl_instr, temp_reg);
	//5. pop up saved flags, ip, discard garbage space and jump to target.
	gen_ijump_reg_arm_epilogue(ts, 0);

}

/*
 * First, second and eleventh rows in table A5-2 in doc
 *
 * Data-processing (register, register-shifted register and immediate)
 *
 *  bit 25: 1 -> immediate
 *          op   rd, rn, #imm
 *
 *  bit 25 = 0 and bit 4 = 0 -> register
 *          op   rd, rn, rm (,shift)  -> shifted value is constant
 *
 *  bit 25 = 0 and bit 4 = 1 -> register-shifted register
 *          op   rd, rn, rm, (type), rs  -> shifted value is in register
 *
 *
 */

static ins_type gen_data_processing(struct translate *ts,
		u4 insn, u4 pc_value) {
	/* fast path:
	 *   (1) for register-shifted register, it's fine since pc can not be in any
	 *       register.
	 *   (2) tst, teq, cmp, cmn are safe
	 *   (3) pc is not in src and dest registers
	 *
	 */

	if (!(insn & (1 << 25)) && (insn & 0x10)) {
		/* register-shifted register */
		return INS_COPY;
	}

	/*
	 * 0: and  1: eor  2: sub  3: rsb
	 * 4: add  5: adc  6: sbc  7: rsc
	 * 8: tst  9: teq  a: cmp  b: cmn
	 * c: orr  d: mov  e: bic  f: mvn
	 */

	u4 op1 = (insn >> 21) & 0xf;

	/* tst, teq, cmp, cmn are safe */
	if ((op1 >= 8) && (op1 <= 11)) {
		return INS_COPY;
	}

	u4 rd = (insn >> 12) & 0xf;
	u4 rn = (insn >> 16) & 0xf;
	u4 rm = (insn) & 0xf;

	if ((rn != ARMREG_PC) && (rd != ARMREG_PC)) {
		//immediate
		if (insn & (1 << 25))
			return INS_COPY;
		else {
			//register
			if (rm != ARMREG_PC)
				return INS_COPY;
		}
	}

	bool rd_pc = (rd == ARMREG_PC)? true : false;
	bool setflag = (insn & (1<<20))? true: false;
	bool immediate = insn & (1 << 25)? true : false;
	/*
	 *
	 *   special case:
	 *
	 *    immediate and imm == 0
	 *        add   ip, pc, #0  is heavily used in plt
	 *
	 *
	 */
	/*special case */
	if ((rd_pc == false) && (immediate)
			&& (!setflag)
			/* we only care last 8 bit. see page A5-8 on doc */
			&& ((insn & 0xff) == 0x0)) {
		u4 op1 = (insn >> 21) & 0xf;
		switch (op1) {
			case 0x0:
				/* Bitwise AND */
				/* rd = rn and 0 = 0*/
				gen_put_reg_imm32(ts, rd, 0x0);
				return INS_PROCESSED;
			case 0x2:
				/* SUB */
			case 0x4:
				/* ADD*/
			case 0x5:
				/* ADC */
			case 0x6:
				/* SBC */
				/* put rd == pc value */

				//debug
				// gen_put_reg_imm32(ts, rd, 0);
				// ARM_LDR_IMM(ts->transl_instr, rd, rd,
				//             0);

				gen_put_reg_imm32(ts, rd, pc_value);
				return INS_PROCESSED;
		}
	}


	/* slow path */
	bool rn_pc = (rn == ARMREG_PC)? true : false;
	bool rn_sp = (rn == ARMREG_SP)? true : false;

	//bool rd_sp = (rd == ARMREG_SP)? true : false;

	bool rm_pc = false, rm_sp = false;


	if (immediate == false) {
		rm_pc = (rm == ARMREG_PC)?true:false;
		rm_sp = (rm == ARMREG_SP)?true:false;
	}

	int temprm = -1;
	int temprn = -1;
	int temprd = -1;
	u4 tempinsn = insn;

	/*
	 *  if immediate:
	 *        rn: is pc, then need a temp register
	 *  if not immediate:
	 *
	 *        rn       rm
	 *        pc       pc
	 *        pc       sp    -> sp is changed when pushing temp register!
	 *        sp       pc    -> sp is changed when pushing temp register!
	 *        sp       sp   ->covered in fast path (rd, rn, rm are not pc)
	 *
	 */
	/*
	 * See Table A5-3. LSL, LSR, ASR, RRX, ROR can also be covered here
	 *
	 */

	//pc not in dest registers -> not indirect jump.
	if (rd_pc == false) {
		//rn and/or rm == pc
		if (immediate) {
			//rn == pc
			temprn = get_reg((1<<rn) | (1<<rd), 10);
			ARM_PUSH1(ts->transl_instr, temprn);
			//put pc into temprn
			gen_put_reg_imm32(ts, temprn, pc_value);
		} else if (rn_pc && rm_pc) {
			temprn = get_reg((1<<rn) | (1<<rd) | (1<<rm), 10);
			temprm = temprn;
			ARM_PUSH1(ts->transl_instr, temprn);
			//put pc into temprn
			gen_put_reg_imm32(ts, temprn, pc_value);
		} else if (rn_pc) {
			temprn = get_reg((1<<rn) | (1<<rd) | (1<<rm), 10);
			ARM_PUSH1(ts->transl_instr, temprn);
			//put pc into temprn
			gen_put_reg_imm32(ts, temprn, pc_value);
			if (rm_sp) {
				temprm = get_reg((1<<rn) | (1<<rd) | (1<<rm) | (1<<temprn), 10);
				ARM_PUSH1(ts->transl_instr, temprm);
				//put original sp (sp + 8) into temprm
				ARM_ADD_IMM12(ts->transl_instr, temprm, ARMREG_SP, 8);
			}

		} else if (rm_pc) {
			temprm = get_reg((1<<rn) | (1<<rd) | (1<<rm), 10);
			ARM_PUSH1(ts->transl_instr, temprm);
			//put pc into temprm
			gen_put_reg_imm32(ts, temprm, pc_value);
			if (rn_sp) {
				temprn = get_reg((1<<rn) | (1<<rd) | (1<<rm) | (1<<temprm), 10);
				ARM_PUSH1(ts->transl_instr, temprn);
				//put original sp (sp + 8) into temprn
				ARM_ADD_IMM12(ts->transl_instr, temprn, ARMREG_SP, 8);
			}
		}

		//patch original instruction
		if (temprm != -1) {
			tempinsn = (tempinsn & (~0xf)) | temprm;
		}

		if (temprn != -1) {
			tempinsn = (tempinsn & (~0xf0000)) | (temprn<<16);
		}

		ARM_RAW(ts->transl_instr, tempinsn);

		//restore temp registers
		if (immediate) {
			//restore temp rn
			ARM_POP1(ts->transl_instr, temprn);
		} else {
			if (rn_pc && rm_pc) {
				//both rn/rm are pc
				ARM_POP1(ts->transl_instr, temprn);
			} else if (rn_pc) {
				ARM_POP1(ts->transl_instr, temprn);
				if (rm_sp) {
					ARM_POP1(ts->transl_instr, temprm);
				}
			} else if (rm_pc) {
				ARM_POP1(ts->transl_instr, temprm);
				if (rn_sp) {
					ARM_POP1(ts->transl_instr, temprn);
				}
			}
		}

		return INS_PROCESSED;
	}

	int pushed_regs_offset = 0;

	bool replace_rn = false;
	bool replace_rm = false;

	//slowest path. rd is pc -> indirect jump
	if (immediate) {
		temprd = get_reg((1<<rn) | (1<<rd), 10);
		ARM_PUSH1(ts->transl_instr, temprd);
		pushed_regs_offset += 4;

		if ((rn == ARMREG_PC) || (rn == ARMREG_SP)) {
			temprn = get_reg((1<<rn) | (1<<rd) | (1<<temprd), 10);
			ARM_PUSH1(ts->transl_instr, temprn);
			pushed_regs_offset += 4;
		}
		if (rn == ARMREG_PC) {
			gen_put_reg_imm32(ts, temprn, pc_value);
			replace_rn = true;
		} else if (rn == ARMREG_SP) {
			//put original sp (sp + pushed_regs_offset) into temp register
			ARM_ADD_IMM12(ts->transl_instr, temprn, ARMREG_SP, pushed_regs_offset);
			replace_rn = true;
		}
	} else {
		//register
		temprd = get_reg((1<<rn) | (1<<rd), 10);
		ARM_PUSH1(ts->transl_instr, temprd);
		pushed_regs_offset += 4;

		//find two temp registers (even we may not need two of them)
		temprn = get_reg((1<<rn) | (1<<rd) | (1<<rm) | (1<<temprd), 10);
		temprm = get_reg((1<<rn) | (1<<rd) | (1<<rm) | (1<<temprd) | (1<<temprn), 10);
		ARM_PUSH2(ts->transl_instr, temprn, temprm);
		pushed_regs_offset += 8;

		if (rn == ARMREG_PC) {
			gen_put_reg_imm32(ts, temprn, pc_value);
			replace_rn = true;
		} else if (rn == ARMREG_SP) {
			//put original sp (sp + pushed_regs_offset) into temp register
			ARM_ADD_IMM12(ts->transl_instr, temprn, ARMREG_SP, pushed_regs_offset);
			replace_rn = true;
		}

		if (rm == ARMREG_PC) {
			gen_put_reg_imm32(ts, temprm, pc_value);
			replace_rm = true;
		} else if (rm == ARMREG_SP) {
			//put original sp (sp + 4*pushed_regs_number) into temp register
			ARM_ADD_IMM12(ts->transl_instr, temprm, ARMREG_SP, pushed_regs_offset);
			replace_rm = true;
		}
	}

	tempinsn = insn;

	tempinsn = (tempinsn & (~0xf000)) | (temprd<<12);

	//patch original instruction
	if (replace_rm) {
		tempinsn = (tempinsn & (~0xf)) | temprm;
	}

	if (replace_rn) {
		tempinsn = (tempinsn & (~0xf0000)) | (temprn<<16);
	}

	ARM_RAW(ts->transl_instr, tempinsn);

	//now jump target is in temprd
	u4 jump_prologue_offset = gen_ijump_reg_arm_prologue(ts, temprd);
	gen_ijump_reg_arm(ts, temprd, jump_prologue_offset - 4);
	gen_ijump_reg_arm_epilogue(ts, -1);

	//restore temp register and stack
	/*
	 *          _______previous sp
	 *   |temprd
	 *   |temprn (if pushed)
	 *   |temprm (if pushed)
	 *   |real jump target____current sp
	 *
	 *
	 *  we need to restore temp registers and sp and then jump to target
	 */

	//sp = sp + 4
	ARM_ADD_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);

	//pop up temprn and temprm
	if (immediate) {
		if (temprn != -1) {
			ARM_POP1(ts->transl_instr, temprn);
		}
	} else {
		ARM_POP2(ts->transl_instr, temprn, temprm);
	}

	//pop temprd
	ARM_POP1(ts->transl_instr, temprd);

	//now sp and temp registers are restored, jump to target
	//target = [sp - pushed_regs_offset - 4]
	ARM_LDR_IMM(ts->transl_instr, ARMREG_PC, ARMREG_SP,
			-(pushed_regs_offset + 4));

	return INS_PROCESSED | INS_INDIRECT_JUMP;
}

/*
 * Loads a single-precision register from memory C4-44
 * FLDS<c>	<Sd>, [<Rn>{, #+/-(<offset>*4)}]
 * 
 * Loads a double-precision register from memory C4-36
 * FLDD<c>	<Dd>, [<Rn>{, #+/-(<offset>*4)}]
 * 
 *		sd/dd: [15:12]
 *		   rn: [19:16]
 *	 offset: [7:0]
 *
 *
 */
ins_type gen_vldstr(struct translate *ts, u4	insn, u4 pc_value) {

	TRACE_ENTER;
	if(((insn >> 20) & 0x2) != 0x0) {
		return INS_COPY;
	}
	if(((insn >> 8) & 0xa) != 0xa) {
		return INS_COPY;
	}
	//u4 rd = (insn >> 12) & 0xf;
	u4 rn = (insn >> 16) & 0xf;
	//u4 offset = insn & 0xff;

	if(rn != ARMREG_PC)
	{
		return INS_COPY;
	}

	/* reserve three temp registers (even 2 registers are enough for ldr imm) */
	u4 temprn = get_reg((1<<rn) | (1<<rn) | (1<<rn), 10);

	/* push temp registers */
	ARM_PUSH1(ts->transl_instr, temprn);

	gen_put_reg_imm32(ts, temprn, pc_value);

	u4 tempinsn = (insn & (~(0xf << 16))) | (temprn << 16);

	ARM_RAW(ts->transl_instr, tempinsn);

	ARM_POP1(ts->transl_instr, temprn);
	TRACE_EXIT;
	return INS_PROCESSED;

}

/* LLDD/FLDMD/FLDMS/FLDMX/FLDS  FSTD/FLTMD/FLTMS/FLTMX/FSTS C3-14 */
#ifdef DO_UAF_DETECT
void verify_fldst_vfp_arm(struct translate *ts, u4 insn, u4 pc_value) {
	u4 rn = (insn >> 16) & 0xf;
	if(rn == ARMREG_SP || rn == ARMREG_PC){
		return;
	}
	//u4 fd = (insn >> 12) & 0xf;
	u4 imm12 = (insn & 0xff) << 2;
	//u4 cpnum = (insn >> 8) & 0xf;
	u4 puw = ((insn >> 22) & 0x6) | ((insn >> 21) & 0x1);
	if(puw == 0) {
		return;
	}
	//u4 add = (insn >> 20) & 0x1;
	//
	/* push ip, lr into stack */
	ARM_PUSH2(ts->transl_instr, ARMREG_IP, ARMREG_LR);
	ARM_PUSH4(ts->transl_instr, ARMREG_R0, ARMREG_R1, ARMREG_R2, ARMREG_R3);

	UAF_LOGI("%s:%d inst: 0x%8x imm=0x%x", FILE, LINE, insn, imm12);

	switch(puw) {
		case 0x1: // post-indexed
			/* start_addr = rn */
		case 0x2: // Unindexed
			/* start_addr = rn */
		case 0x3: // post-indexed
			/* start_addr = rn */
			if(rn != ARMREG_R0){
				ARM_MOV_REG_REG(ts->transl_instr, ARMREG_R0, rn);
			}
			break;
		case 0x4: // Negative offseta
			/* addr = rn - offset * 4 */
		case 0x5: // pre-indexed
			/* start_addr = rn - offset * 4 */
			if(1) {
				ARM_SUB_IMM12(ts->transl_instr, ARMREG_R0, rn, imm12);
			}
			break;
		case 0x6: // Positive offset
			/* addr = rn + offset * 4 */
		case 0x7: // pre-indexed
			/* start_addr = rn + offset * 4 */
			if(1) {
				ARM_ADD_IMM12(ts->transl_instr, ARMREG_R0, rn, imm12);
			}
			break;
		default:
			UAF_LOGI("%s:%d inst: 0x%8x error", FILE, LINE, insn);
			break;
	}

	/* move flags into ip */
	ARM_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	ARM_PUSH1(ts->transl_instr, ARMREG_IP);
	
	
	/* Do check */
#ifdef DEBUG_UAF_CHECK
	gen_put_reg_imm32(ts, ARMREG_R1, UAF_CHECK_ADDR_VFP_ARM);
#endif
	gen_put_reg_imm32(ts, ARMREG_R2, func_addr_check);
	ARM_BLX_REG(ts->transl_instr, ARMREG_R2);
	
	
	
	/* pop saved flags into ip */
	ARM_POP1(ts->transl_instr, ARMREG_IP);
	/* put ip -> apsr */
	//0x2: means nzcvq
	/* pop ip */
	ARM_MSR_REG(ts->transl_instr, ARMREG_IP, 0x2);
	
	/* Pop r0, r1, r2 */
	ARM_POP4(ts->transl_instr, ARMREG_R0, ARMREG_R1, ARMREG_R2, ARMREG_R3);
	/* pop ip, lr */
	ARM_POP2(ts->transl_instr, ARMREG_IP, ARMREG_LR);
	UAF_LOGI("%s:%d", FILE, LINE);
}
/* verify the address of the load/store intructions */
void verify_ldstwb_arm(struct translate *ts, u4 insn, u4 pc_value) {


	/* load word. (LDR): imm, literal, register */
	u4 rn = (insn >> 16) & 0xf;
	//u4 rt = (insn >> 12) & 0xf;
	u4 rm = insn & 0xf;

	if(rn == ARMREG_SP || rn == ARMREG_PC)
		return;
	/* push ip, lr into stack */
	ARM_PUSH2(ts->transl_instr, ARMREG_IP, ARMREG_LR);
	ARM_PUSH4(ts->transl_instr, ARMREG_R0, ARMREG_R1, ARMREG_R2, ARMREG_R3);

	bool add = (insn & (1 << 23))? true:false;
	u4 imm5 = (insn >> 7) & 0x1f;
	u4 imm12 = insn & 0xfff;

	UAF_LOGI("%s:%d inst: 0x%8x at 0x%8x imm12=0x%x", FILE, LINE, insn, pc_value, imm12);

	/* Immediate offset/index (A5-19) */
	if(!(insn & (1 << 25))) {
		if(add){
			/* r0 = rn + imm12
			 * ADD r0, rn, imm12
			 */
			ARM_ADD_IMM12(ts->transl_instr, ARMREG_R0, rn, imm12);
		} else {
			/* r0 = rn - imm12
			 * SUB r0, rn, imm12
			 */
			ARM_SUB_IMM12(ts->transl_instr, ARMREG_R0, rn, imm12);
		}
	} else {
		/* Register offset/index (A5-19) */
		if(!(insn & (0xff << 4))) {
			if(add) {
				/* r0 = rn + rm 
				 * ADD r0, rn, rm
				 */
				ARM_ADD_REG_REG(ts->transl_instr, ARMREG_R0, rn, rm);
			} else {
				/* r0 = rn - rm
				 * SUB r0, rn, rm
				 */
				ARM_SUB_REG_REG(ts->transl_instr, ARMREG_R0, rn, rm);
			}
		} /* Scaled register offset/index (A5-19) */ 
		else {
			u1 shift = (insn >> 5) & 0x3;
#if 0
			switch((insn >> 5) & 0x3) {
				case 0x0: 
					/* r0 = rn +/- rm lsl imm5
					 * ADD/SUB r0, rn, rm lsl imm5
					 */
				case 0x1: 
					/* r0 = rn +/- rm lsr imm5
					 * ADD/SUB r0, rn, rm lsr imm5
					 */
				case 0x2: 
					/* r0 = rn +/- rm asr imm5
					 * ADD/SUB r0, rn, rm lsr imm5
					 */
				case 0x3: 
					/* r0 = rn +/- rm ror/rrx imm5
					 * ADD/SUB r0, rn, rm ror/rrx imm5
					 */
				default:
#endif
					if(add)
					{ 
						ARM_DEF_ADD_REG_REG_SHIFT_IMM(ts->transl_instr, ARMREG_R0, rn, rm, imm5, shift);
					} else {
						ARM_DEF_SUB_REG_REG_SHIFT_IMM(ts->transl_instr, ARMREG_R0, rn, rm, imm5, shift);
					}
#if 0
					break;
			}
#endif
		}
	}

	/* move flags into ip */
	ARM_MRS(ts->transl_instr, ARMREG_IP);
	/* push flags into stack */
	ARM_PUSH1(ts->transl_instr, ARMREG_IP);
  
	/* Do check */
#ifdef DEBUG_UAF_CHECK
	gen_put_reg_imm32(ts, ARMREG_R1, UAF_CHECK_ADDR_ARM);
#endif
	gen_put_reg_imm32(ts, ARMREG_R2, func_addr_check);
	ARM_BLX_REG(ts->transl_instr, ARMREG_R2);

	/* pop saved flags into ip */
	ARM_POP1(ts->transl_instr, ARMREG_IP);
	/* put ip -> apsr */
	//0x2: means nzcvq
	/* pop ip */
	ARM_MSR_REG(ts->transl_instr, ARMREG_IP, 0x2);
	/* Pop r0, r1, r2 */
	ARM_POP4(ts->transl_instr, ARMREG_R0, ARMREG_R1, ARMREG_R2, ARMREG_R3);
	/* pop ip, lr */
	ARM_POP2(ts->transl_instr, ARMREG_IP, ARMREG_LR);
	UAF_LOGI("%s:%d", FILE, LINE);
}
#endif // DO_UAF_DETECT

/* generate load word and byte. page A5-17 in doc
 *
 * LDR (imm, literal, register)
 *
 *   rt: [15:12]
 *   rn: [19:16]
 *   rm: [4:0]
 *
 *
 *
 * LDR<c> <Rt>,[<Rn>,#+/-<imm12>]!
 * LDR<c> <Rt>,[<Rn>],+/-<Rm>{, <shift>}
 *
 * index, add, wback
 *
 *  add: rn +/- offset
 *  if index, then load address = addr, otherwise it's rn
 *  if wb then write addr into rn
 *
 *   fortunately, if wb, then rn can not be pc
 *
 *
 */
ins_type gen_ldstwb(struct translate *ts, u4 insn, u4 pc_value) {

	/* fast path: store is ok */
	if (!(insn & (1 << 20))) {
		//store
		return INS_COPY;
	}

	/*fast path: load byte is ok */
	if (insn & (1 << 22)) {
		return INS_COPY;
	}

	/* load word. (LDR): imm, literal, register */
	u4 rn = (insn >> 16) & 0xf;
	u4 rt = (insn >> 12) & 0xf;
	u4 rm = insn & 0xf;

	/*fast path: rt != 15*/
	if ((rt != ARMREG_PC) && (rn != ARMREG_PC)) {
		return INS_COPY;
	}


	/* reserve three temp registers (even 2 registers are enough for ldr imm) */
	u4 temprt = get_reg((1<<rn) | (1<<rt) | (1<<rm), 10);
	u4 temprn = get_reg((1<<rn) | (1<<rt) | (1<<rm) | (1<<temprt), 10);
	u4 temprm = get_reg((1<<rn) | (1<<rt) | (1<<rm) | (1<<temprt) | (1<<temprn), 10);

	/* push temp registers */
	ARM_PUSH3(ts->transl_instr, temprt, temprn, temprm);


	/* ldr(register) : rt, rn rm
	*/
	bool replace_rt = false;
	bool replace_rn = false;
	bool replace_rm = false;

	/* set temprn */
	if (rn == ARMREG_SP) {
		/* put original sp (sp + 12) into temprn */
		ARM_ADD_IMM12(ts->transl_instr, temprn, ARMREG_SP, 12);
		replace_rn = true;
	} else if (rn == ARMREG_PC) {
		/* put pc into temprn */
		gen_put_reg_imm32(ts, temprn, pc_value);
		replace_rn = true;
	} else {

	}

	if (rt == ARMREG_PC) {
		replace_rt = true;
	}

	if (insn & (1 << 25)) {
		/* shift/register */
		if (rm == ARMREG_SP) {
			/* put original sp (sp + 12) into temprm */
			ARM_ADD_IMM12(ts->transl_instr, temprm, ARMREG_SP, 12);
			replace_rm = true;
		}else if (rm == ARMREG_PC) {
			//put pc into temprm
			gen_put_reg_imm32(ts, temprm, pc_value);
			replace_rm = true;
		}
	}

	/* now patch original instruction */
	u4 tempinsn = insn;

	if (replace_rt) {
		tempinsn = (tempinsn & (~0xf000)) | (temprt<<12);
	}

	//patch original instruction
	if (replace_rm) {
		tempinsn = (tempinsn & (~0xf)) | temprm;
	}

	if (replace_rn) {
		tempinsn = (tempinsn & (~0xf0000)) | (temprn<<16);
	}

	ARM_RAW(ts->transl_instr, tempinsn);

	/* rt != pc,  rn == pc */
	if (rt != ARMREG_PC) {
		if (rt == ARMREG_SP) {
			//todo
			BT_DEBUG("sp as base");
			goto todo;
		}
		//restore temp register. rn == pc -> wback is false
		ARM_POP3(ts->transl_instr, temprt, temprn, temprm);

		return INS_PROCESSED;
	}

	/* slowest path: rt == 15, indirect jump */

	//now jump target is in temprt
	u4 jump_prologue_offset = gen_ijump_reg_arm_prologue(ts, temprt);
	gen_ijump_reg_arm(ts, temprt, jump_prologue_offset - 4);
	gen_ijump_reg_arm_epilogue(ts, -1);

	//restore temp register and stack
	/*
	 *          _______previous sp
	 *   |temprt
	 *   |temprn
	 *   |temprm
	 *   |real jump target____current sp
	 *
	 *
	 *  we need to restore temp registers and sp and then jump to target
	 */

	/* write back register if necessary! */
	if ((!(insn & (1 << 24))) || (insn & (1 << 21))) {
		/*p ==0 || w == 1 -> wback */
		if (rn == ARMREG_SP) {
			/* we can NOT just put temprn -> rn(sp) since
			 * it will change sp. (we need sp value to load the)
			 * jump target!!
			 */

			/* SP will be changed because of writing back.
			 *
			 * But we can not just put temprn to sp since we need
			 * sp to load jump target.
			 *
			 * solution: since sp will be changed, we can put the real
			 *           jump target to new stack first, and then change
			 *           sp to new stack. And then jump to real target.
			 *
			 *           In this solution, we change the value at
			 *           address (newsp -4). But it does not matter since
			 *           this memory address is next available (free)
			 *           space on the new stack.
			 *
			 */

			//1. put real target into temprt. (temprt can be used here)
			ARM_POP1(ts->transl_instr, temprt);
			//2. put newsp(temprn) on stack
			ARM_STR_IMM(ts->transl_instr, temprn, ARMREG_SP , -4);
			//3. put real target(temprt) into [newsp(temprn) - 4]
			ARM_STR_IMM(ts->transl_instr, temprt, temprn, -4);
			//4. restore temp registers
			ARM_POP3(ts->transl_instr, temprt, temprn, temprm);
			/*
			 *          ____current_sp
			 *   |temprt
			 *   |temprn
			 *   |temprm
			 *   |newsp
			 *
			 *
			 new stack:
			 *   |real_target

*/

			//5. change sp to newsp
			ARM_LDR_IMM(ts->transl_instr, ARMREG_SP, ARMREG_SP, -16);
			/*
			 *
			 *   |temprt
			 *   |temprn
			 *   |temprm
			 *   |newsp
			 *
			 *
			 new stack:    __current(new)_sp
			 *   |real_target

*/
			//6. jump to real target
			ARM_LDR_IMM(ts->transl_instr, ARMREG_PC, ARMREG_SP, -4);
			return INS_PROCESSED | INS_INDIRECT_JUMP;
		} else {
			if (replace_rn) {
				//temprn -> rn
				ARM_MOV_REG_REG(ts->transl_instr, rn, temprn);
			}
		}
	}

	//sp = sp + 4
	ARM_ADD_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);

	//pop up temp registers
	ARM_POP3(ts->transl_instr, temprt, temprn, temprm);

	//debug: generate lw [0]
	// gen_put_reg_imm32(ts, ARMREG_R0, 0);
	// ARM_LDR_IMM(ts->transl_instr, ARMREG_R0, ARMREG_R0,
	//                     0);

	//now sp and temp registers are restored, jump to target
	//target = [sp - 16]
	ARM_LDR_IMM(ts->transl_instr, ARMREG_PC, ARMREG_SP, -16);

	return INS_PROCESSED | INS_INDIRECT_JUMP;

todo:
	BT_ERR(true, "todo arm instruction 0x%-8x ", insn);
	return INS_TODO;
}

/* reglist != 0 */
static inline int find_first_set(u4 reglist) {
	int k = 0;

	if (reglist & 0xff00) { k += 8; reglist >>= 8; }
	if (reglist & 0x00f0) { k += 4; reglist >>= 4; }
	if (reglist & 0x000c) { k += 2; reglist >>= 2; }
	if (reglist & 0x0002) { k += 1;}

	return k;
}

/*find first highest zero bit in register list*/
static inline int find_first_zero(u4 reglist) {
	int k = 0;

	if ((reglist & 0xff00) != 0xff00) { k += 8; reglist >>= 8;}
	if ((reglist & 0x00f0) != 0x00f0) { k += 4; reglist >>= 4;}
	if ((reglist & 0x000c) != 0x000c) { k += 2; reglist >>= 2;}
	if ((reglist & 0x0002) != 0x0002) { k += 1;}

	return k;
}

//Counting bits set, Brian Kernighan's way
static inline int count_bit_set(u4 reglist){
	unsigned int c; // c accumulates the total bits set in v
	for (c = 0; reglist; c++)
	{
		reglist &= reglist - 1; // clear the least significant bit set
	}

	return c;
}

/*
 * generate block data transfer
 *
 * LDM(DA,DB) <RN>{!}, <register list>
 *
 */
ins_type gen_block_transfer(struct translate *ts, u4 insn, u4 pc_value) {
	/*fast path: instruction without pc in the list*/
	if (!(insn & 0x8000)) {
		return INS_COPY;
	}

	/* slow path: pc in register list */
	bool decrement = (insn & (1<<23)) ? false:true;
	bool before = (insn & (1<<24)) ? true:false;
	bool increment = !decrement;
	bool after = !before;

	//bool sp_in_list = (insn & (1<<13))?true:false;

	/* base register */
	u4 rn = (insn >> 16) & 0xf;

	//bool sp_is_base = (rn == ARMREG_SP)?true:false;

	bool wback = (insn & (1<<21))?true:false;

	u4 reglist = (insn & 0xffff);
	u4 regcnt = count_bit_set(reglist);

	u4 tempreg = -1;
	u4 tempinsn = insn;

	int offset = 0;

	/* store: pc in register list */
	if (!(insn & (1 << 20))) {
		//1. find a temp register
		tempreg = get_reg(1<<rn, 10);
		//2. push temp register on stack
		ARM_PUSH1(ts->transl_instr, tempreg);
		//3. pc_Value -> temp register
		gen_put_reg_imm32(ts, tempreg, pc_value);
		//4. put temp register (pc_value) into desired position
		/*
		 * address to store pc:
		 *  DA: Rn - 4*regcnt + 4 + 4 * (regcnt - 1) = Rn
		 *  DB: RN - 4*regcnt + 4*(regcnt - 1) = Rn - 4
		 *  IA: Rn + 4*(regcnt - 1) = Rn + 4*regcnt - 4
		 *  IB: Rn + 4 + 4*(regcnt-1) = Rn + 4*regcnt
		 */
		if (decrement) {
			if (after)
				offset = 0;
			else
				offset = -4;
		} else {
			if (after)
				offset = (regcnt - 1) <<2;
			else
				offset = (regcnt) <<2;
		}
		ARM_STR_IMM(ts->transl_instr, tempreg, rn, offset);
		//5. restore temp register
		ARM_POP1(ts->transl_instr, tempreg);

		//6. now storing other registers other than pc
		/*
		 *  We need to adjust rn register before storing other register
		 *
		 *
		 *   suppose original instruction:
		 *      STMDA  RN, Pc,reg2,reg1
		 *
		 *   after masking out pc, the instruction is:
		 *      STMDA  RN, reg2,reg1
		 *
		 *    |pc   _current rn
		 *    |xx
		 *    |xx
		 *
		 *  it will  reg1 into [rn-4] and reg2 into [rn] and overwrite pc!!!
		 *
		 *  so we need to adjust rn = rn - 4
		 *
		 *    |pc
		 *    |xx  __ adjusted rn
		 *    |xx
		 *
		 *  DA: rn = rn - 4
		 *  DB: rn = rn - 4
		 *  IA: 0
		 *  IB: 0
		 *
		 *
		 */
		if (regcnt != 1) {
			if (decrement) {
				ARM_SUB_IMM12(ts->transl_instr, rn, rn, 4)
			}
			//mask out bit 15
			tempinsn = (tempinsn & 0xffff7fff);
			ARM_RAW(ts->transl_instr, tempinsn);
		}

		//7. if write back, we need to adjust rn
		if (wback) {
			/*
			 *  DA: rn = rn  (we already decrease 4 before)
			 *  DB: rn = rn  (we already decrease 4 before)
			 *  IA: rn = rn + 4
			 *  IB: rn = rn + 4
			 */

			if (increment) {
				ARM_ADD_IMM12(ts->transl_instr, rn, rn, 4);
			}
		} else { //wback
			//restore the adjusted rn
			if (decrement) {
				ARM_ADD_IMM12(ts->transl_instr, rn, rn, 4)
			}
		}
		return INS_PROCESSED;
	}

	//load: pc in register list

	int jump_prologue_offset = 0;

	if (rn != ARMREG_SP) {
		//sp is not base register

		//1. find a temp register
		tempreg = get_reg((1<<rn) | (reglist), 10);

		//2. save temp register
		ARM_PUSH1(ts->transl_instr, tempreg);

		//3. load memory into temp register
		//mask out bit 15
		tempinsn = (tempinsn & 0xffff7fff);
		//set bit temp register
		tempinsn |= (1<<tempreg);
		ARM_RAW(ts->transl_instr, tempinsn);

		//4. jump to temp register
		jump_prologue_offset = gen_ijump_reg_arm_prologue(ts, tempreg);
		gen_ijump_reg_arm(ts, tempreg, jump_prologue_offset - 4);
		gen_ijump_reg_arm_epilogue(ts, -1);

		//5. restore temp register, sp and jump to real target
		//sp = sp + 4
		ARM_ADD_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 4);
		//pop temp register
		ARM_POP1(ts->transl_instr, tempreg);
		//now sp and temp register is restored, jump to target
		//target = [sp - 8]
		ARM_LDR_IMM(ts->transl_instr, ARMREG_PC, ARMREG_SP, -8);

		return INS_PROCESSED | INS_INDIRECT_JUMP;

	}

	//sp is base register.
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

	if ((increment) && (wback)) {
		//first load other registers
		if (regcnt != 1) {
			//mask out bit 15
			tempinsn = (tempinsn & 0xffff7fff);
			ARM_RAW(ts->transl_instr, tempinsn);
		}

		//1. get a temp register
		tempreg = get_reg((1<<rn), 10);
		//2. save temp register
		ARM_PUSH1(ts->transl_instr, tempreg);
		//3. jump target -> temp register
		ARM_LDR_IMM(ts->transl_instr, tempreg, ARMREG_SP, 4);
		/*
		 *
		 *   |jump target
		 *   |temp register ___current sp
		 *
		 *
		 */
		//4. jump to temp register
		jump_prologue_offset = gen_ijump_reg_arm_prologue(ts, tempreg);
		gen_ijump_reg_arm(ts, tempreg, jump_prologue_offset - 4);
		gen_ijump_reg_arm_epilogue(ts, -1);

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
		ARM_ADD_IMM12(ts->transl_instr, ARMREG_SP, ARMREG_SP, 12);
		//restore temp register
		ARM_LDR_IMM(ts->transl_instr, tempreg, ARMREG_SP, -8);
		//now sp and temp register is restored, jump to target
		//target = [sp - 12]
		ARM_LDR_IMM(ts->transl_instr, ARMREG_PC, ARMREG_SP, -12);

		return INS_PROCESSED | INS_INDIRECT_JUMP;
	} else {
		goto todo;
	}

todo:
	BT_ERR(true, "todo arm instruction 0x%-8x ", insn);
	return INS_TODO;
}


/* the dumped buffer can be disassembled by ODA
 *
 * http://www.onlinedisassembler.com/odaweb/run_hex
 *
 *
 */

// #define DIS_ARM_INSTRUCTION

#ifdef  DIS_ARM_INSTRUCTION
char dump_buffer[1024];
static void dump_translated_buffer(unsigned char * buf_start, u4 size) {
	unsigned char * c_buf;
	u4 index = 0;

	for (c_buf = buf_start; c_buf < buf_start + size; c_buf+= 4) {
		index+= sprintf(dump_buffer + index, "%x ", *(u4*)(c_buf));
	}

	BT_DEBUG_CLEAN("DUMP: %s", dump_buffer);
}
#endif

static void arm_debug_translation(struct translate *ts,
		unsigned char * old_transl_instr, u4 insn) {

#ifdef  DIS_ARM_INSTRUCTION
	u4 temp_insn;
	//dump the instruction
	dis_arm_instruction((u4)ts->cur_instr, insn);
	BT_DEBUG_CLEAN("[DIS]\t------------> ");
	dump_translated_buffer(old_transl_instr, (u4)(ts->transl_instr) -
			(u4)old_transl_instr);
	//disassemble the translated instructions
	for (; old_transl_instr < ts->transl_instr; ) {
		temp_insn = *(u4*)(old_transl_instr);
		dis_arm_instruction((u4)old_transl_instr, temp_insn);
		BT_DARM((u4)old_transl_instr, temp_insn);
		old_transl_instr += 4;
	}
	BT_DEBUG_CLEAN("[DIS]\n\n");
#endif

}

/*
 * decoding code is from qemu 12.0
 */
ins_type fbt_translate_instr_arm(struct translate *ts) {
	TRACE_ENTER;
	unsigned char *cur = (ts->cur_instr = ts->next_instr);

	u4 rm, cond, notcond, op1, sh;

	/* this must be signed type!!!*/
	s4 offset;

	u4 jump_address, jump_prologue_offset;

	//whether we should issue a condjmp here!
	bool condjmp = false;

	u4 insn = *((u4 *)cur);

	//u4 tempinsn = insn;

	//rn = (insn >> 16) & 0xf;
	//rs = (insn >> 12) & 0xf;
	//rd = (insn >> 8) & 0xf;
	rm = insn & 0xf;

	/* in ARM mode, pc is 8 bytes ahead */
	u4 pc_value = (u4)(ts->cur_instr) + 8;

	ins_type ret = 0;

	/* next instruction is 4 bytes ahead */
	ts->next_instr = cur + 4;

	unsigned char * old_transl_instr = ts->transl_instr;

	BT_DEBUG("translating instruction [0x%-8x-0x%-4x]", (u4)cur, insn);

	cond = insn >> 28;

	if (cond == 0xf){ /* 0x1111 */
		/* Unconditional instructions.  Page A5-25 on doc */
		if ((insn & 0x0e000000) == 0x0a000000) {    /* 1111 101x xxxx xxxx xxxx xxxx xxxx xxxx */
			/* branch link and change to thumb (blx <offset>) */
			offset = (((s4)insn << 8) >> 8);

			/* offset * 4 + bit24 * 2 + (thumb bit) */
			jump_address = pc_value + (offset << 2);
			jump_address |= (((insn >> 23) & 2) | 1);

			//see page A8-59 On doc. Next_instr_addr = pc - 4 in arm mode.
			gen_put_reg_imm32(ts, ARMREG_LR, (u4)(pc_value -4));

			gen_jump_arm(ts, jump_address, 0xff00);
			ret = INS_DIRECT_JUMP | INS_PROCESSED;
		} else {
			ret = INS_COPY;
		}
		goto end;
	}

	u4 original_transl;
	if (cond != 0xe) {
		/* if not always execute, we generate a conditional jump to
			 next instruction */
		notcond = cond ^ 1;
		/* if not condition, then jump to end*/
		/* offset will be patched later*/
		original_transl = (u4)(ts->transl_instr);
		ARM_B_COND(ts->transl_instr, notcond, 0);
		condjmp = true;
	}

	/*
	 *  Bit [27 26 25 24] == [0 0 1 1]
	 *  And BIT 23 = 0
	 *  And BIT 20 = 0
	 *
	 *  SEE A5.2 in doc:
	 *      op = 1
	 *      op1 = 10xx0
	 *
	 *   So it covers the last three rows in table A5-2.
	 *
	 */
	if ((insn & 0x0f900000) == 0x03000000) {			    /* xxxx 0011 0xx0 xxxx xxxx xxxx xxxx xxxx */
		if ((insn & (1 << 21)) == 0) {						    /* xxxx 0011 0x00 xxxx xxxx xxxx xxxx xxxx */
			/* MOVW */
			/* MOVT */
			//it's ok. since destination can not be pc
			ret = INS_COPY;
		} else {
			if (((insn >> 12) & 0xf) != 0xf)	
				goto illegal_op;
			if (((insn >> 16) & 0xf) == 0) {          /* xxxx 0011 0xx0 0000 xxxx xxxx xxxx xxxx */
				//WFE
				//WFI
				//SEV
				ret = INS_COPY;
			} else {
				/* CPSR = immediate */
				ret = INS_COPY;
			}
		}
	} else if ((insn & 0x0f900000) == 0x01000000      /* xxxx 0001 0xx0 xxxx xxxx xxxx xxxx xxxx */
			&& (insn & 0x00000090) != 0x00000090) {/*!xxxx xxxx xxxx xxxx xxxx xxxx 1xx1 xxxx */ 
		/*
		 *  Bit [27 26 25 24] == [0 0 0 1]
		 *  AND [23 22 21 20] == [0 x x 0]
		 *  And [7 6 5 4] == not [1 x x 1]
		 *
		 *  SEE A5.2 in doc:
		 *      op = 0
		 *      op1 = 10xx0
		 *      op2 = not [1 x x 1] -> [0 x x x] or [1 x x 0]
		 *
		 *   So it covers the third and fourth row in table A5-2.
		 *
		 */

		/* miscellaneous instructions */
		/* see A.5.2.12 on doc */
		op1 = (insn >> 21) & 3;    /* op1= xxxx xxxx xxbb xxxx xxxx xxxx xxxx xxxx */
		sh = (insn >> 4) & 0xf;    /* sh = xxxx xxxx xxxx xxxx xxxx xxxx bbbb xxxx */
		rm = insn & 0xf;           /* rm = xxxx xxxx xxxx xxxx xxxx xxxx xxxx bbbb */
		switch (sh) {
			case 0x0: /* move program status register */
				//MRS, MSR
				ret = INS_COPY;
				break;
			case 0x1:
				if (op1 == 1) {
					/* branch/exchange thumb (bx). */
					/* bx rm. Destination mode depends on last bit of rm. */
					if (rm == ARMREG_SP) {
						goto sp_used;
					}
					jump_prologue_offset = gen_ijump_reg_arm_prologue(ts, rm);
					gen_ijump_reg_arm(ts, rm, jump_prologue_offset - 4);
					gen_ijump_reg_arm_epilogue(ts, 0);
					ret = INS_INDIRECT_JUMP | INS_PROCESSED;
				} else if (op1 == 3) {
					/* clz */
					ret = INS_COPY;
				} else {
					goto illegal_op;
				}
				break;
			case 0x2:
				if (op1 == 1) {
					/* bxj */
					goto todo;
				} else {
					goto illegal_op;
				}
				break;
			case 0x3:
				if (op1 != 1)
					goto illegal_op;

				/* branch link/exchange thumb (blx) */
				/* blx rm */

				/*
				 *  put pc_value-4 to reg lr
				 */
				gen_put_reg_imm32(ts, ARMREG_LR, (u4)pc_value - 4);

				if (rm == ARMREG_SP) {
					goto sp_used;
				}

				//then jump to register rm
				jump_prologue_offset = gen_ijump_reg_arm_prologue(ts, rm); // return 16
				gen_ijump_reg_arm(ts, rm, jump_prologue_offset - 4);
				gen_ijump_reg_arm_epilogue(ts, 0);
				ret = INS_INDIRECT_JUMP | INS_PROCESSED;
				break;
			case 0x5: /* saturating add/subtract */
				ret = INS_COPY;
				break;
			case 0x7:
				/* SMC instruction (op1 == 3)
					 and undefined instructions (op1 == 0 || op1 == 2)
					 will trap */
				if (op1 != 1) {
					goto illegal_op;
				}
				/* bkpt */
				ret = INS_COPY;
				/* TODO: is this instruction allowed here? */
				break;
			case 0x8: /* signed multiply */
			case 0xa:
			case 0xc:
			case 0xe:
				/* see section A.5.4.4 on doc */
				ret = INS_COPY;
				break;
			default:
				goto illegal_op;
		}
	} else if (((insn & 0x0e000000) == 0 &&        
				(insn & 0x00000090) != 0x90) ||
			((insn & 0x0e000000) == (1 << 25))) {  /* xxxx 000x xxxx xxxx xxxx xxxx 1xx1 xxxx */
		/* or xxxx 001x xxxx xxxx xxxx xxxx xxxx xxxx */
		/*
		 *  (Bit [27 26 25 24] == [0 0 0 x]
		 *  And [7 6 5 4] == not [1 x x 1])
		 * or ([27 26 25] = [0 0 1])
		 *
		 *
		 *  SEE A5.2 in doc:
		 * case 1: op == 0
		 *         op1 == xxxx
		 *         op2 != [1 x x 1]
		 *    -> covers first and second rows (third and fourth rows have
		 *                                     been covered in previous *else*)
		 *       in table A5-2
		 *
		 * case 2: op == 1
		 *         op1 = xxxx
		 *         op2 = xxxx
		 *    -> covers 11th row (last three rows have been covered before)
		 *       in table A5-2
		 *
		 *
		 *  So, here we care about data-processing(Register,
		 *   register-shifted register, immediate) instructions
		 *
		 */
		ret = gen_data_processing(ts, insn, pc_value);

	} else {
		/* other instructions */
		op1 = (insn >> 24) & 0xf;	/* xxxx bbbb xxxx xxxx xxxx xxxx xxxx xxxx */
		switch (op1) {
			case 0x0:
			case 0x1:
				/*
				 * bit [27 26 25 24] == [0 0 0 x]
				 *  covers other rows in table A5-2 (Row 5-10)
				 *
				 */
				/* multiplies, extra load/stores */
				ret = INS_COPY;
				break;

			case 0x4:
			case 0x5:
				/*
				 * Load/store immediate offset
				 *
				 * bit [27 26 25 24] == [0 1 0 x]
				 *  covers row 2 in table A5-1. (page A5-2 on doc)
				 */
				goto do_ldst;

			case 0x6:
			case 0x7:
				/*
				 * Load/store register offset
				 *
				 * bit [27 26 25 24] == [0 1 1 x]
				 *  covers row 3/4 in table A5-1. (page A5-2 on doc)
				 */

				if (insn & (1 << 4)) {
					/* op = 1 on page A5-2. row 4 in table A5-1 */
					/* media instruction*/
					ret = INS_COPY;
					break;
				}

do_ldst:
				/* Rewhy: TODO address verification */
#ifdef DO_UAF_DETECT
				verify_ldstwb_arm(ts, insn, pc_value);
#endif
				ret = gen_ldstwb(ts, insn, pc_value);
				break;
			case 0x8:
			case 0x9:
				/*
				 * Load/store multiple
				 *
				 * bit [27 26 25 24] == [1 0 0 x]
				 * covers part of row 5 in table A5-1. (page A5-2 on doc)
				 *
				 *   see table A5-21 (page A5-23 on doc)
				 *   covers all the rows except last two
				 */
				/* Rewhy: TODO address verification */
				ret = gen_block_transfer(ts, insn, pc_value);
				break;
			case 0xa:
			case 0xb:
				/*
				 * bit [27 26 25 24] == [1 0 1 x]
				 *  covers part of row 5 in table A5-1. (page A5-2 on doc)
				 *
				 *   see table A5-21 (page A5-23 on doc)
				 *   covers last two rows in table A5-21
				 *
				 *   branch (And link)
				 */
				offset = (((s4)insn << 8) >> 8);
				jump_address = pc_value + (offset << 2);

				//BL<C> <label>
				if (insn & (1 << 24)) {
					//see page A8-59 On doc. Next_instr_addr = pc - 4 in arm mode.
					gen_put_reg_imm32(ts, ARMREG_LR, (u4)(pc_value - 4));
				}

				gen_jump_arm(ts, jump_address, 0xff00);
				ret = INS_DIRECT_JUMP | INS_PROCESSED;
				break;

			case 0xc:
#ifdef DO_UAF_DETECT
				verify_fldst_vfp_arm(ts, insn, pc_value);
#endif
				ret = INS_COPY;
				break;
			case 0xd:
				/* Coprocessor (FLDS/FLDD/FSTS/FSTD) */
#ifdef DO_UAF_DETECT
				verify_fldst_vfp_arm(ts, insn, pc_value);
#endif
				ret = gen_vldstr(ts, insn, pc_value);
				break;
			case 0xe:
				/* Coprocessor */
				ret = INS_COPY;
				break;
			case 0xf:
				/* swi */
				/* TODO: We need to hook this instruction. */
				/* Rewhy: TODO address verification */
				ret = INS_COPY;
				break;
		}
	}

end:
	/* now process the instruction according to ret */
	if (ret & INS_COPY) {
		ARM_RAW(ts->transl_instr, insn);
	}

	//if condition execution, we need to patch the offset here.
	if (condjmp) {
		if (ret & (INS_INDIRECT_JUMP | INS_DIRECT_JUMP)) {
			ret |= INS_CONDITIONAL_JUMP;
			BT_DEBUG("condition jump: arm instruction 0x%-8x ", insn);
		}
		u4 offset = (u4)ts->transl_instr - original_transl;
		//actual pc is 8 bytes ahead, so we need to minus 8 from here.
		//the offset is 4 bytes aligned.
		offset = (offset - 8) >> 2;
		//patch the pc based jump
		*(u4 *)original_transl = (*(u4 *)original_transl) | (offset & 0xffffff);
	}

	arm_debug_translation(ts, old_transl_instr, insn);
	TRACE_EXIT;
	return ret;

sp_used:
todo:
	BT_ERR(true, "todo arm instruction 0x%-8x ", insn);
illegal_op:
	BT_ERR(true, "illegal_op arm instruction 0x%-8x ", insn);

	TRACE_EXIT;
	return INS_TODO;
}
