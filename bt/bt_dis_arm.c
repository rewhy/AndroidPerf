#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <android/log.h>

#include "ba/ba.h"
#include "sandbox.h"
#include "asm.h"

#include "bt.h"
#include "bt_code_cache.h"
#include "bt_asm_macros.h"

#include "debug/debug.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG  "disassembler"

#define append_to_buf(fmt, x...) \
	do{ \
		buf_index += sprintf(dis_buf + buf_index, fmt, ##x); \
	} while(0)


static char condname[16][3] = {"eq", "ne", "cs", "cc",
	"mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt",
	"gt", "le", "al", "al"};

char opcode[32];
#define opcode(op) \
	do{ \
		sprintf(opcode, "%s<%s>", op, condname[cond]);\
		append_to_buf("%-10s", opcode);\
	} while(0)

static char regstr[16][4] = {"r0", "r1", "r2", "r3",
	"r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11",
	"ip", "sp", "lr", "pc"};

static char dregstr[16][4] = {"d0", "d1", "d2", "d3",
	"d4", "d5", "d6", "d7"};

static char sregstr[16][4] = {"s0", "s1", "s2", "s3",
	"s4", "s5", "s6", "s7",
	"s8", "s9", "s10", "s11",
	"s12", "s13", "s15", "s16"};

#define regname(index, append) \
	do{ \
		append_to_buf("%s%s", regstr[index], append);\
	} while(0)

#define dregname(index, append) \
	do{ \
		append_to_buf("%s%s", dregstr[index], append);\
	} while(0)

#define sregname(index, append) \
	do{ \
		append_to_buf("%s%s", sregstr[index], append);\
	} while(0)

// char regstr[8];
// volatile char * reg_name(int reg_index) {
//     memset(regstr, 0x0, sizeof(regstr));

//     switch (reg_index) {
//         case 13:
//             sprintf(regstr, "%s", "sp");
//             break;
//         case 14:
//             sprintf(regstr, "%s", "lr");
//             break;
//         case 15:
//             sprintf(regstr, "%s", "pc");
//             break;
//         default:
//             sprintf(regstr, "r%d", reg_index);
//             break;
//     }

//     return regstr;
// }

#define imm_shift(sh, imm5) \
	do{ \
		if ((sh) == 0) {append_to_buf(" LSL %d", imm5);} \
		if ((sh) == 1) {append_to_buf(" LSR %d", imm5);} \
		if ((sh) == 2) {append_to_buf(" ASR %d", imm5);} \
		if (((sh) == 3) && (imm5 == 0)) { append_to_buf(" RRX 1");} \
		if (((sh) == 3) && (imm5 != 0)) { append_to_buf(" ROR %d", imm5);} \
	} while(0)

void dis_arm_instruction(u4 addr, u4 insn) {

	u4 rn, rs, rd, dd, sd, rm, cond, i, op1, sh;

	/* this must be signed type!!!*/
	s4 offset;

	u4 jump_address, shift, imm5, bottom;

	bool add;

	u4 val;

	//whether we should issue a condjmp here!
	//bool condjmp = false;

	//u4 tempinsn = insn;

	rn = (insn >> 16) & 0xf;
	rs = (insn >> 12) & 0xf;
	rd = (insn >> 8) & 0xf;
	rm = insn & 0xf;

	cond = insn >> 28;

	char dis_buf[128];
	int buf_index = 0;
	memset(dis_buf, 0x0, sizeof(dis_buf));

	append_to_buf("[DIS] %-8x %-8x ", addr, insn);
	// append_to_buf("[DIS] %d %d %d %d ", rn, rs, rd, rm);

	if (cond == 0xf){
		if (((insn >> 25) & 7) == 1) {
			/* neon */
			append_to_buf("%s ", "neon data processing");
		} else if ((insn & 0x0f100000) == 0x04000000) {
			append_to_buf("%s ", "neon load store");
		}

		if ((insn & 0x0e000000) == 0x0a000000) {
			/* branch link and change to thumb (blx <offset>) */
			opcode("blx");

			offset = (((s4)insn << 8) >> 8);
			jump_address = (offset << 2);
			jump_address |= (((insn >> 23) & 2) | 1);

			append_to_buf("<pc + %d>", jump_address);
		} else {
			append_to_buf("%s: 0x%x ", "other unconditional insn", insn);
		}

		goto end;
	}

	// if (cond != 0xe) {
	//     condjmp = true;
	// }

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
	if ((insn & 0x0f900000) == 0x03000000) {
		if ((insn & (1 << 21)) == 0) {
			if ((insn & (1 << 22)) == 0) {
				opcode("movw");
			} else {
				opcode("movt");
			}
			// append_to_buf("%s, ", reg_name(rs));
			regname(rs, ", ");
			val = ((insn >> 4) & 0xf000) | (insn & 0xfff);
			append_to_buf("#0x%x", (u4)val);
		} else {
			if (((insn >> 12) & 0xf) != 0xf)
				goto illegal_op;
			if (((insn >> 16) & 0xf) == 0) {
				switch (insn & 0xff) {
					case 3:
						opcode("wfi");
						break;
					case 2:
						opcode("wfe");
						break;
					case 4:
						opcode("sev");
						break;
					default:
						opcode("nop");
						break;
				}
			} else {
				opcode("msr");
			}
		}
	} else if ((insn & 0x0f900000) == 0x01000000
			&& (insn & 0x00000090) != 0x00000090) {
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
		op1 = (insn >> 21) & 3;
		sh = (insn >> 4) & 0xf;
		// rm = insn & 0xf;
		switch (sh) {
			case 0x0: /* move program status register */
				if (op1 & 1) {
					opcode("msr");
					append_to_buf("<spec>, ");
					regname(rm, "");
				} else {
					opcode("mrs");
					regname(rs, ", ");
					append_to_buf("<spec>");
				}
				break;
			case 0x1:
				if (op1 == 1) {
					opcode("bx");
					// append_to_buf("%s", reg_name(rm));
					regname(rm, "");
				} else if (op1 == 3) {
					opcode("clz");
					// append_to_buf("%s, %s", reg_name(rs), reg_name(rm));
					regname(rs, ", ");
					regname(rm, "");
				} else {
					goto illegal_op;
				}
				break;
			case 0x2:
				if (op1 == 1) {
					/* bxj */
					opcode("bxj");
					// append_to_buf("%s", reg_name(rm));
					regname(rm, "");
				} else {
					goto illegal_op;
				}
				break;
			case 0x3:
				if (op1 != 1)
					goto illegal_op;

				/* branch link/exchange thumb (blx) */
				/* blx rm */
				opcode("blx");
				// append_to_buf("%s", reg_name(rm));
				regname(rm, "");
				break;
			case 0x5: /* saturating add/subtract */
				append_to_buf("%s", "saturating add/sub ");
				break;
			case 7:
				/* SMC instruction (op1 == 3)
					 and undefined instructions (op1 == 0 || op1 == 2)
					 will trap */
				if (op1 != 1) {
					goto illegal_op;
				}
				opcode("bkpt");
				/* TODO: is this instruction allowed here? */
				break;
			case 0x8: /* signed multiply */
			case 0xa:
			case 0xc:
			case 0xe:
				/* see section A.5.4.4 on doc */
				append_to_buf("%s", "signed multiply");
				break;
			default:
				goto illegal_op;
		}
	} else if (((insn & 0x0e000000) == 0 &&
				(insn & 0x00000090) != 0x90) ||
			((insn & 0x0e000000) == (1 << 25))) {

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
		//ret = gen_data_processing(ts, insn, pc_value);
		op1 = (insn >> 21) & 0xf;
		u4 op2 = (insn>>5) & 0x3;
		u4 op3 = (insn>>5) & 0x3;
		switch (op1) {
			case 0x0:
				opcode("and");
				break;
			case 0x1:
				opcode("eor");
				break;
			case 0x2:
				opcode("sub");
				break;
			case 0x3:
				opcode("rsb");
				break;
			case 0x4:
				opcode("add");
				break;
			case 0x5:
				opcode("adc");
				break;
			case 0x6:
				opcode("sbc");
				break;
			case 0x7:
				opcode("rsc");
				break;
			case 0x8:
				opcode("tst");
				break;
			case 0x9:
				opcode("teq");
				break;
			case 0xa:
				opcode("cmp");
				break;
			case 0xb:
				opcode("cmn");
				break;
			case 0xc:
				opcode("orr");
				break;
			case 0xd:
				if (insn & (1 << 25)) {
					//immediate
					opcode("mov");
				} else if (insn & (1 << 4)) {
					//register-shifted register
					if (op2 == 0) {
						opcode("lsl");
					} else if (op2 == 1) {
						opcode("lsr");
					}else if (op2 == 2) {
						opcode("asr");
					}else if (op2 == 3) {
						opcode("ror");
					}
				} else {
					if (op3 == 0) {
						if (insn & 0xf80)
							opcode("lsl");
						else
							opcode("mov");
					} else if (op3 == 1) {
						opcode("lsr");
					}else if (op3 == 2) {
						opcode("asr");
					}else if (op3 == 3) {
						if (insn & 0xf80)
							opcode("ror");
						else
							opcode("rrx");
					}
				}
				break;
			case 0xe:
				opcode("bic");
				break;
			case 0xf:
				opcode("mvn");
				break;
		}

		if (insn & (1 << 25)) {
			//immediate
			// append_to_buf("%s, %s, ", reg_name(rs), reg_name(rn));
			regname(rs, ", ");
			regname(rn, ", ");
			val = insn & 0xff;
			shift = ((insn >> 8) & 0xf) * 2;
			if (shift) {
				val = (val >> shift) | (val << (32 - shift));
			}
			append_to_buf("0x%x", val);
		} else if (insn & (1 << 4)) {
			//register shifted register
			if (op1 != 13) {
				// append_to_buf("%s, %s, %s, ", reg_name(rs), reg_name(rn),
				//                                        reg_name(rm));
				regname(rs, ", ");
				regname(rn, ", ");
				regname(rm, ", ");
				if (op2 == 0) {
					append_to_buf("LSL ");
				} else if (op2 == 1) {
					append_to_buf("LSR ");
				} else if (op2 == 2) {
					append_to_buf("ASR ");
				} else if (op2 == 3) {
					append_to_buf("ROR ");
				}
				// append_to_buf(" %s ",reg_name(rd));
				regname(rd, "");
			} else {
				// append_to_buf("%s, %s, %s, ", reg_name(rs), reg_name(rm),
				// reg_name(rd));
				regname(rs, ", ");
				regname(rm, ", ");
				regname(rd, ", ");
			}
		} else {
			if (op1 != 13) {
				// append_to_buf("%s, %s, %s, ", reg_name(rs), reg_name(rn),
				// reg_name(rm));
				regname(rs, ", ");
				regname(rn, ", ");
				regname(rm, ", ");

				if (op2 == 0) {
					append_to_buf("LSL ");
				} else if (op2 == 1) {
					append_to_buf("LSR ");
				} else if (op2 == 2) {
					append_to_buf("ASR ");
				} else if (op2 == 3) {
					append_to_buf("ROR ");
				}
			} else {
				if (op3 == 0) {
					if (insn & 0xf80) {
						// append_to_buf("%s, %s, ", reg_name(rs), reg_name(rm));
						regname(rs, ", ");
						regname(rm, ", ");
						append_to_buf("#0x%x", (insn >>12) & 0x1f);
					} else {
						// append_to_buf("%s, %s", reg_name(rs), reg_name(rm));
						regname(rs, ", ");
						regname(rm, "");
					}
				} else if (op3 == 1) {
					// append_to_buf("%s, %s, ", reg_name(rs), reg_name(rm));
					regname(rs, ", ");
					regname(rm, ", ");
					append_to_buf("#0x%x", (insn >>12) & 0x1f);
				}else if (op3 == 2) {
					// append_to_buf("%s, %s, ", reg_name(rs), reg_name(rm));
					regname(rs, ", ");
					regname(rm, ", ");
					append_to_buf("#0x%x", (insn >>12) & 0x1f);
				}else if (op3 == 3) {
					if (insn & 0xf80) {
						// append_to_buf("%s, %s, ", reg_name(rs), reg_name(rm));
						regname(rs, ", ");
						regname(rm, ", ");
						append_to_buf("#0x%x", (insn >>12) & 0x1f);
					} else {
						// append_to_buf("%s, %s", reg_name(rs), reg_name(rm));
						regname(rs, ", ");
						regname(rm, "");
					}
				}
			}
		}

	} else {
		/* other instructions */
		op1 = (insn >> 24) & 0xf;
		switch (op1) {
			case 0x0:
			case 0x1:
				/*
				 * bit [27 26 25 24] == [0 0 0 x]
				 *  covers other rows in table A5-2 (Row 5-10)
				 *
				 */
				/* multiplies, extra load/store */
				append_to_buf("%s", "multiplies, extra load/store");
				break;

			case 0x4:
			case 0x5:
				/*
				 * bit [27 26 25 24] == [0 1 0 x]
				 *  covers row 2 in table A5-1. (page A5-2 on doc)
				 */
				goto do_ldst;

			case 0x6:
			case 0x7:
				/*
				 * bit [27 26 25 24] == [0 1 1 x]
				 *  covers row 3/4 in table A5-1. (page A5-2 on doc)
				 */

				if (insn & (1 << 4)) {
					/* op = 1 on page A5-2. row 4 in table A5-1 */
					/* media instruction*/
					append_to_buf("%s", "media instruction");
					break;
				}

do_ldst:
				add = (insn & (1<<23))? true:false;
				imm5 = (insn >>7) & 0x1f;

				//ret = gen_ldstwb(ts, insn, pc_value);
				if (insn & (1<<20)) {
					//load

					if (insn & (1<<22)) {
						//bit 21 == 1  bit 24 = 0
						if ((insn & (1<<21)) && (!(insn & (1<<24)))) {
							opcode("ldrbt");
						} else {
							opcode("ldrb");
						}
					} else {
						//bit 21 == 1  bit 24 = 0
						if ((insn & (1<<21)) && (!(insn & (1<<24)))) {
							opcode("ldrt");
						} else {
							opcode("ldr");
						}
					}
				} else {
					//store
					if (insn & (1<<22)) {
						//bit 21 == 1  bit 24 = 0
						if ((insn & (1<<21)) && (!(insn & (1<<24)))) {
							opcode("strbt");
						} else {
							opcode("strb");
						}
					} else {
						//bit 21 == 1  bit 24 = 0
						if ((insn & (1<<21)) && (!(insn & (1<<24)))) {
							opcode("strt");
						} else {
							opcode("str");
						}
					}
				}
				// append_to_buf("%s, [%s], ", reg_name(rs), reg_name(rn));
				regname(rs, ", ");
				append_to_buf("[");
				regname(rn, "");
				if (insn & (1<<25)) {
					append_to_buf("], ");
					// append_to_buf("%s %s, ", add?"+":"-", reg_name(rm));
					append_to_buf("%s", add?" + ":" - ");
					regname(rm, ", ");
					imm_shift((insn >>5)&0x3, imm5);
				} else {
					//immediate
					append_to_buf("%s0x%x", add?" + ":" - ", insn & 0xfff);
					append_to_buf("]");
				}

				break;
			case 0x8:
			case 0x9:
				/*
				 * bit [27 26 25 24] == [1 0 0 x]
				 *  covers part of row 5 in table A5-1. (page A5-2 on doc)
				 *
				 *   see table A5-21 (page A5-23 on doc)
				 *   covers all the rows except last two
				 */
				//ret = gen_block_transfer(ts, insn, pc_value);

				op1 = (insn >> 22) & 0xf;
				bool load = (insn & (1<<20))?true:false;
				bool wback = (insn & (1<<21))?true:false;

				if (op1 == 0x0) {
					if (load)
						opcode("ldmda");
					else
						opcode("stmda");
				}else if (op1 == 0x2) {
					if (load)
						opcode("ldmia");
					else
						opcode("stmia");
				}else if (op1 == 0x4) {
					if (load)
						opcode("ldmdb");
					else
						opcode("stmdb");
				}else if (op1 == 0x6) {
					if (load)
						opcode("ldmib");
					else
						opcode("stmib");
				}

				// append_to_buf("%s %s,", reg_name(rn), (wback? "!":""));
				regname(rn, " ");
				append_to_buf("%s,", (wback? "!":""));

				append_to_buf(",{");
				for (i =0; i < 16; i ++) {
					if ((1<<i) & insn) {
						// append_to_buf("%s, ", reg_name(i));
						regname((i), ", ");
					}
				}
				append_to_buf("}");

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

				//BL<C> <label>
				if (insn & (1 << 24)) {
					opcode("b");
				} else {
					opcode("bl");
				}

				offset = (((s4)insn << 8) >> 8);
				offset = (offset << 2);

				append_to_buf("%d ", offset);
				break;

			case 0xc:
				/* Coprocessor */
				append_to_buf("%s ", "coop instruction");
				break;
			case 0xd:
				/* bit [21 20] == [0 1] */
				if(((insn>>20)&0x2) == 0x0){
					offset = (s4)((insn & 0xff)<<2);
					rn = (insn>>16) & 0xf;
					rd = (insn>>12) & 0xf;
					add = (insn & (0x1<<23)) ? true:false;
					if(((insn>>8) & 0xf) == 0xa){
						
						opcode((insn & (1 << 20)) ? "flds":"fsts");
						bottom = (insn>>22)&0x1;
						sd = rd * 2 + bottom;
						sregname(sd, ",");
					} else if(((insn>>8) & 0xf) == 0xb){
						dd = rd;
						opcode((insn & (1 << 20)) ? "fldd":"fstd");
						dregname(dd, ",");
					}
					append_to_buf(" %s", "[");
					regname(rn, "");
					if(offset > 0)
					{
						append_to_buf(", %s0x%x", add?"+":"-", offset); 
					}
					append_to_buf(" %s", "]");

				} else {
					append_to_buf("%s ", "coop instruction");
				}
				break;
			case 0xe:
				/* Coprocessor */
				append_to_buf("%s ", "coop instruction");
				break;
			case 0xf:
				/* swi */
				/* TODO: We need to hook this instruction. */
				opcode("swi");
				break;
		}
	}

end:
	//dump the buffer
	//INSN_INFO(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);

	return;

	//sp_used:
	//todo:
	//    BT_ERR(true, "todo arm instruction 0x%-8x ", insn);
illegal_op:
	BT_ERR(true, "illegal_op arm instruction 0x%-8x ", insn);
}
