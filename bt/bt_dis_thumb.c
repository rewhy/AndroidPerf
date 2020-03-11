#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <android/log.h>

#include "ba/ba.h"
#include "debug/debug.h"

#include "sandbox.h"
#include "asm.h"

#include "bt.h"
#include "bt_code_cache.h"
#include "bt_asm_macros.h"



#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG  "disassembler"

#define append_to_buf(fmt, x...) \
	do{ \
		buf_index += sprintf(dis_buf + buf_index, fmt, ##x); \
	} while(0)

static char regstr[16][4] = {"r0", "r1", "r2", "r3",
	"r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11",
	"ip", "sp", "lr", "pc"};

#define regname(index, append) \
	do{ \
		append_to_buf("%s%s", regstr[index], append);\
	} while(0)


void dis_thumb2_instruction(u4 addr, u4 insn) {
	u4 rn, rs, rd, rm, imm, dd, sd;

	rn = (insn >> 16) & 0xf;
	rs = (insn >> 12) & 0xf;
	rd = (insn >> 8) & 0xf;
	rm = insn & 0xf;

	u4 load, op, i, shift, shiftop, logic_cc, bottom;
	char dis_buf[128];
	int buf_index = 0;

	s4 offset;

	u4 add, index, wb;
	memset(dis_buf, 0x0, sizeof(dis_buf));

	append_to_buf("[DIS] %-8x %-8x ", addr, insn);

	switch ((insn >> 25) & 0xf) {
		case 0:
		case 1:
		case 2:
		case 3:
			/* 16-bit instructions.  Should never happen.  */
			goto illegal;
		case 4:
			load = (insn & (1 << 20));
			if ((insn & (1 << 22))) {
				/* see 3-28 in doc2 */
				/* Load/store doubleword. table branch  */

				if ((insn & 0x01200000) == 0) {
					/* Load/store doubleword.  */
					/* ldrd <rs>, <rd>, [rn, #imm] */
					if (load) {
						append_to_buf("%-8s ", "ldrd");
					} else {
						append_to_buf("%-8s ", "strd");
					}

					// append_to_buf("%s, %s, ", reg_name(rs), reg_name(rd));
					regname(rs, ", ");
					regname(rd, ", ");

					offset = (insn & 0xff) * 4;

					// append_to_buf("[%s", reg_name(rn));
					append_to_buf("[");
					regname(rn, ", ");

					if (insn & (1 << 24)) {
						append_to_buf("], #");
					} else {
						append_to_buf(", #");
					}

					if ((insn & (1 << 23)) == 0) {
						append_to_buf("- 0x%8x", (u4)offset);
					} else {
						append_to_buf("+ 0x%8x", (u4)offset);
					}

					if (!(insn & (1 << 24))) {
						append_to_buf("]");
					}

					if (!(insn & (1 << 21))) {
						append_to_buf("{!}");
					}

				} else if ((insn & (1 << 23)) == 0) {
					/* Load/store exclusive word.  */
					/* LDREX<c> <rs>,[<Rn>{,#<imm>}] */
					//rn/rs can not be reg 15. so its ok
					if (insn & (1 << 20)) {
						append_to_buf("%-8s ", "ldrex");
					} else {
						append_to_buf("%-8s ", "strex");
					}
					// append_to_buf("%s, [%s, #0x%8x] ",
					// reg_name(rs), reg_name(rn), (insn & 0xff));

					regname(rs, ", ");
					append_to_buf("[");
					regname(rn, ", ");
					append_to_buf("#0x%8x]",  (insn & 0xff));

				} else if ((insn & (1 << 6)) == 0) {
					/* Table Branch. */
					if (insn & (1 << 4)) {
						//tbh
						append_to_buf("%-8s ", "tbh");
					} else {
						//tbb
						append_to_buf("%-8s ", "tbb");
					}
					// append_to_buf("[%s, %s]", reg_name(rn), reg_name(rm));
					append_to_buf("[");
					regname(rn, ", ");
					regname(rm, "]");
				} else {
					/* Load/store exclusive byte/halfword/doubleword.  */
					// destination/src reg can not be pc
					op = ((insn >> 4) & 0xf) |((insn >>20) << 4);
					// if (op == 2) {
					//     goto illegal;
					// }
					switch (op) {
						case 0x14:
							append_to_buf("%-8s ", "ldrexb");
							// append_to_buf("%s, [%s] ", reg_name(rs),
							// reg_name(rn));


							regname(rs, ", ");
							append_to_buf("[");
							regname(rn, "]");
							break;
						case 0x15:
							append_to_buf("%-8s ", "ldrexh");
							// append_to_buf("%s, [%s] ", reg_name(rs),
							//                             reg_name(rn));
							regname(rs, ", ");
							append_to_buf("[");
							regname(rn, "]");
							break;
						case 0x17:
							append_to_buf("%-8s ", "ldrexd");
							// append_to_buf("%s, %s, [%s] ", reg_name(rs),
							// reg_name(rd), reg_name(rn));
							regname(rs, ", ");
							regname(rd, ", ");
							append_to_buf("[");
							regname(rn, "]");
							break;
						case 0x4:
							append_to_buf("%-8s ", "strexb");
							// append_to_buf("%s, %s, [%s] ", reg_name(rm),
							// reg_name(rs), reg_name(rn));
							regname(rm, ", ");
							regname(rs, ", ");
							append_to_buf("[");
							regname(rn, "]");
							break;
						case 0x5:
							append_to_buf("%-8s ", "strexh");
							// append_to_buf("%s, %s, [%s] ", reg_name(rm),
							// reg_name(rs), reg_name(rn));
							regname(rm, ", ");
							regname(rs, ", ");
							append_to_buf("[");
							regname(rn, "]");
							break;
						case 0x7:
							append_to_buf("%-8s ", "strexd");
							// append_to_buf("%s, %s, %s, [%s] ", reg_name(rm),
							// reg_name(rs), reg_name(rd), reg_name(rn));
							break;
							regname(rm, ", ");
							regname(rs, ", ");
							regname(rd, ", ");
							append_to_buf("[");
							regname(rn, "]");
						default:
							goto illegal;
					}
				}
			} else {
				/* Load/store multiple, RFE, SRS.  */
				if (((insn >> 23) & 1) == ((insn >> 24) & 1)) {
					/* RFE, SRS.*/
					/* Not available in user mode.  */
					goto illegal;
				} else {
					/* Load/store multiple.  */
					if (insn & (1 << 20)) {
						if (insn & (1<<24)) {
							append_to_buf("%-8s ", "ldmdb");
						} else {
							if ((insn & (1 << 21)) && (rn == 13)) {
								append_to_buf("%-8s ", "pop");
								append_to_buf("{");
								for (i =0; i < 16; i ++) {
									if ((1<<i) & insn) {
										// append_to_buf("%s, ", reg_name(i));
										regname((i), ", ");
									}
								}
								append_to_buf("}");
								break;
							} else {
								append_to_buf("%-8s ", "ldmia");
							}
						}

					} else {
						if (insn & (1<<24)) {
							append_to_buf("%-8s ", "stmdb");
						} else {
							append_to_buf("%-8s ", "stmia");
						}
					}
					// append_to_buf("%s", reg_name(rn));
					regname(rn, "");
					if (insn & (1 << 21)) {
						append_to_buf("{!}");
					}
					append_to_buf(",{");
					for (i =0; i < 16; i ++) {
						if ((1<<i) & insn) {
							// append_to_buf("%s, ", reg_name(i));
							regname((i), ", ");
						}
					}
					append_to_buf("}");

				}
			}
			break;

		case 5:
			op = (insn >> 21) & 0xf;
			if (op == 6) {
				/* Halfword pack.  */
				/* it's ok since destination reg can not be pc */
				if (insn & (1 << 5)) {
					///* pkhtb */
					append_to_buf("%-8s ", "pkhtb");
				} else {
					append_to_buf("%-8s ", "pkhbt");
				}
				// append_to_buf("%s, %s, %s", reg_name(rd),
				// reg_name(rn), reg_name(rm));
				regname(rd, ", ");
				regname(rn, ", ");
				regname(rm, "");
				shift = ((insn >> 10) & 0x1c) | ((insn >> 6) & 0x3);
				if (insn & (1 << 5)) {
					///* pkhtb */
					if (shift == 0)
						shift = 31;
					append_to_buf("{, LSL #%d}", shift);
				} else {
					append_to_buf("{, ASR #%d}", shift);
				}
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

				shift = ((insn >> 6) & 3) | ((insn >> 10) & 0x1c);
				shiftop = (insn >> 4) & 3;
				switch (op) {
					case 0x0:
						append_to_buf("%-8s ", "and");
						// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
						// reg_name(rm), shift);
						regname(rd, ", ");
						regname(rn, ", ");
						regname(rm, ", ");
						append_to_buf("(,#%d)", shift);
						break;
					case 0x1:
						append_to_buf("%-8s ", "bic");
						// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
						// reg_name(rm), shift);
						regname(rd, ", ");
						regname(rn, ", ");
						regname(rm, ", ");
						append_to_buf("(,#%d)", shift);
						break;
					case 0x2:
						if (rd != 15) {
							append_to_buf("%-8s ", "orr");
							// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
							// reg_name(rm), shift);
							regname(rd, ", ");
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(,#%d)", shift);
						} else {
							if (shiftop == 0) {
								if (shift !=0) {
									append_to_buf("%-8s ", "lsl");
									// append_to_buf("%s, %s, #%d ", reg_name(rd),
									// reg_name(rm), shift);
									regname(rd, ", ");
									regname(rm, ", ");
									append_to_buf("#%d", shift);
								} else {
									append_to_buf("%-8s ", "mov");
									// append_to_buf("%s, %s", reg_name(rd),
									// reg_name(rm));
									regname(rd, ", ");
									regname(rm, "");
								}

							} else if (shiftop == 1) {
								append_to_buf("%-8s ", "lsr");
								// append_to_buf("%s, %s, #%d ", reg_name(rd),
								// reg_name(rm), shift);
								regname(rd, ", ");
								regname(rm, ", ");
								append_to_buf("#%d", shift);
							} else if (shiftop == 2) {
								append_to_buf("%-8s ", "asr");
								// append_to_buf("%s, %s, #%d ", reg_name(rd),
								// reg_name(rm), shift);
								regname(rd, ", ");
								regname(rm, ", ");
								append_to_buf("#%d", shift);
							} else if (shiftop == 3) {
								if (shift == 0) {
									append_to_buf("%-8s ", "rrx");
									// append_to_buf("%s, %s", reg_name(rd),
									// reg_name(rm));
									regname(rd, ", ");
									regname(rm, "");

								} else {
									append_to_buf("%-8s ", "ror");
									// append_to_buf("%s, %s, #%d ", reg_name(rd),
									// reg_name(rm), shift);
									regname(rd, ", ");
									regname(rm, ", ");
									append_to_buf("#%d", shift);
								}
							}
						}
						break;
					case 0x3:
						if (rd == 15) {
							append_to_buf("%-8s ", "mvn");
							// append_to_buf("%s, %s, (,#%d) ", reg_name(rd),
							// reg_name(rm), shift);
							regname(rd, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						}
						else {
							append_to_buf("%-8s ", "orn");
							// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
							// reg_name(rm), shift);
							regname(rd, ", ");
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						}

						break;

					case 0x4:
						if ((rd == 15) && (insn &(1<<20))){
							append_to_buf("%-8s ", "teq");
							// append_to_buf("%s, #%d ",  reg_name(rn),
							// shift);
							regname(rn, ", ");
							append_to_buf("#%d", shift);
						} else {
							append_to_buf("%-8s ", "eor");
							// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
							// reg_name(rm), shift);
							regname(rd, ", ");
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						}

						break;
					case 0x8:
						if ((rd == 15) && (insn &(1<<20))) {
							append_to_buf("%-8s ", "cmn");
							// append_to_buf("%s, %s, (,#%d) ",  reg_name(rn),
							// reg_name(rm), shift);
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						}

						else {
							append_to_buf("%-8s ", "add");
							// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
							// reg_name(rm), shift);
							regname(rd, ", ");
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						}

						break;
					case 10:
						append_to_buf("%-8s ", "adc");
						// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
						// reg_name(rm), shift);
						regname(rd, ", ");
						regname(rn, ", ");
						regname(rm, ", ");
						append_to_buf("(#%d)", shift);
						break;
					case 11:
						append_to_buf("%-8s ", "sbc");
						// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
						// reg_name(rm), shift);
						regname(rd, ", ");
						regname(rn, ", ");
						regname(rm, ", ");
						append_to_buf("(#%d)", shift);
						break;
					case 13:
						if ((rd == 15) && (insn &(1<<20))) {
							append_to_buf("%-8s ", "cmp");
							// append_to_buf("%s, %s, (,#%d) ", reg_name(rn),
							// reg_name(rm), shift);
							// regname(rd, ", ");
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						} else {
							append_to_buf("%-8s ", "sub");
							// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
							// reg_name(rm), shift);
							regname(rd, ", ");
							regname(rn, ", ");
							regname(rm, ", ");
							append_to_buf("(#%d)", shift);
						}

						break;
					case 14:
						append_to_buf("%-8s ", "rsb");
						// append_to_buf("%s, %s, %s, (,#%d) ", reg_name(rd),reg_name(rn),
						// reg_name(rm), shift);
						regname(rd, ", ");
						regname(rn, ", ");
						regname(rm, ", ");
						append_to_buf("(#%d)", shift);
						break;
					default:
						goto illegal;
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
					op = (insn >> 21) & 3;
					logic_cc = (insn & (1 << 20)) != 0;
					if (op == 0) {
						append_to_buf("%s", "lsl");
					} else if (op ==1) {
						append_to_buf("%s", "lsr");
					} else if (op == 2) {
						append_to_buf("%s", "asr");
					} else if (op ==3) {
						append_to_buf("%s", "ror");
					}
					if (logic_cc) {
						append_to_buf(".c");
					}
					append_to_buf(".w    ");
					// append_to_buf("%s, %s, %s ", reg_name(rd),reg_name(rn),
					// reg_name(rm));
					regname(rd, ", ");
					regname(rn, ", ");
					regname(rm, "");

				case 1:
					/* Sign/zero extend.  */
					/*it's fine*/
					append_to_buf("Sign/zero extend");
					break;
					goto todo;
				case 2:
					/* SIMD add/subtract.  */
					/*it's fine*/
					append_to_buf("SIMD add/substract");
					// goto todo;
					break;
				case 3:
					/* Other data processing.  */
					append_to_buf("Other data processing");
					// goto todo;
					break;
				case 4:
				case 5:
					/* 32-bit multiply.  Sum of absolute differences.  */
					append_to_buf("32-bit multiply");
					// goto todo;
					break;
				case 6:
				case 7:
					append_to_buf("64-bit multiply and divide");
					// goto todo;
					break;
			}
			break;
		case 6:
		case 7:
		case 14:
		case 15:
			/* Coprocessor.  */
			//goto illegal;
			if (((insn >> 24) & 3) == 3) {
				append_to_buf("%s ", "neon");
			} else {
				switch ((insn >> 8) & 0xf) {
					case 10:
					case 11:
						/* vfp instruction */
						/* bit [21 20] == [0 1] */
						if(((insn>>20)&0x2) == 0x0){
							offset = (s4)((insn & 0xff)<<2);
							rn = (insn>>16) & 0xf;
							rd = (insn>>12) & 0xf;
							add = (insn & (0x1<<23)) ? true:false;
							if(((insn>>8) & 0xf) == 0xa){

								append_to_buf("%s ", (insn & (1 << 20)) ? "flds":"fsts");
								bottom = (insn>>22)&0x1;
								sd = rd * 2 + bottom;
								regname(sd, ", ");
							} else if(((insn>>8) & 0xf) == 0xb){
								dd = rd;
								append_to_buf("%s ", (insn & (1 << 20)) ? "fldd":"fstd");
								regname(dd, ", ");
							}
							append_to_buf("%s", "[");
							regname(rn, "");
							if(offset > 0)
							{
								append_to_buf(", %s0x%x", add?"+":"-", offset); 
							}
							append_to_buf(" %s", "]");

						} else {
							append_to_buf("%s ", "vfp instruction");
						}
						break;
					case 15:
						append_to_buf("%s ", "mrc instruction");
						break;
					default:
						goto illegal;
				}
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

					if (insn & (1 << 12)) {
						if (insn & (1<<14)) {
							append_to_buf("%-8s ", "bl");
						} else {
							append_to_buf("%-8s ", "b");
						}
					} else {
						append_to_buf("%-8s ", "blx");
					}

					append_to_buf("%d", offset);
				} else if (((insn >> 23) & 7) == 7) {
					/* Misc control */
					/* not implementation */
					/* MRS/MSR */
					if ((insn &(0xffeff0ff)) == 0xf3ef8000) {
						//MRS
						append_to_buf("%-8s ", "mrs");
						// append_to_buf("%s, ", reg_name(rd));
						regname(rd, ", ");
						if (insn & (1<<20)) {
							append_to_buf("spsr");
						} else {
							append_to_buf("cpsr");
						}
					} else if ((insn &(0xffe0f0ff)) == 0xf3808000) {
						//MSR
						append_to_buf("%-8s ", "msr");

						if (insn & (1<<20)) {
							append_to_buf("spsr_");
						} else {
							append_to_buf("cpsr_");
						}

						if (insn & (1<<11)) {
							append_to_buf("nzcvq");
						}

						if (insn & (1<<10)) {
							append_to_buf("g");
						}

						// append_to_buf(", %s", reg_name(rn));
						append_to_buf(",");
						regname(rn, "");

					} else {
						goto illegal;
					}
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

					u4 cond = (insn >> 22) & 0xf;

					/* conditional branch*/
					switch (cond) {
						case 0x0:
							append_to_buf("%-8s ", "beq");
							break;
						case 0x1:
							append_to_buf("%-8s ", "bne");
							break;
						case 0x2:
							append_to_buf("%-8s ", "bcs");
							break;
						case 0x3:
							append_to_buf("%-8s ", "bcc");
							break;
						case 0x4:
							append_to_buf("%-8s ", "bmi");
							break;
						case 0x5:
							append_to_buf("%-8s ", "bpl");
							break;
						case 0x6:
							append_to_buf("%-8s ", "bvs");
							break;
						case 0x7:
							append_to_buf("%-8s ", "bvc");
							break;

						case 0x8:
							append_to_buf("%-8s ", "bhi");
							break;
						case 0x9:
							append_to_buf("%-8s ", "bls");
							break;
						case 0xa:
							append_to_buf("%-8s ", "bge");
							break;
						case 0xb:
							append_to_buf("%-8s ", "blt");
							break;
						case 0xc:
							append_to_buf("%-8s ", "bgt");
							break;
						case 0xd:
							append_to_buf("%-8s ", "ble");
							break;
					}

					append_to_buf("0x%-8x ", offset);
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
						shift = ((insn >> 6) & 3) | ((insn >> 10) & 0x1c);
						switch (op) {
							case 2:
								/* Signed bitfield extract.  */
							case 6:
								/* Unsigned bitfield extract.  */
							case 3:
								/* Bitfield insert/clear.  */
								/* IF RN=15, -> BFC */
								append_to_buf("%s ", "Bitfield");
								break;
								goto todo;
							case 7:
								goto illegal;
							default: /* Saturate.  */
								append_to_buf("%s ", "Saturate");
								goto todo;
						}
					} else { /* bit 24 == 0*/
						/* bit 24 = 0. see 3-13 in doc2. 3-15 */
						imm = ((insn & 0x04000000) >> 15)
							| ((insn & 0x7000) >> 4) | (insn & 0xff);
						if (insn & (1 << 22)) {
							//16 bits imm
							imm |= (insn >> 4) & 0xf000;
							/* movt */
							/* movw */
							if (insn & (1<<23)) {
								append_to_buf("%-8s ", "movt");
							} else {
								append_to_buf("%-8s ", "movw");
							}

							// append_to_buf("%s, #0x%-8x ", reg_name(rd), imm);
							regname(rd, ", ");
							append_to_buf("#0x%-8x ", imm);
						} else {

							if (rn == 15) {
								/*adr. see 4-28 in doc2*/
								imm = ((insn & 0x04000000) >> 15)
									| ((insn & 0x7000) >> 4) | (insn & 0xff);
								// offset = pc_value & ~(uint32_t)3;
								// if (insn & (1 << 23))
								//     offset -= imm;
								// else
								//     offset += imm;
								append_to_buf("%-8s ", "adr.w");
								// append_to_buf("%s, pc %s #0x%-8x ", reg_name(rd),
								// (insn & (1 << 23))?"-":"+", imm);
								regname(rd, ", ");
								append_to_buf("pc %s #0x%-8x ",
										(insn & (1 << 23))?"-":"+", imm);
							} else {
								if (insn & (1<<23)) {
									//sub
									append_to_buf("%-8s ", "subw");
								} else {
									append_to_buf("%-8s ", "addw");
								}

								imm = ((insn & 0x04000000) >> 15)
									| ((insn & 0x7000) >> 4) | (insn & 0xff);

								// append_to_buf("%s, %s, #0x%-8x ", reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#0x%-8x ", imm);
							}
						}
					}
				}  else { //bit 25 == 0
					/* modified 12-bit immediate.  */
					/* SEE page 3-14 in doc2*/
					//goto todo;
					op = (insn >> 21) & 0xf;
					shift = ((insn & 0x04000000) >> 23) | ((insn & 0x7000) >> 12);
					imm = (insn & 0xff);
					switch (shift) {
						case 0: /* XY */
							/* Nothing to do.  */
							break;
						case 1: /* 00XY00XY */
							imm |= imm << 16;
							break;
						case 2: /* XY00XY00 */
							imm |= imm << 16;
							imm <<= 8;
							break;
						case 3: /* XYXYXYXY */
							imm |= imm << 16;
							imm |= imm << 8;
							break;
						default: /* Rotated constant.  */
							shift = (shift << 1) | (imm >> 7);
							imm |= 0x80;
							imm = imm << (32 - shift);
							break;
					}
					switch (op) {
						case 0x0:
							if (rd == 15) {
								append_to_buf("%-8s ", "tst");
								// append_to_buf("%s, #%d ", reg_name(rn), imm);
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							} else {
								append_to_buf("%-8s ", "and");
								// append_to_buf("%s, %s, #%d ",reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							}
							break;
						case 0x1:
							append_to_buf("%-8s ", "bic");
							// append_to_buf("%s, %s ,#%d ", reg_name(rd),
							// reg_name(rn), imm);
							regname(rd, ", ");
							regname(rn, ", ");
							append_to_buf("#%d ", imm);
							break;
						case 0x2:
							if (rn == 15) {
								append_to_buf("%-8s ", "mov");
								// append_to_buf("%s, #%d ", reg_name(rd), imm);
								regname(rd, ", ");
								append_to_buf("#%d ", imm);
							} else {
								append_to_buf("%-8s ", "orr");
								// append_to_buf("%s, %s, #%d ",reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							}
							break;
						case 0x3:
							if (rn == 15) {
								append_to_buf("%-8s ", "mvn");
								// append_to_buf("%s, #%d ", reg_name(rd), imm);
								regname(rd, ", ");
								append_to_buf("#%d ", imm);
							} else {
								append_to_buf("%-8s ", "orn");
								// append_to_buf("%s, %s, #%d ",reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							}
							break;
						case 0x4:
							if (rd == 15) {
								append_to_buf("%-8s ", "teq");
								// append_to_buf("%s, #%d ", reg_name(rn), imm);
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							} else {
								append_to_buf("%-8s ", "eor");
								// append_to_buf("%s, %s ,#%d ", reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							}

							break;
						case 0x8:
							if (rd == 15) {
								append_to_buf("%-8s ", "cmn");
								// append_to_buf("%s, #%d ", reg_name(rn), imm);
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							} else {
								append_to_buf("%-8s ", "add");
								// append_to_buf("%s, %s ,#%d ", reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							}
							break;
						case 10:
							append_to_buf("%-8s ", "adc");
							// append_to_buf("%s, %s ,#%d ", reg_name(rd),
							// reg_name(rn), imm);
							regname(rd, ", ");
							regname(rn, ", ");
							append_to_buf("#%d ", imm);
							break;
						case 11:
							append_to_buf("%-8s ", "sbc");
							// append_to_buf("%s, %s ,#%d ", reg_name(rd),
							// reg_name(rn), imm);
							regname(rd, ", ");
							regname(rn, ", ");
							append_to_buf("#%d ", imm);
							break;
						case 13:
							if (rd == 15) {
								append_to_buf("%-8s ", "cmp");
								// append_to_buf("%s, #%d ", reg_name(rn), imm);
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							} else {
								append_to_buf("%-8s ", "sub");
								// append_to_buf("%s, %s ,#%d ", reg_name(rd),
								// reg_name(rn), imm);
								regname(rd, ", ");
								regname(rn, ", ");
								append_to_buf("#%d ", imm);
							}

							break;
						case 14:
							append_to_buf("%-8s ", "rsb");
							// append_to_buf("%s, %s ,#%d ", reg_name(rd),
							// reg_name(rn), imm);
							regname(rd, ", ");
							regname(rn, ", ");
							append_to_buf("#%d ", imm);
							break;
						default:
							goto illegal;
					}
				}
			}
			break; //case 8 9 10 11
		case 12:
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
						append_to_buf("PLD/PLDW/PLI");
						goto todo;
					}
					int op1 = (insn >> 23) & 3;
					int op2 = (insn >> 6) & 0x3f;

					if (op1 & 1) {
						append_to_buf("PLD/PLDW/PLI1");
						goto todo;; /* PLD/PLDW/PLI or unallocated hint */
					}
					if ((op2 == 0) || ((op2 & 0x3c) == 0x30)) {
						append_to_buf("PLD/PLDW/PLI2");
						goto todo;; /* PLD/PLDW/PLI or unallocated hint */
					}
					/* UNDEF space, or an UNPREDICTABLE */
					goto undefined;
				}
			}

			// if (rn == 13) {
			//     //sp as base register!!!
			//     goto todo;
			// }

			//rn : base reg.  rs: target reg
			/* PC Relative load.*/
			if (rn == 15) {
				imm = 0;
				if (insn & (1 << 23))
					imm += insn & 0xfff;
				else
					imm -= insn & 0xfff;
			}
			//load
			if (insn & (1 << 20)) {
				switch (op) {
					case 0:
						append_to_buf("%-8s ", "ldrb");
						break;
					case 1:
						append_to_buf("%-8s ", "ldrh");
						break;
					case 2:
						append_to_buf("%-8s ", "ldr");
						break;
					case 4:
						append_to_buf("%-8s ", "ldrsb");
						break;
					case 5:
						append_to_buf("%-8s ", "ldrsh");
						break;
				}

			} else {
				switch (op) {
					//store
					case 0:
						append_to_buf("%-8s ", "strb");
						break;
					case 1:
						append_to_buf("%-8s ", "strh");
						break;
					case 2:
						append_to_buf("%-8s ", "str");
						break;
				}
			}

			if (insn & (1 << 23)) {
				/* Positive offset.  */
				imm = insn & 0xfff;
				// append_to_buf("%s, [%s, #0x%-8x]",  reg_name(rs), reg_name(rn),
				// imm);
				regname(rs, ", ");
				append_to_buf("[");
				regname(rn, ", ");
				append_to_buf("#0x%-8x]", imm);

			} else {
				imm = insn & 0xff;
				switch ((insn >> 8) & 0xf) {
					case 0x0: /* Shifted Register.  */
						shift = (insn >> 4) & 0xf;
						// append_to_buf("%s, [%s, %s, LSL #%d]",  reg_name(rs), reg_name(rn),
						// reg_name(rm), shift);
						regname(rs, ", ");
						append_to_buf("[");
						regname(rn, ", ");
						regname(rm, ", LSL ");
						append_to_buf("#%d]", shift);
						break;
					case 0xc: /* Negative offset.  */
						// append_to_buf("%s, [%s, -#%d]",  reg_name(rs), reg_name(rn),
						// imm);
						regname(rs, ", ");
						append_to_buf("[");
						regname(rn, ", ");
						append_to_buf("-#%d]", imm);
						break;
					case 0x9: /* Post-decrement.  */
					case 0xb: /* Post-increment.  */
					case 0xd: /* Pre-decrement.  */
					case 0xf: /* Pre-increment.  */
					case 0xe: /* user privilege  */
						add = (insn & (1<<9));
						index = (insn & (1<<10));
						wb = (insn & (1<<8));
						// append_to_buf("%s, [%s, ",  reg_name(rs), reg_name(rn));
						regname(rs, ", ");
						append_to_buf("[");
						regname(rn, ", ");
						if (index) {
							append_to_buf("%s, #%d]",add?"+":"-", imm);
							if (wb) {
								append_to_buf("!");
							}
						} else {
							append_to_buf("%s], #%d",add?"+":"-", imm);
						}
						break;
					default:
						goto illegal;
				}
			}

			//append_to_buf("%s, %s, ", "str");

			break;//case 12
		default:
			goto illegal;
	} //switch

	//dump the buffer
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);

	return;

undefined:
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);
	BT_ERR(true, "undefined instruction 0x%-8x ", insn);
	return;
todo:
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);
	BT_ERR(true, "TODO*****instruction 0x%-8x ", insn);
	return;
illegal:
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);
	BT_ERR(true, "illegal*****instruction 0x%-8x ", insn);
	return;
}



/* format:
 *
 *   [DIS]  address(8bytes) insn (8 bytes, left aligned), ins(8bytes) xxx,xxx,xxx
 */
//return value: 1: thumb2. 0:thumb
int dis_thumb_instruction(u4 addr, u2 insn) {

	u4 op, rm, rn, rd, shift, cond, val, imm;
	int i;

	s4 offset;


	char dis_buf[128];
	int buf_index = 0;

	u2 bits_15_12 = insn >> 12;

	//thumb2 instruction
	//u4 insn_next = *((u2*)(addr + 2));
	//u4 new_insn = (insn << 16) | insn_next;

	// char op[12], oprand1[12], oprand[12], oprand3[12];

	memset(dis_buf, 0x0, sizeof(dis_buf));

	append_to_buf("[DIS] %-8x %-8x ", addr, insn);

	switch (bits_15_12) {
		case 0:
		case 1:
			rd = insn & 7;
			op = (insn >> 11) & 3;
			rn = (insn >> 3) & 7;
			if (op == 3) {
				/* add/subtract */
				rm = (insn >> 6) & 7;

				if (insn & (1<<9)) {
					append_to_buf("%-8s ", "sub");
				} else {
					append_to_buf("%-8s ", "add");
				}

				append_to_buf("r%d, r%d, ", rd, rn);

				if (insn & (1 << 10)) {
					append_to_buf("%s", "#");
				} else {
					append_to_buf("%s", "r");
				}
				append_to_buf("%d", rm);
				break;
			} else {
				/* shift immediate */
				rm = (insn >> 3) & 7;
				shift = (insn >> 6) & 0x1f;
				if (op == 0x0) {
					append_to_buf("%-8s ", "lsl");
				} else if (op == 0x01) {
					append_to_buf("%-8s ", "lsr");
				} else {
					append_to_buf("%-8s ", "asr");
				}
				append_to_buf("r%d, r%d, #0x%x", rd, rn, shift);
				break;
			}
		case 2:
		case 3:
			/* arithmetic large immediate */
			op = (insn >> 11) & 3;
			rd = (insn >> 8) & 0x7;
			imm = insn & 0xff;
			if (op == 0) {
				/* mov */
				append_to_buf("%-8s ", "mov");
			} else if (op == 1) {
				append_to_buf("%-8s ", "cmp");
			} else if (op == 2) {
				append_to_buf("%-8s ", "add");
			} else {
				append_to_buf("%-8s ", "sub");
			}
			append_to_buf("r%d, #0x%x", rd, imm);
			break;
		case 4:
			if (insn & (1 << 11)) {
				rd = (insn >> 8) & 7;
				/* pc relative load. */
				append_to_buf("%-8s ", "ldr");
				append_to_buf("r%d, ", rd);
				imm = (insn & 0xff) * 4;
				append_to_buf("[pc, #0x%x]", imm);
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

				if (op == 0) {
					append_to_buf("%-8s ", "add");
				} else if (op == 1) {
					append_to_buf("%-8s ", "cmp");
				} else if (op == 2) {
					append_to_buf("%-8s ", "mov");
				} else if (op == 3) {
					if (insn & (1<<7))
						append_to_buf("%-8s ", "blx");
					else
						append_to_buf("%-8s ", "bx");
				}

				if (op != 3) {
					append_to_buf("r%d, r%d", rd, rm);
				} else {
					append_to_buf("r%d", rm);
				}

				break;

			} else {
				/*data processing*/
				op = (insn >> 6) & 0xf;
				rd = insn & 7;
				rm = (insn >> 3) & 7;

				switch (op) {
					case 0x0:
						append_to_buf("%-8s ", "and");
						break;
					case 0x1:
						append_to_buf("%-8s ", "eor");
						break;
					case 0x2:
						append_to_buf("%-8s ", "lsl");
						break;
					case 0x3:
						append_to_buf("%-8s ", "lsr");
						break;
					case 0x4:
						append_to_buf("%-8s ", "asr");
						break;
					case 0x5:
						append_to_buf("%-8s ", "adc");
						break;
					case 0x6:
						append_to_buf("%-8s ", "sbc");
						break;
					case 0x7:
						append_to_buf("%-8s ", "ror");
						break;
					case 0x8:
						append_to_buf("%-8s ", "tst");
						break;
					case 0x9:
						append_to_buf("%-8s ", "neg");
						break;
					case 0xa:
						append_to_buf("%-8s ", "cmp");
						break;
					case 0xb:
						append_to_buf("%-8s ", "cmn");
						break;
					case 0xc:
						append_to_buf("%-8s ", "orr");
						break;
					case 0xd:
						append_to_buf("%-8s ", "mul");
						break;
					case 0xe:
						append_to_buf("%-8s ", "bic");
						break;
					case 0xf:
						append_to_buf("%-8s ", "mvn");
						break;
				}

				append_to_buf("r%d, r%d", rd, rm);
			}
			break;

		case 5:
			/* load/store register offset.  */
			rd = insn & 7;
			rn = (insn >> 3) & 7;
			rm = (insn >> 6) & 7;
			op = (insn >> 9) & 7;

			switch (op) {
				case 0x0:
					/* str */
					append_to_buf("%-8s ", "str");
					break;
				case 0x1:
					/* strh */
					append_to_buf("%-8s ", "strh");
					break;
				case 0x2:
					/* strb */
					append_to_buf("%-8s ", "strb");
					break;
				case 0x3:
					/* ldrsb */
					append_to_buf("%-8s ", "ldrsb");
					break;
				case 0x4:
					/* ldr */
					append_to_buf("%-8s ", "ldr");
					break;
				case 0x5:
					/* ldrh */
					append_to_buf("%-8s ", "ldrh");
					break;
				case 0x6:
					/* ldrb */
					append_to_buf("%-8s ", "ldrb");
					break;
				case 0x7:
					/* ldrsh */
					append_to_buf("%-8s ", "ldrsh");
					break;
			}

			append_to_buf("r%d, [r%d, r%d]", rd, rn, rm);
			break;
		case 6:
			/* load/store word immediate offset */
			rd = insn & 7;
			rn = (insn >> 3) & 7;
			val = (insn >> 4) & 0x7c;

			if (insn & (1 << 11)) {
				/* load */
				append_to_buf("%-8s ", "ldr");
			} else {
				append_to_buf("%-8s ", "str");
			}

			append_to_buf("r%d, [r%d, #0x%x]", rd, rn, val);
			break;

		case 7:
			/* load/store byte immediate offset */
			rd = insn & 7;
			rn = (insn >> 3) & 7;
			val = (insn >> 6) & 0x1f;
			if (insn & (1 << 11)) {
				/* load */
				append_to_buf("%-8s ", "ldrb");
			} else {
				append_to_buf("%-8s ", "strb");
			}
			append_to_buf("r%d, [r%d, #0x%x]", rd, rn, val);
			break;

		case 8:
			/* load/store halfword immediate offset */
			rd = insn & 7;
			rn = (insn >> 3) & 7;
			val = (insn >> 5) & 0x3e;
			if (insn & (1 << 11)) {
				/* load */
				append_to_buf("%-8s ", "ldrh");
			} else {
				append_to_buf("%-8s ", "strh");
			}
			append_to_buf("r%d, [r%d, #0x%x]", rd, rn, val);
			break;

		case 9:
			/* sp relative load store */
			rd = (insn >> 8) & 7;
			val = (insn & 0xff) * 4;

			if (insn & (1 << 11)) {
				/* load */
				append_to_buf("%-8s ", "ldr");
			} else {
				append_to_buf("%-8s ", "str");
			}

			append_to_buf("r%d, [sp, #0x%x]", rd, val);
			break;

		case 10:
			/*pc sp relative load address */
			rd = (insn >> 8) & 7;
			val = (insn & 0xff) * 4;

			append_to_buf("%-8s ", "add");

			if (insn & (1 << 11)) {
				/* sp */
				append_to_buf("r%d, sp, #0x%x", rd, val);
			} else {
				/*pc*/
				append_to_buf("r%d, pc, #0x%x", rd, val);
			}
			break;
		case 11:
			/* misc */
			op = (insn >> 8) & 0xf;
			switch (op) {
				case 0x0:
					/* adjust stack pointer */
					append_to_buf("%-8s ", "add");
					val = (insn & 0x7f) * 4;
					if (insn & (1 << 7))
						append_to_buf("sp, #-0x%x", val);
					else
						append_to_buf("sp, #0x%x", val);
					break;
				case 0x2:
					append_to_buf("%-8s ", "uxtb");
					break;

				case 4: case 5:
					append_to_buf("%-8s ", "push");

					append_to_buf("%s", "{");
					for (i =0; i < 8; i ++) {
						if (insn & (1 << i)) {
							append_to_buf("r%d,", i);
						}
					}

					if (insn & (1<<8)) {
						append_to_buf("%s", "lr ");
					}
					append_to_buf("%s", "}");
					break;

				case 0xc:
				case 0xd:
					append_to_buf("%-8s ", "pop");
					append_to_buf("%s", "{");
					for (i =0; i < 8; i ++) {
						if (insn & (1 << i)) {
							append_to_buf("r%d,", i);
						}
					}

					if (insn & (1<<8)) {
						append_to_buf("%s", "pc ");
					}
					append_to_buf("%s", "}");
					break;
				case 0xf:
					/*it*/
					append_to_buf("%s", "it ");
					break;

				case 1: case 3: case 9: case 11:
					/*cbz*/
					if (insn & (1 << 11)) {
						append_to_buf("%-8s ", "cbnz");
					} else {
						append_to_buf("%-8s ", "cbz");
					}

					val = (u4)addr + 4;
					offset = ((insn & 0xf8) >> 2) | (insn & 0x200) >> 3;
					val += (offset);
					append_to_buf("0x%8x", val);
					break;
				default:
					goto undef;
			}
			break;

		case 12:
			/* multi load store*/
			rn = (insn >> 8) & 0x7;
			if (insn & (1 << 11)) {
				append_to_buf("%-8s ", "ldmia");
			} else {
				append_to_buf("%-8s ", "stmia");
			}
			append_to_buf("r%d!, ", rn);
			append_to_buf("%s", "{");
			for (i =0; i < 8; i ++) {
				if (insn & (1 << i)) {
					append_to_buf("r%d,", i);
				}
			}
			append_to_buf("%s", "}");
			break;

		case 13:
			cond = (insn >> 8) & 0xf;
			if (cond == 0xf) {
				imm = (insn & 0xff);
				/*swi*/
				append_to_buf("%-8s %d", "swi", imm);
			} else if (cond == 0xe) {
				goto undef;
			} else {
				/* conditional branch*/
				switch (cond) {
					case 0x0:
						append_to_buf("%-8s ", "beq");
						break;
					case 0x1:
						append_to_buf("%-8s ", "bne");
						break;
					case 0x2:
						append_to_buf("%-8s ", "bcs");
						break;
					case 0x3:
						append_to_buf("%-8s ", "bcc");
						break;
					case 0x4:
						append_to_buf("%-8s ", "bmi");
						break;
					case 0x5:
						append_to_buf("%-8s ", "bpl");
						break;
					case 0x6:
						append_to_buf("%-8s ", "bvs");
						break;
					case 0x7:
						append_to_buf("%-8s ", "bvc");
						break;

					case 0x8:
						append_to_buf("%-8s ", "bhi");
						break;
					case 0x9:
						append_to_buf("%-8s ", "bls");
						break;
					case 0xa:
						append_to_buf("%-8s ", "bge");
						break;
					case 0xb:
						append_to_buf("%-8s ", "blt");
						break;
					case 0xc:
						append_to_buf("%-8s ", "bgt");
						break;
					case 0xd:
						append_to_buf("%-8s ", "ble");
						break;
				}

				val = (u4)addr + 4;
				offset = ((s4)insn << 24) >> 24;
				val += offset << 1;

				append_to_buf("0x%-8x (%d)", val, offset<<1);
			}
			break;
		case 14:
			if (insn & (1 << 11)) {
				//ret = fbt_translate_instr_thumb2(ts, insn_hw);
				goto thumb2;
			} else {
				/* unconditional branch */
				append_to_buf("%-8s ", "b");
				val = (u4)addr + 4;
				offset = ((s4)insn << 21) >> 21;
				val += (offset << 1);
				append_to_buf("0x%-8x (%d)", val, offset<<1);
			}
			break;
		case 15:
			//ret = fbt_translate_instr_thumb2(ts, insn_hw);
			goto thumb2;

		default:
			goto undef;
	}

	//dump the buffer
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);

	return 0;

thumb2:
	return 1;
undef:
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", dis_buf);
	BT_ERR(true, "undefined instruction 0x%-8x ", insn);
	return 0;
}
