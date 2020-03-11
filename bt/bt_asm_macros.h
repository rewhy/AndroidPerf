#ifndef FBT_ASM_MACROS_H
#define FBT_ASM_MACROS_H


/* this code is from mono project. arch/arm/arm-codegen.h*/
typedef enum {
    ARMREG_R0 = 0,
    ARMREG_R1,
    ARMREG_R2,
    ARMREG_R3,
    ARMREG_R4,
    ARMREG_R5,
    ARMREG_R6,
    ARMREG_R7,
    ARMREG_R8,
    ARMREG_R9,
    ARMREG_R10,
    ARMREG_R11,
    ARMREG_R12,
    ARMREG_R13,
    ARMREG_R14,
    ARMREG_R15,


    /* aliases */
    /* args */
    ARMREG_A1 = ARMREG_R0,
    ARMREG_A2 = ARMREG_R1,
    ARMREG_A3 = ARMREG_R2,
    ARMREG_A4 = ARMREG_R3,

    /* local vars */
    ARMREG_V1 = ARMREG_R4,
    ARMREG_V2 = ARMREG_R5,
    ARMREG_V3 = ARMREG_R6,
    ARMREG_V4 = ARMREG_R7,
    ARMREG_V5 = ARMREG_R8,
    ARMREG_V6 = ARMREG_R9,
    ARMREG_V7 = ARMREG_R10,

    ARMREG_FP = ARMREG_R11,
    ARMREG_IP = ARMREG_R12,
    ARMREG_SP = ARMREG_R13,
    ARMREG_LR = ARMREG_R14,
    ARMREG_PC = ARMREG_R15,

    /* co-processor */
    ARMREG_CR0 = 0,
    ARMREG_CR1,
    ARMREG_CR2,
    ARMREG_CR3,
    ARMREG_CR4,
    ARMREG_CR5,
    ARMREG_CR6,
    ARMREG_CR7,
    ARMREG_CR8,
    ARMREG_CR9,
    ARMREG_CR10,
    ARMREG_CR11,
    ARMREG_CR12,
    ARMREG_CR13,
    ARMREG_CR14,
    ARMREG_CR15,

    /* XScale: acc0 on CP0 */
    ARMREG_ACC0 = ARMREG_CR0,

    ARMREG_MAX = ARMREG_R15
} ARMReg;

typedef enum {
    ARMCOND_EQ = 0x0,          /* Equal; Z = 1 */
    ARMCOND_NE = 0x1,          /* Not equal, or unordered; Z = 0 */
    ARMCOND_CS = 0x2,          /* Carry set; C = 1 */
    ARMCOND_HS = ARMCOND_CS,   /* Unsigned higher or same; */
    ARMCOND_CC = 0x3,          /* Carry clear; C = 0 */
    ARMCOND_LO = ARMCOND_CC,   /* Unsigned lower */
    ARMCOND_MI = 0x4,          /* Negative; N = 1 */
    ARMCOND_PL = 0x5,          /* Positive or zero; N = 0 */
    ARMCOND_VS = 0x6,          /* Overflow; V = 1 */
    ARMCOND_VC = 0x7,          /* No overflow; V = 0 */
    ARMCOND_HI = 0x8,          /* Unsigned higher; C = 1 && Z = 0 */
    ARMCOND_LS = 0x9,          /* Unsigned lower or same; C = 0 || Z = 1 */
    ARMCOND_GE = 0xA,          /* Signed greater than or equal; N = V */
    ARMCOND_LT = 0xB,          /* Signed less than; N != V */
    ARMCOND_GT = 0xC,          /* Signed greater than; Z = 0 && N = V */
    ARMCOND_LE = 0xD,          /* Signed less than or equal; Z = 1 && N != V */
    ARMCOND_AL = 0xE,          /* Always */
    ARMCOND_NV = 0xF,          /* Never */

    ARMCOND_SHIFT = 28
} ARMCond;

typedef enum {
    ARMOP_AND = 0x0,
    ARMOP_EOR = 0x1,
    ARMOP_SUB = 0x2,
    ARMOP_RSB = 0x3,
    ARMOP_ADD = 0x4,
    ARMOP_ADC = 0x5,
    ARMOP_SBC = 0x6,
    ARMOP_RSC = 0x7,
    ARMOP_TST = 0x8,
    ARMOP_TEQ = 0x9,
    ARMOP_CMP = 0xa,
    ARMOP_CMN = 0xb,
    ARMOP_ORR = 0xc,
    ARMOP_MOV = 0xd,
    ARMOP_BIC = 0xe,
    ARMOP_MVN = 0xf,

    ARMOP_MOVT = 0xa,
    ARMOP_MOVW = 0x8,


    /* not really opcodes */

    ARMOP_STR = 0x0,
    ARMOP_LDR = 0x1,

    /* ARM2+ */
    ARMOP_MUL   = 0x0, /* Rd := Rm*Rs */
    ARMOP_MLA   = 0x1, /* Rd := (Rm*Rs)+Rn */

    /* ARM3M+ */
    ARMOP_UMULL = 0x4,
    ARMOP_UMLAL = 0x5,
    ARMOP_SMULL = 0x6,
    ARMOP_SMLAL = 0x7,

    /* for data transfers with register offset */
    ARM_UP   = 1,
    ARM_DOWN = 0
} ARMOpcode;

typedef enum {
    ARMSHIFT_LSL = 0,
    ARMSHIFT_LSR = 1,
    ARMSHIFT_ASR = 2,
    ARMSHIFT_ROR = 3,

    ARMSHIFT_ASL = ARMSHIFT_LSL
    /* rrx = (ror, 1) */
} ARMShiftType;

#define ARM_DEF_COND(cond) (((cond) & 0xF) << ARMCOND_SHIFT)

#define GET_INS_19_16(ins) ((ins & 0x000f0000) >>16)
#define GET_INS_15_12(ins) ((ins & 0x0000f000) >>12)
#define SET_INS_15_12(ins, val) (((val) << 12) || (ins & 0xffff0fff))







/*for code generation*/

//	__android_log_print(ANDROID_LOG_INFO, "ARM_EMIT", "[%s:%d] [0x%-8x]=0x%8x", FILE, __LINE__, (u4)dst, (u4)ins);
#define ARM_EMIT(dst, ins) \
		{ \
			*((u4*)(dst)) = ins; \
			(dst) += 4; \
		}

/* push. */
#define ARM_MRT_ID 4
#define ARM_MRT_MASK 7 << 25
#define ARM_MRT_TAG ARM_MRT_ID << 25

#define ARM_DEF_MRT(regs, rn, l, w, s, u, p, cond) \
    (regs)        | \
    (rn << 16)    | \
    (l << 20)     | \
    (w << 21)     | \
    (s << 22)     | \
    (u << 23)     | \
    (p << 24)     | \
    (ARM_MRT_TAG) | \
    ARM_DEF_COND(cond)


#define ARM_DEF_PUSH(regs, cond) \
    (regs)          | \
    (0x92D<<16)        | \
    ARM_DEF_COND(cond)

/* push. (A1) see page 532. A8-246 */
#define ARM_PUSH(dst, regs) \
    ARM_EMIT(dst,(ARM_DEF_PUSH(regs, ARMCOND_AL)));

#define ARM_DEF_PUSH_1(reg, cond) \
    (0x4) | \
    (reg<<12)        | \
    (0x52d<<16)        | \
    ARM_DEF_COND(cond)
/* push. (A2) see page 532. A8-246 */

#define ARM_PUSH1(dst, reg) \
    ARM_EMIT(dst,(ARM_DEF_PUSH_1(reg, ARMCOND_AL)));
// #define ARM_PUSH1(p, r1) ARM_PUSH(p, (1 << r1))
#define ARM_PUSH2(p, r1, r2) ARM_PUSH(p, (1 << r1) | (1 << r2))
#define ARM_PUSH3(p, r1, r2, r3) ARM_PUSH(p, (1 << r1) | (1 << r2) | (1 << r3))
#define ARM_PUSH4(p, r1, r2, r3, r4) ARM_PUSH(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4))
#define ARM_PUSH5(p, r1, r2, r3, r4, r5) ARM_PUSH(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5))
#define ARM_PUSH6(p, r1, r2, r3, r4, r5, r6) ARM_PUSH(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5) | (1 << r6))
#define ARM_PUSH7(p, r1, r2, r3, r4, r5, r6, r7) ARM_PUSH(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5) | (1 << r6) | (1 << r7))
#define ARM_PUSH8(p, r1, r2, r3, r4, r5, r6, r7, r8) ARM_PUSH(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5) | (1 << r6) | (1 << r7) | (1 << r8))

/* POP. (A1) see page 530. A8-244 */
#define ARM_DEF_POP(regs, cond) \
    (regs)          | \
    (0x8BD<<16)        | \
    ARM_DEF_COND(cond)

#define ARM_POP(dst, regs) ARM_EMIT(dst,(ARM_DEF_POP(regs, ARMCOND_AL)));

#define ARM_DEF_POP_1(reg, cond) \
    (0x4) | \
    (reg<<12)          | \
    (0x49d<<16)        | \
    ARM_DEF_COND(cond)

/* push. (A2) see page 530. A8-244 */
#define ARM_POP1(dst, reg) ARM_EMIT(dst,(ARM_DEF_POP_1(reg, ARMCOND_AL)));
#define ARM_POP8(p, r1, r2, r3, r4, r5, r6, r7, r8) ARM_POP(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5) | (1 << r6) | (1 << r7) | (1 << r8))
#define ARM_POP7(p, r1, r2, r3, r4, r5, r6, r7) ARM_POP(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5) | (1 << r6) | (1 << r7))
#define ARM_POP6(p, r1, r2, r3, r4, r5, r6) ARM_POP(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5) | (1 << r6))
#define ARM_POP5(p, r1, r2, r3, r4, r5) ARM_POP(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4) | (1 << r5))
#define ARM_POP4(p, r1, r2, r3, r4) ARM_POP(p, (1 << r1) | (1 << r2) | (1 << r3) | (1 << r4))
#define ARM_POP3(p, r1, r2, r3) ARM_POP(p, (1 << r1) | (1 << r2) | (1 << r3))
#define ARM_POP2(p, r1, r2) ARM_POP(p, (1 << r1) | (1 << r2))


#if 0
typedef struct {
    arminstr_t rm   : 4;
    arminstr_t tag  : 1; /* 0 - immediate shift, 1 - reg shift */
    arminstr_t type : 2; /* shift type - logical, arithmetic, rotate */
} ARMDPI_op2_reg_shift;


/* op2 is reg shift by imm */
typedef union {
    ARMDPI_op2_reg_shift r2;
    struct {
        arminstr_t _dummy_r2 : 7;
        arminstr_t shift : 5;
    } imm;
} ARMDPI_op2_reg_imm;

/*  Word/byte transfer */
typedef union {
    ARMDPI_op2_reg_imm op2_reg_imm;
    struct {
        arminstr_t op2_imm : 12;
        arminstr_t rd      :  4;
        arminstr_t rn      :  4;
        arminstr_t ls      :  1;
        arminstr_t wb      :  1;
        arminstr_t b       :  1;
        arminstr_t u       :  1; /* down(0) / up(1) */
        arminstr_t p       :  1; /* post-index(0) / pre-index(1) */
        arminstr_t type    :  1; /* imm(0) / register(1) */
        arminstr_t tag     :  2; /* 0 1 */
        arminstr_t cond    :  4;
    } all;
} ARMInstrWXfer;
#endif


#define ARM_WXFER_ID 1
#define ARM_WXFER_MASK 3 << 26
#define ARM_WXFER_TAG ARM_WXFER_ID << 26


#define ARM_DEF_WXFER_IMM(imm12, rd, rn, ls, wb, b, p, cond) \
    ((((int)imm12) < 0) ? -(int)(imm12) : (imm12)) | \
    ((rd) << 12)                                   | \
    ((rn) << 16)                                   | \
    ((ls) << 20)                                   | \
    ((wb) << 21)                                   | \
    ((b)  << 22)                                   | \
    (((int)(imm12) >= 0) << 23)                    | \
    ((p) << 24)                                    | \
    ARM_WXFER_TAG                                  | \
    ARM_DEF_COND(cond)

#define ARM_WXFER_MAX_OFFS 0xFFF

/* this macro checks for imm12 bounds */

/* LDRx */
/* immediate offset, post-index */
#define ARM_LDR_IMM_POST_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_LDR, 0, 0, 0, cond))

#define ARM_LDR_IMM_POST(p, rd, rn, imm) \
                            ARM_LDR_IMM_POST_COND(p, rd, rn, imm, ARMCOND_AL)

#define ARM_LDRB_IMM_POST_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_LDR, 0, 1, 0, cond))

#define ARM_LDRB_IMM_POST(p, rd, rn, imm) \
                            ARM_LDRB_IMM_POST_COND(p, rd, rn, imm, ARMCOND_AL)


/* immediate offset, pre-index */
#define ARM_LDR_IMM_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_LDR, 0, 0, 1, cond))

#define ARM_LDR_IMM(p, rd, rn, imm) \
                                ARM_LDR_IMM_COND(p, rd, rn, imm, ARMCOND_AL)

#define ARM_LDRB_IMM_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_LDR, 0, 1, 1, cond))

#define ARM_LDRB_IMM(p, rd, rn, imm) \
                                ARM_LDRB_IMM_COND(p, rd, rn, imm, ARMCOND_AL)


/* STRx */
/* immediate offset, post-index */
#define ARM_STR_IMM_POST_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_STR, 0, 0, 0, cond))

#define ARM_STR_IMM_POST(p, rd, rn, imm) ARM_STR_IMM_POST_COND(p, rd, rn, imm, ARMCOND_AL)

#define ARM_STRB_IMM_POST_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_STR, 0, 1, 0, cond))

#define ARM_STRB_IMM_POST(p, rd, rn, imm) \
                            ARM_STRB_IMM_POST_COND(p, rd, rn, imm, ARMCOND_AL)

/* immediate offset, pre-index */
#define ARM_STR_IMM_COND(p, rd, rn, imm, cond) \
     ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_STR, 0, 0, 1, cond))

#define ARM_STR_IMM(p, rd, rn, imm) ARM_STR_IMM_COND(p, rd, rn, imm, ARMCOND_AL)

#define ARM_STRB_IMM_COND(p, rd, rn, imm, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_IMM(imm, rd, rn, ARMOP_STR, 0, 1, 1, cond))

#define ARM_STRB_IMM(p, rd, rn, imm) \
                                ARM_STRB_IMM_COND(p, rd, rn, imm, ARMCOND_AL)

/* write-back */
#define ARM_STR_IMM_WB_COND(p, rd, rn, imm, cond) \
                    ARM_DEF_WXFER_IMM(p, imm, rd, rn, ARMOP_STR, 1, 0, 1, cond)
#define ARM_STR_IMM_WB(p, rd, rn, imm) \
                                ARM_STR_IMM_WB_COND(p, rd, rn, imm, ARMCOND_AL)



//put ins into instruction cache directly
//__android_log_print(ANDROID_LOG_INFO, "ARM_RAW", "[%s:%d] [0x%-8x]=0x%8x", FILE, __LINE__, (u4)dst, (u4)ins); 
#define ARM_RAW(dst, ins)  \
    *((u4*)dst) = (ins); \
    dst +=4

#define ARM_DEF_WXFER_REG_REG_UPDOWN_COND(rm, shift_type, shift, rd, rn, ls, wb, b, u, p, cond) \
    (rm)                | \
    ((shift_type) << 5) | \
    ((shift) << 7)      | \
    ((rd) << 12)        | \
    ((rn) << 16)        | \
    ((ls) << 20)        | \
    ((wb) << 21)        | \
    ((b)  << 22)        | \
    ((u)  << 23)        | \
    ((p)  << 24)        | \
    (1    << 25)        | \
    ARM_WXFER_TAG       | \
    ARM_DEF_COND(cond)

#define ARM_DEF_WXFER_REG_REG_COND(rm, shift_type, shift, rd, rn, ls, wb, b, p, cond) \
    ARM_DEF_WXFER_REG_REG_UPDOWN_COND(rm, shift_type, shift, rd, rn, ls, wb, b, ARM_UP, p, cond)
#define ARM_DEF_WXFER_REG_MINUS_REG_COND(rm, shift_type, shift, rd, rn, ls, wb, b, p, cond) \
    ARM_DEF_WXFER_REG_REG_UPDOWN_COND(rm, shift_type, shift, rd, rn, ls, wb, b, ARM_DOWN, p, cond)


#define ARM_LDR_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_REG_REG_COND(rm, shift_type, shift, rd, rn, ARMOP_LDR, 0, 0, 1, cond))
#define ARM_LDR_REG_REG_SHIFT(p, rd, rn, rm, shift_type, shift) \
    ARM_LDR_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, ARMCOND_AL)
#define ARM_LDR_REG_REG(p, rd, rn, rm) \
    ARM_LDR_REG_REG_SHIFT(p, rd, rn, rm, ARMSHIFT_LSL, 0)

#define ARM_LDRB_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_REG_REG_COND(rm, shift_type, shift, rd, rn, ARMOP_LDR, 0, 1, 1, cond))
#define ARM_LDRB_REG_REG_SHIFT(p, rd, rn, rm, shift_type, shift) \
    ARM_LDRB_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, ARMCOND_AL)
#define ARM_LDRB_REG_REG(p, rd, rn, rm) \
    ARM_LDRB_REG_REG_SHIFT(p, rd, rn, rm, ARMSHIFT_LSL, 0)

#define ARM_STR_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_REG_REG_COND(rm, shift_type, shift, rd, rn, ARMOP_STR, 0, 0, 1, cond))
#define ARM_STR_REG_REG_SHIFT(p, rd, rn, rm, shift_type, shift) \
    ARM_STR_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, ARMCOND_AL)
#define ARM_STR_REG_REG(p, rd, rn, rm) \
    ARM_STR_REG_REG_SHIFT(p, rd, rn, rm, ARMSHIFT_LSL, 0)

/* zero-extend */
#define ARM_STRB_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, cond) \
    ARM_EMIT(p, ARM_DEF_WXFER_REG_REG_COND(rm, shift_type, shift, rd, rn, ARMOP_STR, 0, 1, 1, cond))
#define ARM_STRB_REG_REG_SHIFT(p, rd, rn, rm, shift_type, shift) \
    ARM_STRB_REG_REG_SHIFT_COND(p, rd, rn, rm, shift_type, shift, ARMCOND_AL)
#define ARM_STRB_REG_REG(p, rd, rn, rm) \
    ARM_STRB_REG_REG_SHIFT(p, rd, rn, rm, ARMSHIFT_LSL, 0)

/*DPI*/

#define ARM_DPI_ID 0
#define ARM_DPI_MASK 3 << 26
#define ARM_DPI_TAG ARM_DPI_ID << 26

#define ARM_DEF_DPI_IMM_COND(imm8, rot, rd, rn, s, op, cond) \
    ((imm8) & 0xFF)      | \
    (((rot) & 0xF) << 8) | \
    ((rd) << 12)         | \
    ((rn) << 16)         | \
    ((s) << 20)          | \
    ((op) << 21)         | \
    (1 << 25)            | \
    (ARM_DPI_TAG)        | \
    ARM_DEF_COND(cond)


#define ARM_DEF_DPI_IMM(imm8, rot, rd, rn, s, op) \
    ARM_DEF_DPI_IMM_COND(imm8, rot, rd, rn, s, op, ARMCOND_AL)

/* codegen */
/*rot here must power of 2*/
#define ARM_DPIOP_REG_IMM8ROT_COND(p, op, rd, rn, imm8, rot, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_IMM_COND((imm8), ((rot) >> 1), (rd), (rn), 0, (op), cond))
#define ARM_DPIOP_S_REG_IMM8ROT_COND(p, op, rd, rn, imm8, rot, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_IMM_COND((imm8), ((rot) >> 1), (rd), (rn), 1, (op), cond))

/* inline */
#define ARM_IASM_DPIOP_REG_IMM8ROT_COND(p, op, rd, rn, imm8, rot, cond) \
    ARM_IASM(ARM_DEF_DPI_IMM_COND((imm8), ((rot) >> 1), (rd), (rn), 0, (op), cond))
#define ARM_IASM_DPIOP_S_REG_IMM8ROT_COND(p, op, rd, rn, imm8, rot, cond) \
    ARM_IASM(ARM_DEF_DPI_IMM_COND((imm8), ((rot) >> 1), (rd), (rn), 1, (op), cond))



#define ARM_DEF_DPI_REG_IMMSHIFT_COND(rm, shift_type, imm_shift, rd, rn, s, op, cond) \
    (rm)                        | \
    ((shift_type & 3) << 5)     | \
    (((imm_shift) & 0x1F) << 7) | \
    ((rd) << 12)                | \
    ((rn) << 16)                | \
    ((s) << 20)                 | \
    ((op) << 21)                | \
    (ARM_DPI_TAG)               | \
    ARM_DEF_COND(cond)

/* codegen */
#define ARM_DPIOP_REG_IMMSHIFT_COND(p, op, rd, rn, rm, shift_t, imm_shift, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), shift_t, imm_shift, (rd), (rn), 0, (op), cond))

#define ARM_DPIOP_S_REG_IMMSHIFT_COND(p, op, rd, rn, rm, shift_t, imm_shift, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), shift_t, imm_shift, (rd), (rn), 1, (op), cond))

#define ARM_DPIOP_REG_REG_COND(p, op, rd, rn, rm, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), ARMSHIFT_LSL, 0, (rd), (rn), 0, (op), cond))

#define ARM_DPIOP_S_REG_REG_COND(p, op, rd, rn, rm, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), ARMSHIFT_LSL, 0, (rd), (rn), 1, (op), cond))

/* inline */
#define ARM_IASM_DPIOP_REG_IMMSHIFT_COND(p, op, rd, rn, rm, shift_t, imm_shift, cond) \
    ARM_IASM(ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), shift_t, imm_shift, (rd), (rn), 0, (op), cond))

#define ARM_IASM_DPIOP_S_REG_IMMSHIFT_COND(p, op, rd, rn, rm, shift_t, imm_shift, cond) \
    ARM_IASM(ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), shift_t, imm_shift, (rd), (rn), 1, (op), cond))

#define ARM_IASM_DPIOP_REG_REG_COND(p, op, rd, rn, rm, cond) \
    ARM_IASM(ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), ARMSHIFT_LSL, 0, (rd), (rn), 0, (op), cond))

#define ARM_IASM_DPIOP_S_REG_REG_COND(p, op, rd, rn, rm, cond) \
    ARM_IASM_EMIT(ARM_DEF_DPI_REG_IMMSHIFT_COND((rm), ARMSHIFT_LSL, 0, (rd), (rn), 1, (op), cond))


/* Rd := Rn op (Rm shift_type Rs) */
#define ARM_DEF_DPI_REG_REGSHIFT_COND(rm, shift_type, rs, rd, rn, s, op, cond) \
    (rm)                        | \
    (1 << 4)                    | \
    ((shift_type & 3) << 5)     | \
    ((rs) << 8)                 | \
    ((rd) << 12)                | \
    ((rn) << 16)                | \
    ((s) << 20)                 | \
    ((op) << 21)                | \
    (ARM_DPI_TAG)               | \
    ARM_DEF_COND(cond)

/* codegen */
#define ARM_DPIOP_REG_REGSHIFT_COND(p, op, rd, rn, rm, shift_t, rs, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_REG_REGSHIFT_COND((rm), shift_t, (rs), (rd), (rn), 0, (op), cond))

#define ARM_DPIOP_S_REG_REGSHIFT_COND(p, op, rd, rn, rm, shift_t, rs, cond) \
    ARM_EMIT(p, ARM_DEF_DPI_REG_REGSHIFT_COND((rm), shift_t, (rs), (rd), (rn), 1, (op), cond))

/* inline */
#define ARM_IASM_DPIOP_REG_REGSHIFT_COND(p, op, rd, rn, rm, shift_t, rs, cond) \
    ARM_IASM(ARM_DEF_DPI_REG_REGSHIFT_COND((rm), shift_t, (rs), (rd), (rn), 0, (op), cond))

#define ARM_IASM_DPIOP_S_REG_REGSHIFT_COND(p, op, rd, rn, rm, shift_t, rs, cond) \
    ARM_IASM(ARM_DEF_DPI_REG_REGSHIFT_COND((rm), shift_t, (rs), (rd), (rn), 1, (op), cond))

//this file is dynamically generated
#include "arm_dpimacros.h"

/* MOVT/MOVW */
#define ARM_DEF_MOVWT_IMM_COND(imm12, rd, imm4, op, cond) \
    ((imm12))    | \
    ((rd) << 12)         | \
    ((imm4) << 16)       | \
    ((0) << 20)          | \
    ((op) << 21)         | \
    (1 << 25)            | \
    (ARM_DPI_TAG)        | \
    ARM_DEF_COND(cond)

//MOVT
#define ARM_MOVT_REG_IMM1204_COND(p, reg, imm12, imm4,  cond) \
    ARM_EMIT(p,ARM_DEF_MOVWT_IMM_COND(imm12, reg, imm4, ARMOP_MOVT, cond))

#define ARM_MOVT_REG_IMM16_COND(p, reg, imm16, cond) \
        ARM_MOVT_REG_IMM1204_COND(p, reg, (imm16&0xfff), (imm16>>12)&0xf, cond)

#define ARM_MOVT_REG_IMM16(p, reg, imm16) \
                ARM_MOVT_REG_IMM16_COND(p, reg, imm16, ARMCOND_AL)

//MOVW
#define ARM_MOVW_REG_IMM1204_COND(p, reg, imm12, imm4,  cond) \
    ARM_EMIT(p,ARM_DEF_MOVWT_IMM_COND(imm12, reg, imm4, ARMOP_MOVW, cond))

#define ARM_MOVW_REG_IMM16_COND(p, reg, imm16, cond) \
        ARM_MOVW_REG_IMM1204_COND(p, reg, ((imm16)&0xfff), ((imm16)>>12)&0xf, cond)

#define ARM_MOVW_REG_IMM16(p, reg, imm16) \
                ARM_MOVW_REG_IMM16_COND(p, reg, imm16, ARMCOND_AL)



/* BRANCH */
#define ARM_BR_ID 5
#define ARM_BR_MASK 7 << 25
#define ARM_BR_TAG ARM_BR_ID << 25

#define ARM_DEF_BR(offs, l, cond) \
                ((offs) | ((l) << 24) | (ARM_BR_TAG) | (cond << ARMCOND_SHIFT))

/* branch */
#define ARM_B_COND(p, cond, offset) ARM_EMIT(p, ARM_DEF_BR(offset, 0, cond))
#define ARM_B(p, offs) ARM_B_COND((p), ARMCOND_AL, (offs))
/* branch with link */
#define ARM_BL_COND(p, cond, offset) ARM_EMIT(p, ARM_DEF_BR(offset, 1, cond))
#define ARM_BL(p, offs) ARM_BL_COND((p), ARMCOND_AL, (offs))

#define ARM_DEF_BX(reg,sub,cond) \
            (0x12fff << 8 | (reg) | ((sub) << 4) | ((cond) << ARMCOND_SHIFT))

#define ARM_BX_COND(p, cond, reg) ARM_EMIT(p, ARM_DEF_BX(reg, 1, cond))
#define ARM_BX(p, reg) ARM_BX_COND((p), ARMCOND_AL, (reg))

#define ARM_BLX_REG_COND(p, cond, reg) ARM_EMIT(p, ARM_DEF_BX(reg, 3, cond))
#define ARM_BLX_REG(p, reg) ARM_BLX_REG_COND((p), ARMCOND_AL, (reg))



/************************ arm ****************************/
//SUB{S}<c> <Rs>,<Rn>,#<const>
#define ARM_DEF_SUB_IMM12(rs, rn, imm12, cond, s) \
    (imm12)        | \
    (rs << 12)      | \
    (rn << 16)      | \
    (s << 20)       | \
    (0x12 << 21)    | \
    (cond << 28)

#define ARM_SUB_IMM12(dst, rs, rn, imm12) \
	u4 rotate = 0; u4 imm8 = imm12;					\
	while((imm8 & 0xf00) != 0)	{						\
		imm8 = imm8 >> 2;									    \
		rotate+=2;}														\
	if(rotate > 0){													\
		imm8 = (((32-rotate) >> 1) << 8) | imm8;}		\
  ARM_EMIT(dst,(ARM_DEF_SUB_IMM12(rs, rn, imm12, ARMCOND_AL, 0)));

//OPT(S)<c> <Rs>, <Rn>, <Rm>, #shift	<shift_imm>/<Rd> (A3-9 and A5-2)
#define ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, reg_imm, cond, i, r, shift, opt) \
	(rm)						| \
	(i << 4)				| \
	(shift << 5)		| \
	(reg_imm << 7)	| \
	(rs << 12)			| \
	(rn << 16)			| \
	(opt << 21)			| \
	(i << 25)				| \
	(cond << 28)

#define ARMSHIFT_OPT_ADD	0x04
#define ARMSHIFT_OPT_SUB	0x02

//SUB <Rs>, <Rn>, <Rm>
#define ARM_DEF_SUB_REG_REG(dst, rs, rn, rm) \
	ARM_EMIT(dst, (ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, 0x0, ARMCOND_AL, 0x0, 0x0, 0x0, ARMSHIFT_OPT_SUB)))
//SUB <Rs>, <Rn>, <Rm>, #shift <shift_imm>
#define ARM_DEF_SUB_REG_REG_SHIFT_IMM(dst, rs, rn, rm, imm5, shift) \
	ARM_EMIT(dst, (ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, imm5, ARMCOND_AL, 0x0, 0x0,  shift, ARMSHIFT_OPT_SUB)))
//SUB <Rs>, <Rn>, <Rm>, #shift <Rd>
#define ARM_DEF_SUB_REG_REG_SHIFT_REG(dst, rs, rn, rm, rd, shift) \
	ARM_EMIT(dst, (ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, (rd << 1) & 0x1d, ARMCOND_AL, 0x0, 0x1, shift, ARMSHIFT_OPT_SUB)))

//ADD <Rs>, <Rn>, <Rm>
#define ARM_DEF_ADD_REG_REG(dst, rs, rn, rm) \
	ARM_EMIT(dst, (ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, 0x0, ARMCOND_AL, 0x0, 0x0, 0x0, ARMSHIFT_OPT_ADD)))
//ADD <Rs>, <Rn>, <Rm>, #shift <shift_imm>
#define ARM_DEF_ADD_REG_REG_SHIFT_IMM(dst, rs, rn, rm, imm5, shift) \
	ARM_EMIT(dst, (ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, imm5, ARMCOND_AL, 0x0, 0x0, shift, ARMSHIFT_OPT_ADD)))
//ADD <Rs>, <Rn>, <Rm>, #shift <Rd>
#define ARM_DEF_ADD_REG_REG_SHIFT_REG(dst, rs, rn, rm, rd, shift) \
	ARM_EMIT(dst, (ARM_DEF_OPT_IMM_SHIFT(rs, rn, rm, (rd << 1) & 0x1d, ARMCOND_AL, 0x0, 0x1, shift, ARMSHIFT_OPT_ADD)))



//ADD{S}<c> <Rs>,<Rn>,#<const> 

#define ARM_DEF_ADD_IMM12(rs, rn, imm12, cond, s) \
    (imm12)        | \
    (rs << 12)      | \
    (rn << 16)      | \
    (s << 20)       | \
    (0x14 << 21)    | \
    (cond << 28)

#define ARM_ADD_IMM12(dst, rs, rn, imm12) \
	u4 imm8 = imm12; u4 rotate = 0;					\
	while((imm8 & 0xf00) != 0)	{						\
		imm8 = imm8 >> 2;									    \
		rotate+=2;}														\
	if(rotate > 0){													\
		imm8 = (((32-rotate) >> 1) << 8) | imm8;}		\
  ARM_EMIT(dst,(ARM_DEF_ADD_IMM12(rs, rn, imm8, ARMCOND_AL, 0)));

//MRS<c> <Rs>,<spec_reg>

#define ARM_DEF_MRS(rs, cond) \
    (rs << 12)       | \
    (0x10f << 16)    | \
    (cond << 28)

#define ARM_MRS(dst, rs) \
    ARM_EMIT(dst,(ARM_DEF_MRS(rs, ARMCOND_AL)));


//MSR<c> <spec_reg>,<Rm>
//MASK <1> :write_nzcvq
//MSK <0>: write_g
#define ARM_DEF_MSR(rm, mask, cond) \
    (rm)       | \
    (0xf<<12)    | \
    (mask<<18)    | \
    (0x12<<20)    |\
    (cond << 28)

#define ARM_MSR_REG(dst, rm, mask) \
    ARM_EMIT(dst,(ARM_DEF_MSR(rm, mask, ARMCOND_AL)));


/*********************** thumb ***********************/

//be cautions.
#define THUMB2_EMIT(dst, ins) { *((u2*)(dst)) = (u2)(((ins) & 0xffff0000)>>16); *((u2*)(dst + 2)) = (u2)((ins) & 0xffff);(dst) += 4;}
//put ins into instruction cache directly
#define THUMB2_RAW(dst, ins) {THUMB2_EMIT(dst, ins)}


#define THUMB_EMIT(dst, ins) {*((u2*)(dst)) = (u2)(ins); (dst) += 2;}
#define THUMB_RAW(dst, ins) {THUMB_EMIT(dst, ins)}

/* push. */
#define THUMB_DEF_PUSH(regs, m) \
    (regs)        | \
    (m << 8)      | \
    (0x5a << 9)

//m: 1-> do we need push lr
#define THUMB_PUSH(dst, regs, m) \
    THUMB_EMIT(dst,(THUMB_DEF_PUSH(regs, m)));


/* pop */
#define THUMB_DEF_POP(regs, p) \
    (regs)        | \
    (p << 8)      | \
    (0x5e << 9)

#define THUMB_POP(dst, regs, p) \
    THUMB_EMIT(dst,(THUMB_DEF_POP(regs, p)));


/* add / subtract*/
/* add rd, rn, rm */
#define THUMB_ADD_SUBTRACT(rd, rn, rm, op, i) \
    (rd)           | \
    (rn << 3)      | \
    (rm << 6)      | \
    (op << 9)      | \
    (i << 10)      | \
    (3 << 11)

#define THUMB_ADD_REG_REG(dst, rd, rn, rm) \
    THUMB_EMIT(dst,(THUMB_ADD_SUBTRACT(rd, rn, rm, 0, 0)));

#define THUMB_ADD_REG_IMM(dst, rd, rn, imm3) \
    THUMB_EMIT(dst,(THUMB_ADD_SUBTRACT(rd, rn, imm3, 0, 1)));


#define THUMB_SUB_REG_REG(dst, rd, rn, rm) \
    THUMB_EMIT(dst,(THUMB_ADD_SUBTRACT(rd, rn, rm, 1, 0)));

#define THUMB_SUB_REG_IMM(dst, rd, rn, imm3) \
    THUMB_EMIT(dst,(THUMB_ADD_SUBTRACT(rd, rn, imm3, 1, 1)));


/* alu */

#define ALU_AND         0x0
#define ALU_EOR         0x1
#define ALU_LSL         0x2
#define ALU_LSR         0x3
#define ALU_ASR         0x4
#define ALU_ADC         0x5
#define ALU_SBC         0x6
#define ALU_ROR         0x7
#define ALU_TST         0x8
#define ALU_NEG         0x9
#define ALU_CMP         0xa
#define ALU_CMN         0xb
#define ALU_ORR         0xc
#define ALU_MUL         0xd
#define ALU_BIC         0xe
#define ALU_MVN         0xf

#define THUMB_ALU(rd, rs, op) \
    (rd)           | \
    (rs << 3)      | \
    (op << 6)      | \
    (0x10 << 10)

#define THUMB_AND_REG(dst, rd, rs) \
    THUMB_EMIT(dst,(THUMB_ALU(rd, rs, ALU_ADD)));


#define THUMB_ALU_IMM(rd, imm8, op) \
    (imm8)           | \
    (rd << 8)      | \
    (op << 11)      | \
    (0x1 << 13)

#define THUMB_MOV_IMM(dst, rd, imm8)\
    THUMB_EMIT(dst,(THUMB_ALU_IMM(rd, imm8, 0)));


/* add offset to sp*/
#define THUMB_SP_OFFSET(s, offset) \
    (offset)           | \
    (s << 7)           | \
    (0xb0 << 8)

#define THUMB_SP_ADD_OFFSET(dst, offset) \
    THUMB_EMIT(dst,(THUMB_SP_OFFSET(0, (offset>>2))));

#define THUMB_SP_SUB_OFFSET(dst, offset) \
    THUMB_EMIT(dst,(THUMB_SP_OFFSET(1, (offset>>2))));


/* load / store with imme offset */
/*offset needs to >>2 first */

/* ldr rd, [rs, #offset]*/
#define THUMB_LDST_IMM_OFFSET(rd, rs , l, offset) \
    (rd)                | \
    (rs << 3)           | \
    ((offset>>2) << 6)  | \
    (l << 11)           | \
    (6<<12)

#define THUMB_LDR_IMM_OFFSET(dst, rd, rs, offset) \
    THUMB_EMIT(dst,(THUMB_LDST_IMM_OFFSET(rd, rs, 1, offset)));

#define THUMB_STR_IMM_OFFSET(dst, rd, rs, offset) \
    THUMB_EMIT(dst,(THUMB_LDST_IMM_OFFSET(rd, rs, 0, offset)));


/* HI REG operation/ branch exchange */
/* CAUTION: reg rd, rs can not be both from r0-r7 (Not necessary)
 *   from ARM V6, both rd/rm can be r0, r7
 *
 */
#define THUMB_HI_OPERATION_BRANCH(rd, rs , op) \
    (rd & 0x7)          | \
    (rs << 3)           | \
    ((rd & 0x8) <<4)    | \
    (op << 8)           | \
    (0x11<<10)

#define THUMB_ADD_HI_REG(dst, rd, rs) \
    THUMB_EMIT(dst,(THUMB_HI_OPERATION_BRANCH(rd, rs, 0)));

#define THUMB_BX(dst, rs) \
    THUMB_EMIT(dst,(THUMB_HI_OPERATION_BRANCH(0, rs, 3)));

/* H1 =1
 *  SEE page A8-60 on ARM DDI 0406A
 */
#define THUMB_BLX(dst, rs) \
    THUMB_EMIT(dst,(THUMB_HI_OPERATION_BRANCH(0x8, rs, 3)));

/* mov rd, rs  -> put rs to rd. one of rs or rd is hi register */
#define THUMB_MOV_HI_REG_REG(dst, rd, rs)\
    THUMB_EMIT(dst,(THUMB_HI_OPERATION_BRANCH(rd, rs, 2)));


/* SP relative load /store */
#define THUMB_DEF_LDST_SP_IMM_OFFSET(rd, l, offset) \
    (offset>>2)         | \
    (rd << 8)           | \
    (l << 11)           | \
    (9 << 12)

#define THUMB_LDR_SP_IMM(dst, rd, imm) \
    THUMB_EMIT(dst,(THUMB_DEF_LDST_SP_IMM_OFFSET(rd, 1, imm)));

#define THUMB_STR_SP_IMM(dst, rd, imm) \
    THUMB_EMIT(dst,(THUMB_DEF_LDST_SP_IMM_OFFSET(rd, 0, imm)));


#define THUMB_DEF_CONB_IMM_OFFSET(cond, offset) \
    (offset>>1)         | \
    (cond << 8)           | \
    (0xd << 12)

#define THUMB_CONB_IMM(dst, cond, offset9) \
    THUMB_EMIT(dst,(THUMB_DEF_CONB_IMM_OFFSET(cond,offset9)));

//todo: what if offset is less than zero?
#define THUMB_DEF_B_IMM11(imm11) \
    (imm11)         | \
    (0x1c << 11)

#define THUMB_B_IMM11(dst, imm11) \
    THUMB_EMIT(dst,(THUMB_DEF_B_IMM11(imm11)));


#define THUMB_DEF_CB_IMM(rn, imm6, nonzero) \
    (rn)         | \
    ((imm6)& 0x1f) << 3 | \
    ((imm6)& 0x20) << 4 | \
    (1<<8) | \
    (nonzero <<11) | \
    (0xb <<12)

#define THUMB_CBNZ(dst, rn, imm6) \
    THUMB_EMIT(dst,(THUMB_DEF_CB_IMM(rn, imm6, 1)));

#define THUMB_CBZ(dst, rn, imm6) \
    THUMB_EMIT(dst,(THUMB_DEF_CB_IMM(rn, imm6, 0)));

//####################### thumb2 ############################################

#define THUMB2_DEF_LDRW_REG(rs, rn, rm, shift) \
    ((rm))                 | \
    ((shift) << 4)         | \
    ((rs) << 12)           | \
    ((rn) << 16)           | \
    (0xf85 << 20)

//LDR.w  <rs>, [rn, rm , LSL # shift]
#define THUMB2_LDR_W_REG(p, rs, rn, rm, shift) \
            THUMB2_EMIT(p, THUMB2_DEF_LDRW_REG(rs, rn, rm, shift))

//LDR<c>.W <Rt>,[<Rn>,#<imm12>]
#define THUMB2_DEF_LDRW_IMM12(rs, rn, imm12) \
    (imm12)                | \
    ((rs) << 12)           | \
    ((rn) << 16)           | \
    (0xf8d << 20)

#define THUMB2_LDRW_IMM12(p, rs, rn, imm12) \
            THUMB2_EMIT(p, THUMB2_DEF_LDRW_IMM12(rs, rn, imm12))

//LDR<c> <RS>,[<Rn>,#-<imm8>]
//LDR<c> <RS>,[<Rn>],#+/-<imm8>
//LDR<c> <RS>,[<Rn>,#+/-<imm8>]!

#define THUMB2_DEF_LDRW_IMM8(rs, rn, imm8, index, add, wb) \
    ((imm8))              | \
    ((wb) << 8)           | \
    ((add) << 9)           | \
    ((index) << 10)           | \
    ((1) << 11)           | \
    ((rs) << 12)           | \
    ((rn) << 16)           | \
    (0xf85 << 20)
//LDR<c><q> <Rt>, [<Rn> {, #+/-<imm>}] Offset: index==TRUE, wback==FALSE
//LDR<c><q> <Rt>, [<Rn>, #+/-<imm>]!   Pre-indexed: index==TRUE, wback==TRUE
//LDR<c><q> <Rt>, [<Rn>], #+/-<imm>    Post-indexed: index==FALSE, wback==TRUE
//index means do we need to add imm8 into base register
#define THUMB2_LDRW_IMM8(p, rs, rn, imm8, index, add, wb) \
            THUMB2_EMIT(p, THUMB2_DEF_LDRW_IMM8(rs, rn, imm8, index, add, wb))


/*push*/
#define THUMB2_DEF_PUSH(regs) \
    ((regs) & (0x5fff))        | \
    (0xe92d << 16)

#define THUMB2_PUSH(dst, regs) \
    THUMB2_EMIT(dst,(THUMB2_DEF_PUSH(regs)));


/*pop*/
#define THUMB2_DEF_POP(regs) \
    ((regs) & (0xdfff))        | \
    (0xe8bd << 16)

#define THUMB2_POP(dst, regs) \
    THUMB2_EMIT(dst,(THUMB2_DEF_POP(regs)));


/*addw T4 */
//ADDW<c> <Rd>,<Rn>,#<imm12>
#define THUMB2_DEF_ADDW_IMM12(rd, rn, imm12) \
    ((imm12) & (0xff))        | \
    (rd << 8)               | \
    (((imm12) & 0x700) <<4)   | \
    (0 << 15)               | \
    (rn << 16)              | \
    (1 << 25 )              | \
    (((imm12) & 0x800) <<15)  | \
    (0x1e <<27)

/*  addw rd, rn, #imm12. */
#define THUMB2_ADDW_IMM12(dst, rd, rn, imm12) \
    THUMB2_EMIT(dst,(THUMB2_DEF_ADDW_IMM12(rd, rn, imm12)));


#define SHIFT_LSL  0x0
#define SHIFT_LSR  0x1
#define SHIFT_ASR  0x2
/*
 * shifttype:
        2 bits: 00 LSL,  shift_n = imm5
                01 LSR,  if imm5 ==0, then 32. else imm5
                02 ASR   if imm5 ==0, then 32. else imm5
                11  (if imm5 == 0) then PRX, shift_n = 1
                    else  ROR, shift_n = imm5
 */
/*addw reg*/
#define THUMB2_DEF_ADDW_REG(rd, rn, rm, shifttype, shift, s) \
    (rm)                    | \
    ((shifttype) << 4)      | \
    ((shift & 0x3) << 6)    | \
    (rd << 8)               | \
    ((shift & 0x1c) << 10) | \
    (0 << 15)               | \
    (rn << 16)              | \
    ((s) << 20)             | \
    (0x758 <<21)

/*  ADD{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>} */
#define THUMB2_ADDW_REG(dst, rd, rn, rm, shifttype, shift) \
    THUMB2_EMIT(dst,(THUMB2_DEF_ADDW_REG(rd, rn, rm, shifttype, shift, 0)));

/*sub. T3 */
#define THUMB2_DEF_SUB_IMM12(rd, rn, imm12, s) \
    (imm12 & (0xff))        | \
    (rd << 8)               | \
    ((imm12 & 0x700) <<4)   | \
    (0 << 15)               | \
    (rn << 16)              | \
    (s << 20)               | \
    (0xd << 21 )              | \
    ((imm12 & 0x800) <<15)  | \
    (0x1e <<27)

/*  sub rd, rn, #imm12*/
#define THUMB2_SUB_IMM12(dst, rd, rn, imm12) \
    THUMB2_EMIT(dst,(THUMB2_DEF_SUB_IMM12(rd, rn, imm12, 0)));


/*subw. T4 */
#define THUMB2_DEF_SUBW_IMM12(rd, rn, imm12) \
    (imm12 & (0xff))        | \
    (rd << 8)               | \
    ((imm12 & 0x700) <<4)   | \
    (0 << 15)               | \
    (rn << 16)              | \
    (0x2a << 20 )              | \
    ((imm12 & 0x800) <<15)  | \
    (0x1e <<27)

/*  subw rd, rn, #imm12*/
#define THUMB2_SUBW_IMM12(dst, rd, rn, imm12) \
    THUMB2_EMIT(dst,(THUMB2_DEF_SUBW_IMM12(rd, rn, imm12)));


/* MOV.W rd,rm T3*/
#define THUMB2_DEF_MOVW_REG(rd, rm, s) \
    (rm)                    | \
    (rd << 8)               | \
    ((0xf) << 16)               | \
    ((s) << 20)               | \
    ((0x752) << 21)

#define THUMB2_MOVW_REG(dst, rd, rm) \
    THUMB2_EMIT(dst,(THUMB2_DEF_MOVW_REG(rd, rm, 0)))

/* MOVW<c> <Rd>,#<imm16> T3*/
#define THUMB2_DEF_MOVW_IMM16(rd, imm16) \
    (imm16 & 0xff)                       | \
    (rd << 8)                            | \
    ((imm16 & 0x700) << 4)               | \
    ((imm16 & 0x800) << 15)               | \
    ((imm16 & 0xf000) << 4)               | \
    ((0x24) << 20)                        | \
    ((0x1e) << 27)

#define THUMB2_MOVW_IMM16(dst, rd, imm16) \
    THUMB2_EMIT(dst,(THUMB2_DEF_MOVW_IMM16(rd, imm16)))


/* LDRH.W rs [rn, rm, LSL #shift]  T2*/
#define THUMB2_DEF_LDRH_REG(rs, rn, rm, shift) \
    (rm)                    | \
    ((shift) << 4)          | \
    ((rs) << 12)            | \
    ((rn) << 16)            | \
    ((0xf83) << 20)

//LDRH<c>.W <Rs>,[<Rn>,<Rm>{,LSL #<shift>}]
#define THUMB2_LDRH_REG(dst, rs, rn, rm, shift) \
    THUMB2_EMIT(dst,(THUMB2_DEF_LDRH_REG(rs, rn, rm, shift)))


/* LDRB<c>.W <Rs>,[<Rn>,<Rm>{,LSL #<shift>}]  T2
 */
#define THUMB2_DEF_LDRB_REG(rs, rn, rm, shift) \
    (rm)                    | \
    ((shift) << 4)          | \
    ((rs) << 12)            | \
    ((rn) << 16)            | \
    ((0xf81) << 20)
//LDRB<c>.W <Rs>,[<Rn>,<Rm>{,LSL #<shift>}]
#define THUMB2_LDRB_REG(dst, rs, rn, rm, shift) \
    THUMB2_EMIT(dst,(THUMB2_DEF_LDRB_REG(rs, rn, rm, shift)))



/* LDMDB<c> <Rn>{!},<registers> T1*/
#define THUMB2_DEF_LDMDB_REG(rn, registers, wb) \
    (registers & 0xdfff)    | \
    ((rn) << 16)            | \
    ((1) << 20)             | \
    ((wb) << 21)            | \
    ((0x3a4) << 22)

#define THUMB2_LDMDB(dst, rn, registers, wb) \
    THUMB2_EMIT(dst,(THUMB2_DEF_LDMDB_REG(rn, registers, wb)))


/* LDMIA<c> <Rn>{!},<registers> T1*/
#define THUMB2_DEF_LDMIA_REG(rn, registers, wb) \
    (registers & 0xdfff)    | \
    ((rn) << 16)            | \
    ((1) << 20)             | \
    ((wb) << 21)            | \
    ((0x3a2) << 22)

#define THUMB2_LDMIA(dst, rn, registers, wb) \
    THUMB2_EMIT(dst,(THUMB2_DEF_LDMIA_REG(rn, registers, wb)))

/* conditional branch T3 */
#define THUMB2_DEF_CONB_IMM20_OFFSET(cond, offset) \
    (((offset) & 0xfff) >>1)             | \
    (((offset) &0x3f000) << 4)         | \
    (((offset) &0x40000)>>5)         | \
    (((offset) &0x80000)>>8)         | \
    (((offset) &0x100000) <<6)         | \
    (1<<15)                          | \
    ((cond)<<22)                     |  \
    ((0x1e) << 27)

#define THUMB2_CONB_IMM20(dst, cond, offset20) \
    THUMB2_EMIT(dst,(THUMB2_DEF_CONB_IMM20_OFFSET(cond,offset20)));


/* MRS */
#define THUMB2_DEF_MRS(rd) \
    ((rd) << 8)              | \
    ((0x1) << 15)            | \
    ((0xf3ef) << 16)

#define THUMB2_MRS(dst, rd) \
    THUMB2_EMIT(dst,(THUMB2_DEF_MRS(rd)));

#define THUMB2_DEF_MSR_REG(rn, mask) \
    ((mask) << 8)              | \
    ((0x1) << 15)            | \
    ((rn) << 16)              | \
    ((0xf38) << 20)

#define THUMB2_MSR_REG(dst, rn, mask) \
    THUMB2_EMIT(dst,(THUMB2_DEF_MSR_REG(rn, mask)));


/* LDR<c> <Rs>,[<Rn>,#-<imm8>]  T4*/
#define THUMB2_DEF_LDR_IMM8(rs, rn, imm8, index, add, wb) \
    (imm8)                    | \
    ((wb) << 8)          | \
    ((add) << 9)          | \
    ((index) << 10)          | \
    ((1) << 11)          | \
    ((rs) << 12)            | \
    ((rn) << 16)            | \
    ((0xf85) << 20)

//index: means do we need to add imm8 to rn as address
//add: + or -
//wb: do we need to write back [rn +/- imm8] to rn
#define THUMB2_LDR_IMM8(dst, rs, rn, imm8, index, add, wb) \
    THUMB2_EMIT(dst,(THUMB2_DEF_LDR_IMM8(rs, rn, imm8, index, add, wb)));

/* STR<c> <Rs>,[<Rn>,#+/-<imm8>]  T4*/
#define THUMB2_DEF_STR_IMM8(rs, rn, imm8, index, add, wb) \
    (imm8)                    | \
    ((wb) << 8)          | \
    ((add) << 9)          | \
    ((index) << 10)          | \
    ((1) << 11)          | \
    ((rs) << 12)            | \
    ((rn) << 16)            | \
    ((0xf84) << 20)

//index: means do we need to add imm8 to rn as address
//add: + or -
//wb: do we need to write back [rn +/- imm8] to rn
#define THUMB2_STR_IMM8(dst, rs, rn, imm8, index, add, wb) \
    THUMB2_EMIT(dst,(THUMB2_DEF_STR_IMM8(rs, rn, imm8, index, add, wb)));


//MOVT<c> <Rd>,#<imm16>  t1
#define THUMB2_DEF_MOVT(rd, imm16) \
    ((imm16) & 0xff)              | \
    ((rd) << 8)                 | \
    (((imm16) & 0x700) << 4)      | \
    (((imm16) & 0x800) << 15)      | \
    (((imm16) & 0xf000) << 4)      | \
    ((0x2c) << 20)               | \
    ((0x1e) << 27)

#define THUMB2_MOVT_IMM(dst, rd, imm16) \
    THUMB2_EMIT(dst,(THUMB2_DEF_MOVT(rd, imm16)));

//MOVW<c> <Rd>,#<imm16>  t3
#define THUMB2_DEF_MOVW(rd, imm16) \
    ((imm16) & 0xff)              | \
    ((rd) << 8)                 | \
    (((imm16) & 0x700) << 4)      | \
    (((imm16) & 0x800) << 15)      | \
    (((imm16) & 0xf000) << 4)      | \
    ((0x24) << 20)               | \
    ((0x1e) << 27)
#define THUMB2_MOVW_IMM(dst, rd, imm16) \
    THUMB2_EMIT(dst,(THUMB2_DEF_MOVW(rd, imm16)));

#endif
