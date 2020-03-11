#ifndef __TRAMPOLINE_TRAMPOLINE_H__
#define __TRAMPOLINE_TRAMPOLINE_H__



/* 8k */
#define GATE_KEEPER_STAGE1_SIZE   (0x2000)


#define GATE_KEEPER_STAGE1_ENTRY_SIZE (16)
/*each entry is 16 bytes*/
#define GATE_KEEPER_STAGE1_ENTRY_NUM (500)

//e92d4000    push    {lr}
//e92d4ff0    push    {r4, r5, r6, r7, r8, r9, sl, fp, lr}
//e3a04001    mov    r4, #1
//ea000007    b     xxxx

#define GATE_KEEPER_STAGE1_E1    0xe92d4000
#define GATE_KEEPER_STAGE1_E2    0xe92d4ff0
#define GATE_KEEPER_STAGE1_E3    0xe3a04000  // imm is last 12 bits
#define GATE_KEEPER_STAGE1_E4    0xea000000  // imm is last 24 bits

/* 4k */
#define GATE_KEEPER_STAGE2_SIZE   (0x1000)



extern void * gate_keeper_start;

#endif