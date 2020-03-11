#ifndef __SANDBOX_ARM_H__
#define __SANDBOX_ARM_H__


#if defined(SANDBOX_TARGET_ARM_THUMB2_MODE)
    #define SANDBOX_NOOP_OPCODE        0x46c0      /* mov r8, r8 */
    #define SANDBOX_HALT_OPCODE        0xbe00      /* bkpt 0x0000 */
    #define SANDBOX_HALT_LEN           2           /* length of halt instruction */
#else
    #define SANDBOX_NOOP_OPCODE        0xe1a00000  /* mov r0, r0 */
    #define SANDBOX_HALT_OPCODE        0xe1266676  /* bkpt 6666 */
    #define SANDBOX_HALT_LEN           4           /* length of halt instruction */
#endif  /* defined(SANDBOX_TARGET_ARM_THUMB2_MODE) */


#define SANDBOX_HALT_WORD          NACL_HALT_OPCODE

#if defined(SANDBOX_TARGET_ARM_THUMB2_MODE)
    #define SANDBOX_HALT         bkpt
#else
    #define SANDBOX_HALT         mov pc, #0
#endif  /* defined(SANDBOX_TARGET_ARM_THUMB2_MODE) */

#define SANDBOX_HALT_THUMB bkpt

#define ARM_PAGE_SIZE   0x1000
#define ARM_PAGE_BITS    12
#define ARM_PAGE_MASK   0xfff
#define ARM_PAGE_CLEAR  (~ARM_PAGE_MASK)

#define ARM_MODE_THUMB 0x1
#define ARM_MODE_ARM   0x0

#endif