#ifndef __SANDBOX_SANDBOX_H__
#define __SANDBOX_SANDBOX_H__

#include <jni.h>

#include "types.h"
#include "bt/bt.h"

//the struct maintains the global information of sandbox
struct sandbox{
    u4 sandbox_start; // the start address of our sandbox
    u4 sandbox_end; //the end address of our sandbox

    //start of jni gate keeper
    void * gate_keeper_start;

    /* the vm passed into native function */
    JavaVM* vm;
};

typedef struct sandbox sandbox;

extern sandbox sbox;
extern bool sandbox_mode;
//the context need to be saved when switching
//TODO: this should be per thread.
// struct arm_context{
//     /* fp: r11, stack_ptr: sp, prog_ctr: pc?? */
//     u4 r4, r5, r6, r7, r8, r9, r10, fp, stack_ptr, prog_ctr;
//     /*  0   4   8   c  10  14   18  1c      20        24 */
//     //Floating-Point Status and Control Register
//     u4 fpscr;
//     /*28*/
// };

/*
 * design of memory layout (2012-09-18)
 *
 *  reserved space to make sure this memory space is 16M aligned.
 *
 *  384M: heap for untrusted code. (rw)
 *  64M: stack for untrusted code (rw)
 *  128M: original code + data (bss.got.plt...) (code:ro. other rw)
 *
 *  The previous space range is for data sandbox which means all the memory
 *   access can not be beyond this address space range.
 *
 *  256M: code cache (x). These are the translated code.
 *
 *  The translated code is code sandbox, which means all the jump can not 
 *  be out of this address range.
 *
 *  other space: trampoline?
 *
 *
 ****************** The design of data sandbox ******************************
 *
 *  The memory space need to be 16M aligned for data sandbox.
 *  Since the data sandbox can be in arbitrary address range, we can not simply
 *  mask particular bits in the register to constrain the memory range which
 *  can be accessed. -> performance overhead ...
 *  Another challenge here is that the code can be ARM code or thumb code or
 *  even thumb2 code. (thumb2 is one particular thumb code and when running
 *  thumb2 code, the cpu is still in thumb mode.)
 *
 *  For the ARM code, the translated code is ARM
 *  For thumb code, the translated code is thumb (and the data access constraint
 *                                                code is thumb2) -> see following
 *  for thumb2 code, the translated code is thumb2
 *
 *  For the following memory access instruction:
 *
 *   ldr   r2, [r3, #4444]
 *
 *   We need to make sure that r3 + #4444 should not in the range of data sandbox.
 *
 *   The sandbox address should be 16M bytes aligned because of the constant in
 *   cmp instruction can only 8 bits set. (see ARM instruction reference
 *     Operand 2 as a constant)
 *
 *   Suppose the start address of datasandbox is 0x4000 0000 and the end address
 *   is 0x5fff ffff
 *
 *   case (1): the instruction is ARM
 *
 *       #since r2 will be overwritten by the content from memory,
 *       #we can reuse it.
 *       add  r2, r3, #444
 *       cmp r2, #0x40000000
 *       movlt  pc, #0   -> if r2 < 0x40000000, set pc = 0 -> segment fault
 *       cmp r2, #0x60000000
 *       movge pc, #0    -> if r2 >= 0x60000000, set pc = 0
 *       ldr r2, [r2]    -> we can access memory now
 *
 *       0:   e2832f6f    add r2, r3, #444    ; 0x1bc
 *       4:   e3520101    cmp r2, #1073741824 ; 0x40000000
 *       8:   b3a0f000    movlt   pc, #0  ; 0x0
 *       c:   e3520206    cmp r2, #1610612736 ; 0x60000000
 *       10:  a3a0f000    movge   pc, #0  ; 0x0
 *       14:  e5922000    ldr r2, [r2]
 *
 *       (instruction length: 24 bytes)
 *
 *
 *   case (2): the instruction is thumb or thumb2
 *
 *     .sandbox_stub:
 *       .thumb
 *       .syntax unified
 *
 *       add    r2, r3, #444
 *       cmp    r2, #0X4F000000
 *       blt   .ee
 *       cmp    r0, #0x60000000
 *       bge    .ee
 *       ldr    r2, [r2]
 *       b      .right
 *   .ee:
 *      bkpt   #44
 *   .right:
 *
 *
 *      0:   f503 72de   add.w   r2, r3, #444    ; 0x1bc
 *      4:   f1b2 4f9e   cmp.w   r2, #1325400064 ; 0x4f000000
 *      8:   db04        blt.n   14 <.ee>
 *      a:   f1b0 4fc0   cmp.w   r0, #1610612736 ; 0x60000000
 *      e:   da01        bge.n   14 <.ee>
 *     10:   6812        ldr r2, [r2, #0]
 *     12:   e000        b.n 16 <.right>
 *
 *     00000014 <.ee>:
 *     14:   be2c        bkpt    0x002c
 *
 *     (instruction length: 22 bytes)
 *
 *
 ******************* The design of code sandbox ******************************
 *
 *
 * For code sandbox, the target of direct jump is known when translating the
 * code. For the indirect jump, it should go to binary translator to do address
 * mapping between old pc to new pc. So we can check the address range here and
 * it should not be a problem.
 *
 *  We also need to process the implicit indirect jumping (ldr pc, xxxx)
 *  -> a challenge here (like the return address in x86)
 *
 *
 *  For code sandbox, we do not insert checking code when doing translation because
 *    (1) the target is invalid, and it happens to have a hit in mapping hash table.
 *       In this case, the code will jump to the hit code cache, which is not
 *        what we want but is not dangerous since all the translated code in
 *        code cache does not have dangerous code
 *    (2) the target is invalid and it does not hit in mapping hash table.
 *       In this case, we will call translate routine to translate target code,
 *       which will do the checking!!!
 *
 */

/******************************** macro ***********************************/



/*
 * Address space layout of sandbox:
 * Our sandbox reserves SANDBOX_MEM_SIZE bytes for untrusted native code.
 */
#define SANDBOX_MEM_SIZE 0x40000000 //(1GB)

//sandbox address space is 16M aligned
#define SANDBOX_START_ALIGNED    0x1000000



/* heap: 0M - 384M */
#define HEAP_START (0x000000)
#define HEAP_SIZE  (0x17600000)
#define HEAP_END   (HEAP_START + HEAP_SIZE - 1)

/* stack: 384M - 448M : 64M
 *        We have different stack for different threads.
 *   64M/16K = 4K (threads)
 */
#define STACK_START (0x18000000)
#define STACK_SIZE (0x4000000)
#define STACK_END   (STACK_START + STACK_SIZE - 1)

/* untrusted code: 448M - 576M: 128M */
#define UNTRUSTED_LIB_START    (0x1c000000)
#define UNTRUSTED_LIB_SIZE     (0x8000000)
#define UNTRUSTED_LIB_END      (UNTRUSTED_LIB_START + UNTRUSTED_LIB_SIZE - 1)


/* we put the trampoline close to code cache.
 */

/* trampoline: 576M - 608M: 32M */
#define TRAMPOLINE_START (0x24000000)
#define TRAMPOLINE_SIZE  (0x2000000)
#define TRAMPOLINE_END   (TRAMPOLINE_START + TRAMPOLINE_SIZE - 1)

//from 1M. This is the trampoline from untrutsed code to trusted code
#define RET_TRAMPOLINE_START    TRAMPOLINE_START + 0x100000
#define IJUMP_TRAMPOLINE_START  RET_TRAMPOLINE_START + ARM_PAGE_SIZE

#define CALLBACK_TRAMPOLINE_START				RET_TRAMPOLINE_START + ARM_PAGE_SIZE
#define CALLBACK_RET_TRAMPOLINE_START		CALLBACK_TRAMPOLINE_START + ARM_PAGE_SIZE

/* code  cache: 608M - 864M: 256M */
#define CODECACHE_START    (0x26000000)
#define CODECACHE_SIZE     (0x10000000)
#define CODECACHE_END      (CODECACHE_START + CODECACHE_SIZE - 1)


/* 864M - 1G: Reserved*/


/* 64K for the untrusted stack for each thread. */
#define UNTRUSTED_STACK_SIZE     0x10000


bool init_sandbox_address_space();


#endif

