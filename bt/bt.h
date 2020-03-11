#ifndef __SANDBOX_BT_H__
#define __SANDBOX_BT_H__


#include "../types.h"
#include "../arm.h"

/*************** macro *******************/
#define assert(x)

#ifdef PAGESIZE
#undef PAGESIZE
#endif
#define PAGESIZE ARM_PAGE_SIZE


/** always allocate 1MB of additional code cache memory */
#define CODE_CACHE_ALLOC_PAGES 0x100
/* CODE_CACHE_ALLOC_PAGES * PAGE_SIZE */
#define CODE_CACHE_ALLOC_SIZE 0x100000

/*
 * Guard of 1/2page that is used in the code-cache for special optimizations.
 * Generally we can stop translating after every single instruction. But if we
 * are in some specific optimizations (e.g., inlining) then we must continue
 * the translation process until we have processed all inlined frames.
 * Because of this we might be unable to stop the translation process if the end
 * of a code cache is reached. Therefore we have a safety margin at the end of
 * every code cache that could be used as a spill region.
 * WARNING: all optimizations might not use more space than TRANSL_GUARD!
 *
 */
#define TRANSL_GUARD 2048


/* allocate this many pages every time we run out of small memory */
#define SMALLOC_PAGES 10
/* max. nr of bytes that can be allocated in a smalloc call */
#define SMALLOC_MAX 0x100

//yajin: do we need the real implementation of fbt_mmap?
#define fbt_mmap mmap

/** different types for memory chunks */
enum mem_type {
    MT_CODE_CACHE,			/**< code cache (RX[W]) */
    MT_MAPPING_TABLE,		/**< mapping table (R[W]) */
#if defined(SHADOWSTACK)
    MT_SHADOWSTACK,			/**< shadow stack (R[W]) */
#endif
#if defined(AUTHORIZE_SYSCALLS)
    MT_SYSCALL_TABLE,		/**< syscall table (R[W]) */
#endif	
#if defined(ICF_PREDICT)
    MT_ICF_PREDICT,			/**< prediction for indirect control flows (R[W]) */
#endif
    MT_TRAMPOLINE,			/**< trampolines to translate new code blocks (RX[W]) */
    MT_INTERNAL					/**< internally used memory (R[W]) */
};

/**
 * This struct is used when a new instruction is parsed and translated.
 * The struct gets updated through the disassembling function and the
 * information is then consumed by the action function (that handles the
 * opcode).
 */
/* this struct is per-thread */
struct translate {
    /** points to the current position in the code cache */
    unsigned char *transl_instr;
    /** points to the end of the code cache */
    unsigned char *code_cache_end;
    /** pointer to the instruction that is currently being translated */
    unsigned char *cur_instr;
    /** pointer to the next instruction */
    unsigned char *next_instr;
    /* for thumb2 conditional execution */
    int it_index;
    int it_cur_num;
    int it_total_num;
    int condexec_cond[4];
    int insn_changed[4];
    unsigned char * it_transl_instr;
    unsigned char * it_instr;
    /** pointer back to tld (for action functions) */
    struct thread_local_data *tld;
};

/** Information about a memory chunk */
struct mem_info {
    enum mem_type type;			/**< chunk type */
    struct mem_info *next;  /**< pointer to next chunk or NULL */
    void *ptr;							/**< pointer to allocated memory */
    long size;							/**< length of allocated memory */
    /* for code cache, the memory is allocated in sandbox using buddy allocator.
     * ba_index stores the index used by buddy allocator. (see ba/ba.c)
     */
    long ba_index;
};

/**
 * This structure defines thread local data that is needed inside the BT.
 * These fields are set during the startup of the BT and then used whenever
 * a new block of code is translated.
 */

/* the trampoline relies on the layout of this structure. Be cautious when you
 * change it. Please change the macro in ../asm.h accordingly if you have changed
 * this structure. see ../asm.h for the constants.
 */
struct thread_local_data {
    /** mapping table between code cache and program */
    void *mappingtable;                                 /*offset 0x0*/

    /* the address of ret_trampoline.
     * ret_trampoline is used for jump from untrusted code
     * to trust code.
     */
    void * ret_trampoline;                              /*offset 0x4*/

    /* the address of gate_keeper.
     * gate keeper is used for jumping from trust code
     * to untrusted cod.
     */
    //void * gate_keeper;                                 /*offset 0x8*/

    //void * ijump_trampoline_arm;                        /*offset 0xc*/

    /* current untrusted stack for this thread.
     * when returning from untrusted code to trusted code,
     * the trampoline will save current stack into this field
     */
    u4 ut_stack;                                        /*offset 0x8*/
    /* the index in ba allocator */
    int ut_stack_ba_index;                              /* offset 0xc */

    /* the saved trusted stack address */
    u4 t_stack;                                         /* offset 0x10 */

    /* the address of untrusted function in native libs. This function
     * is the one that will be called using jni. This value will be set
     *  in wrapper_dlsym!!!
     */
    u4 untrusted_func_addr;                             /* offset 0x14 */

    /* the address of JNI function call (in libdvm.so ) */
    u4 jni_func_addr;                                   /* offset 0x18 */

    void * callback_ret_trampoline;                          /* offset 0x1c */

    /* the trampoline and gate keeper is NOT per thread.
     * we put the address here for quickly accessing its address.
     */

    /** all allocated memory */
    struct mem_info *chunk;
    /** pointer to memory that can be used through the fbt_smalloc allocator */
    void *smalloc;
    /** amount of memory left available at smalloc above */
    long smalloc_size;

    /* translation information for the current instruction that is
     * currently being translated.
     */
    struct translate trans;

    /*for JNI calls (See jni.c) */
    void * jni_func_hash;
};

/* instruction type */
#if 0
enum ins_type {
    /* instruction will cause control flow transfer */
    INS_INDIRECT_JUMP = (1<<1),
    /* direct jump */
    INS_DIRECT_JUMP = (1<<2),
    /* instruction will load data from memory (other )*/
    INS_LOAD = (1<<3),
    /* pc relative load */
    INS_PC_RELATIVE_LOAD = (1<<4),
    /* instruction will store data into memory */
    INS_STORE = (1<<5),
     /* pc relative store */
    INS_PC_RELATIVE_STORE = (1<<6),
    /*ALU has pc as operand */
    INS_PC_ALU = (1<<7),
    /* system call instruction*/
    INS_SYSCALL = (1<<8),
    /* do not copy this instruction. such as IT instruction */
    INS_SKIP = (1<<9),
    /*INS_UNDEFINED*/
    INS_UNDEFINED = (1<<10),
    /*INS_ILLEGAL */
    INS_ILLEGAL = (1<<11),
    /*INS_PROCESSED*/
    INS_PROCESSED = (1<<12),
    /*INS_NORMAL. Just copy this instruction into code cache */
    INS_NORMAL = (1<<13),
};
#endif

enum ins_type {
    /* skip this instruction */
    INS_SKIP = (1<<0x1),
    /* copy this instruction */
    INS_COPY = (1<<0x2),
    /* this instruction has been processed */
    INS_PROCESSED = (1<<0x3),

    /*detailed instruction type. We really do not care them */

    /* instruction will cause control flow transfer */
    INS_INDIRECT_JUMP = (1<<0x4),
    /* direct jump */
    INS_DIRECT_JUMP = (1<<0x5),
    /* instruction will load data from memory (other )*/
    INS_LOAD = (1<<0x6),
    /* pc relative load */
    INS_PC_RELATIVE_LOAD = (1<<0x7),
    /* instruction will store data into memory */
    INS_STORE = (1<<0x8),
    /* pc relative store */
    INS_PC_RELATIVE_STORE = (1<<0x9),
    /*ALU has pc as operand */
    INS_PC_ALU = (1<<0xa),
    /* system call instruction*/
    INS_SYSCALL = (1<<0xb),
    /* ARM neon instructions */
    INS_NEON = (1<<0xc),
    /* conditional jump */
    INS_CONDITIONAL_JUMP = (1<<0xd),
    /* VFP */
    INS_VFP = (1<<0xe),

    INS_TODO = (1<<31),
};
typedef enum ins_type ins_type;

/** the translation can be in these states. */
enum translation_state {
  /** translation must not stop after this instruction but must continue */
  OPEN,
  /** translation may stop after this instruction */
  NEUTRAL,
  /** translation must stop after this instruction */
  CLOSE,
  /** translation must stop after this instruction and fixup code must be
     inserted as if the instruction limit is reached */
  CLOSE_GLUE
};
typedef enum translation_state translation_state;

#endif
