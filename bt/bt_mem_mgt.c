#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

#include "ba/ba.h"
#include "sandbox.h"
#include "global.h"

#include "bt.h"
#include "bt_code_cache.h"



/* Untrusted stack is pre-allocated (inside sandbox) and we need to allocate
 * the stack for each thread. Buddy allocator is used here.
 */
static struct ba_bits ut_stack_bitmap[STACK_SIZE / PAGESIZE];
static struct ba ba_ut_stack = {
    //yajin: we need to add base later
    .base = STACK_START,
    .size = STACK_SIZE,
    //one page.
    .min_alloc = ARM_PAGE_SIZE,
    /* max_order will be determined automatically */
    .bitmap = ut_stack_bitmap,
    .num_entries = sizeof(ut_stack_bitmap)/sizeof(ut_stack_bitmap[0]),
};

/*code cache*/
static struct ba_bits code_cache_bitmap[CODECACHE_SIZE / CODE_CACHE_ALLOC_SIZE];
static struct ba ba_code_cache = {
    //yajin: we need to add base later
    .base = CODECACHE_START,
    .size = CODECACHE_SIZE,
    //CODE_CACHE_ALLOC_PAGES * PAGE_SIZE
    .min_alloc = CODE_CACHE_ALLOC_SIZE,
    /* max_order will be determined automatically */
    .bitmap = code_cache_bitmap,
    .num_entries = sizeof(code_cache_bitmap)/sizeof(code_cache_bitmap[0]),
};

//initiate the ba allocator for bt
bool fbt_init_ba() {
	TRACE_ENTER;
    ba_ut_stack.base += sbox.sandbox_start;
    ba_init(&ba_ut_stack);

    ba_code_cache.base += sbox.sandbox_start;
    ba_init(&ba_code_cache);
		TRACE_EXIT;
    return true;
}

static void * g_mappingtable = NULL;

struct thread_local_data *fbt_init_tls() {
    void *mem;
    mem = fbt_mmap(NULL, SMALLOC_PAGES * PAGESIZE, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        BT_ERR(false, "OOPS: cannot mmap the memory space.");
        return NULL;
    }

    struct thread_local_data *tld = (struct thread_local_data*)(mem);

    //allocate the untrusted stack for this thread
    tld->ut_stack_ba_index = ba_allocate(&ba_ut_stack, UNTRUSTED_STACK_SIZE);
    //tld->ut_stack_ba_index = ba_reverse_allocate(&ba_ut_stack, UNTRUSTED_STACK_SIZE);

    if(tld->ut_stack_ba_index < 0) {
        BT_ERR(false, "OOPS: cannot allocate memory for untrusted stack.");
        return NULL;
    }

    //TODO: put a guard byte here to make sure that the stack can not be
    // overflowed. However since this stack is for untrusted code, we really
    // do not care about it....
    tld->ut_stack = ba_start_addr(&ba_ut_stack, tld->ut_stack_ba_index);
    //make the stack rw
    mprotect((void *)((u4)tld->ut_stack), UNTRUSTED_STACK_SIZE,
                                        PROT_READ | PROT_WRITE);
    //stack is from top to down
    tld->ut_stack += UNTRUSTED_STACK_SIZE;
    BT_INFO("INFO: allocated untrusted stack. Top of the stack is 0x%8x", tld->ut_stack);

    /* initialize memory allocation */
    tld->chunk = (struct mem_info*)(tld + 1);
    tld->chunk->next = NULL;
    tld->chunk->type = MT_INTERNAL;
    tld->chunk->ptr = mem;
    tld->chunk->size = SMALLOC_PAGES * PAGESIZE;
    tld->chunk->ba_index = -1;

    /* initialize translate struct */
    tld->trans.tld = tld;
    tld->trans.transl_instr = NULL;
    tld->trans.code_cache_end = NULL;
    tld->trans.cur_instr = NULL;
    //tld->trans.next_instr = NULL;

    tld->smalloc = (void*)(tld->chunk + 1);
    tld->smalloc_size = (SMALLOC_PAGES * PAGESIZE) - ((u4)(tld->smalloc)
                                                            - (u4)(mem));

    /* allocate memory for hashtable.
       0x1 guard for tcache_find_fast asm function */
    
		/* mapping table is global for all threads */
    if (g_mappingtable == NULL) {
        g_mappingtable = fbt_lalloc(tld, (MAPPINGTABLE_SIZE / PAGESIZE) + 1,
                                                         MT_MAPPING_TABLE);
    }
    tld->mappingtable = g_mappingtable;

    BT_INFO("INFO: allocated mapping table. address [0x%8x]",
                                                            (u4)tld->mappingtable);

    /* guard for find_fast-wraparound used in optimizations */
    *(u4*)((u4)(tld->mappingtable)+MAPPINGTABLE_SIZE) = 0x1;

    tld->ret_trampoline = (void *)(sbox.sandbox_start + RET_TRAMPOLINE_START);

		tld->callback_ret_trampoline = (void *)&sandbox_callback_ret_trampoline;
    // tld->gate_keeper = (void *)(sbox.gate_keeper_start);
    //tld->ijump_trampoline_arm = (void *)(sbox.sandbox_start + IJUMP_TRAMPOLINE_START);

    //will be set in lock_thread() (wrapper.c)
    tld->untrusted_func_addr = 0;

    //current mode is ARM
    // tld->cur_mode = ARM_MOD_ARM;

    return tld;
}


void *fbt_lalloc(struct thread_local_data *tld,
                    int pages, enum mem_type type) {
    assert(pages > 0);

    /* TODO: add guard pages for stack, mapping table, code cache */
    int alloc_size = pages * PAGESIZE;

    struct mem_info *chunk = fbt_smalloc(tld, sizeof(struct mem_info));

    /* what flags should we use for the current alloc? */
    long prot = 0;
    switch (type) {
        case MT_INTERNAL:
        case MT_MAPPING_TABLE:
#if defined(SHADOWSTACK)
        case MT_SHADOWSTACK:
#endif
#if defined(AUTHORIZE_SYSCALLS)
        case MT_SYSCALL_TABLE:
#endif
#if defined(ICF_PREDICT)
        case MT_ICF_PREDICT:
#endif
            prot = PROT_READ|PROT_WRITE;
            break;
        case MT_CODE_CACHE:
        case MT_TRAMPOLINE:
            prot = PROT_READ|PROT_WRITE|PROT_EXEC;
            break;
    }

    void *retval;
    /* code cache is pre-allocated inside sandbox */
    if (type == MT_CODE_CACHE) {

        chunk->ba_index = ba_allocate(&ba_code_cache, alloc_size);
        if(chunk->ba_index < 0) {
            BT_ERR(true, "OOPS: cannot allocate memory for code cache.");
        }
        retval = (void *)ba_start_addr(&ba_code_cache, chunk->ba_index);
        /* change this memory region to rwx */
        /* todo: remove w when the code cache is executing...*/
        mprotect(retval, alloc_size, prot);

    } else {
        retval = fbt_mmap(NULL, alloc_size, prot, MAP_PRIVATE|MAP_ANONYMOUS,
                                                                    -1, 0);
        if (retval == MAP_FAILED) {
            BT_ERR(true, "BT failed to allocate memory \n");
        }
        chunk->ba_index = -1;
    }
    /* fill in the memory chunk information and store it in the list */
    chunk->ptr = retval;
    chunk->size = alloc_size;
    chunk->type = type;
    chunk->next = tld->chunk;
    tld->chunk = chunk;
    return retval;
}

/*Yajin: The smallocated memory is never release? */
void *fbt_smalloc(struct thread_local_data *tld, long size) {
    /* ensure that we use smalloc only for small stuff */
    if (size > SMALLOC_MAX || size <= 0) {
        BT_ERR(true, "Too much memory requested\n");
    }

    /* do we need to allocate additional small memory space? */
    if (size > tld->smalloc_size) {
        void *mem;
        mem = fbt_mmap(NULL, SMALLOC_PAGES * PAGESIZE, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            BT_ERR(true, "BT failed to allocate memory \n");
        }
        tld->smalloc_size = SMALLOC_PAGES * PAGESIZE;
        tld->smalloc = mem;

        struct mem_info *chunk = (struct mem_info*)fbt_smalloc(tld,
                                                    sizeof(struct mem_info));

        chunk->type = MT_INTERNAL;
        chunk->ptr = mem;
        chunk->size = SMALLOC_PAGES * PAGESIZE;

        chunk->next = tld->chunk;
        tld->chunk = chunk;
    }

    /* let's hand that chunk of memory back to the caller */
    void *mem = tld->smalloc;
    tld->smalloc += size;
    assert(((long)tld->smalloc) == ((long)mem)+size);

    return mem;
}

void fbt_allocate_new_code_cache(struct thread_local_data *tld) {
    void *mem = fbt_lalloc(tld, CODE_CACHE_ALLOC_PAGES, MT_CODE_CACHE);
    tld->trans.transl_instr = mem;
    tld->trans.code_cache_end = mem + (CODE_CACHE_ALLOC_PAGES * PAGESIZE)
                                                            - TRANSL_GUARD;
    BT_INFO("INFO: allocated code cache.[0x%8x-0x%8x)",
                                    (u4)tld->trans.transl_instr,
                                    (u4)tld->trans.code_cache_end + TRANSL_GUARD);

    /* fill code cache with invalid instructions */
    memset(tld->trans.transl_instr, 0xffffffff,
                    (CODE_CACHE_ALLOC_PAGES * PAGESIZE)/4);

    cacheflush((u4)tld->trans.transl_instr, (u4)tld->trans.code_cache_end, 0);
}

