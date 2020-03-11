#ifndef __SANDBOX_GLOBAL_H__
#define __SANDBOX_GLOBAL_H__

#include "debug/debug.h"
#include "sandbox.h"

//#ifdef _SANDBOX_GLOBAL // Added by Rewhy
extern sandbox sbox;

extern char sandbox_jni_gate_keeper, sandbox_jni_gate_keeper_end;
extern char sandbox_jni_gate_keeper_arm_constant_translate;
extern char sandbox_jni_gate_keeper_arm_constant_lock;
extern char sandbox_jni_gate_keeper_debug_constant;

extern char sandbox_constructor_gate_keeper;
extern char sandbox_constructor_gate_keeper_arm_constant_translate;
extern char sandbox_constructor_gate_keeper_arm_constant_lock;
extern char sandbox_constructor_gate_keeper_debug_constant;

extern char sandbox_ret_trampoline, sandbox_ret_trampoline_end;
extern char sandbox_ret_trampoline_constant_unlock;
extern char sandbox_ret_trampoline_constant_debug;

extern char sandbox_ijump_trampoline_arm, sandbox_ijump_trampoline_arm_end;
extern char sandbox_ijump_trampoline_arm_constant;
extern char sandbox_ijump_trampoline_debug_constant;
extern char sandbox_ijump_trampoline_arm_constant_get_tld;

extern char sandbox_callback_trampoline, sandbox_callback_trampoline_end;
extern char sandbox_callback_trampoline_constant;
extern char sandbox_callback_trampoline_constant_translate;
extern char sandbox_callback_trampoline_constant_lock;
extern char sandbox_callback_trampoline_constant_debug;
extern char sandbox_callback_trampoline_constant_get_tld;

extern char sandbox_callback_trampoline_thumb, sandbox_callback_trampoline_thumb_end;
extern char sandbox_callback_trampoline_thumb_constant;
extern char sandbox_callback_trampoline_thumb_constant_translate;
extern char sandbox_callback_trampoline_thumb_constant_lock;
extern char sandbox_callback_trampoline_thumb_constant_debug;
extern char sandbox_callback_trampoline_thumb_constant_get_tld;

extern char sandbox_callback_ret_trampoline, sandbox_callbackret__trampoline_end;
extern char sandbox_callback_ret_trampoline_constant_unlock;
extern char sandbox_callback_ret_trampoline_constant_get_tld;
extern char sandbox_callback_ret_trampoline_constant_debug;

extern char sandbox_callback_ret_trampoline_thumb, sandbox_callbackret__trampoline_thumb_end;
extern char sandbox_callback_ret_trampoline_thumb_constant_unlock;
extern char sandbox_callback_ret_trampoline_thumb_constant_get_tld;
extern char sandbox_callback_ret_trampoline_thumb_constant_debug;

extern char sandbox_jni_trampoline;
extern char sandbox_jni_trampoline_constant_get_tld;
extern char sandbox_jni_trampoline_constant_translate;
extern char sandbox_jni_trampoline_constant_debug;

extern char sandbox_jni_trampoline_thumb;
extern char sandbox_jni_trampoline_thumb_constant_get_tld;
extern char sandbox_jni_trampoline_thumb_constant_translate;
extern char sandbox_jni_trampoline_thumb_constant_debug;
//#endif // End


//wrapper.c
void *wrapper_dlopen(const char *file, int mode);
void *wrapper_dlsym(void * handle, const char * name);
u4 get_native_func(int index);

//trampoline/trampoline.c
//#ifdef _TRAMPOLINE_GLOBAL
void init_trampoline();
//#endif

//linker.c
//#ifdef _SANDBOX_LINKER_GLOBAL
bool __sandbox_linker_init(unsigned sandbox_start);
//#endif

//bt_mem_mgt.c
//#ifdef _FBT_INIT_BA_GLOBAL
bool fbt_init_ba();
void fbt_allocate_new_code_cache(struct thread_local_data *tld);
//#endif

/* bt.c */
//#ifdef _FBT_INIT_GLOBAL
void fbt_init();
//#endif

/* bt_mem_mgt.c */
//#ifdef _BT_MEM_MGT
struct thread_local_data *fbt_init_tls();
void *fbt_lalloc(struct thread_local_data *tld, int pages, enum mem_type type);
void *fbt_smalloc(struct thread_local_data *tld, long size);
//#endif

/* bt_code_cache.c */
//#ifdef BT_CODE_CACHE
void *fbt_ccache_find(struct thread_local_data *tld, void *orig_address);
void fbt_ccache_add_entry(struct thread_local_data *tld, void *orig_address,
                          void *transl_address);

void *fbt_translate_noexecute(void *orig_address,
                                struct thread_local_data *tld, int t_mode);
void *fbt_translate_noexecute_bridge(void *orig_address,
                                struct thread_local_data *tld);
//#endif



/* bt_transalte_arm.c */
//#ifdef BT_TRANSALTE_ARM
ins_type fbt_translate_instr_arm(struct translate *ts);
//#endif

/* bt_transalte_thumb.c */
//#ifdef BT_TRANSALTE_THUMB
ins_type fbt_translate_instr_thumb(struct translate *ts);
//#endif

//bt_dis_thumb.c
//#ifdef BT_DIS_THRUMB
void dis_thumb2_instruction(u4 addr, u4 insn);
int dis_thumb_instruction(u4 addr, u2 insn);
//#endif

//bt_dis_arm.c
//#ifdef BT_DIS_ARM
void dis_arm_instruction(u4 addr, u4 insn);
//#endif

//thread/jni.c
//#ifdef THREAD_JNI
void init_tld_jni(struct thread_local_data * tld);
bool validate_jni(u4 addr);
//#endif

//thread/thread.c
//#ifdef THREAD_THREAD
struct thread_local_data * get_tld();
struct thread_local_data * lock_thread();
struct thread_local_data * unlock_thread();
struct thread_local_data * lock_thread_1();
//#endif

//debug/debug.c
//#ifdef DEBUG_DEBUG
void bt_debug_print_address(u4 addr, int type);
void bt_debug_print_reg(u4 reg_index, u4 value, u4 pc);
void bt_debug_print_pc(u4 pc);
//#endif


//debug/bdb.c
//#ifdef DEBUG_BDB
int bdb_debugger_init();
void gen_enter_debugger_thumb(struct translate *ts);
bool send_pc_mapping(u4 o_pc, u4 t_pc);
//#endif


#endif
