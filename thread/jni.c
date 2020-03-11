#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utility.h"
#include "types.h"
#include "sandbox.h"
#include "global.h"
#include "arm.h"
#include "sandbox.h"

/* The JNI functions exposed by JNIEnv can be called by untrusted native
 *  libraries. And these JNI functions are out of sandbox.
 *
 * We need to allow such calls and only allow such calls.
 *
 *
 *  (1) We put the address of these JNI functions into a hash table
 *  (2) When untrusted libs want to jump out sandbox, we check whether
 *      the target address is in this hash table. If so, we will check
 *      the parameters and then jump to JNI function. Otherwise, the
 *      untrusted lib is doing something wrong and we can block its execution.
 *
 *
 *   See section 4.4 in Robusta paper.
 */


/* There are around 250 JNI functions */

struct hash_entry {
	u4   func_address;
	struct hash_entry * next;
};


#define HASH_LEN      512
#define HASH_FUNC(addr)  ((addr>>4)%(HASH_LEN))

// struct hash_entry * jni_funcs_hash[HASH_LEN];

static void * global_jni_func_hash = NULL;

static void * new_hash_table() {
	if(global_jni_func_hash)
		return global_jni_func_hash;

	global_jni_func_hash = malloc(HASH_LEN * sizeof(void*));
	if (global_jni_func_hash == NULL) {
		SANDBOX_LOGE("[x] [%s:%d]: can not get global_jni_func_hash \n", FILE, LINE);
		return NULL;
	}

	SANDBOX_LOGE("[x] [%s:%d]: malloced global_jni_func_hash (0x%8x-0x%8x)\n", FILE, LINE, (u4)global_jni_func_hash, (u4)global_jni_func_hash+HASH_LEN*sizeof(void*));
	memset(global_jni_func_hash, 0x0, HASH_LEN * sizeof(void*));
	return global_jni_func_hash;
}

/*void new_hash_table(struct thread_local_data *tld) {
	if (tld->jni_func_hash) {
		return;
	}

	tld->jni_func_hash = malloc(HASH_LEN * sizeof(void*));
	if (tld->jni_func_hash == NULL) {
		SANDBOX_LOGE("[x] [%s:%d]: can not get jni_func_hash \n", FILE, LINE);
		return;
	}

	memset(tld->jni_func_hash, 0x0, HASH_LEN * sizeof(void*));
}*/

/* given function address, check whether this function is in hash table */
bool hash_find(struct thread_local_data *tld, u4 addr) {
	TRACE_ENTER;
	int index = HASH_FUNC(addr);

	struct hash_entry ** jni_funcs_hash = tld->jni_func_hash;

	//SANDBOX_LOGI("[x] [%s:%d]: FIND jni funcs hash table address 0x%8x \n", FILE, LINE, (u4)jni_funcs_hash);
	struct hash_entry * entry = jni_funcs_hash[index];
	//SANDBOX_LOGI("[x] [%s:%d]: FIND jni funcs hash entry address 0x%8x \n", FILE, LINE, (u4)entry);

	while (entry != NULL) {
		//SANDBOX_LOGI("[x] [%s:%d]: FIND tld = 0x%x, addr = 0x%x \n", FILE, LINE, (u4)tld, addr);
		if (entry->func_address == (addr>>1)) {
			return true;
		}
		entry = entry->next;
	}
	TRACE_EXIT;
	return false;
}


static bool hash_put(u4 addr) {

  TRACE_ENTER;
	if(global_jni_func_hash == NULL){
		SANDBOX_LOGI("[x] [%s:%d]: global_jni_func_hash has not been malloced\n", FILE, LINE);
		return false;
	}
	int index = HASH_FUNC(addr);

	struct hash_entry * new_entry = (struct hash_entry *)malloc(sizeof(struct hash_entry));
	if (new_entry == NULL) {
	  SANDBOX_LOGI("[x] [%s:%d]: Malloc JNI hash entry error \n", FILE, LINE);
		return false;
	}

	//we do not care last bit address.
	new_entry->func_address = (addr>>1);

	struct hash_entry ** jni_funcs_hash = (struct hash_entry **)global_jni_func_hash;

	struct hash_entry * entry = jni_funcs_hash[index];
	jni_funcs_hash[index] = new_entry;
	new_entry->next = entry;
	
	SANDBOX_LOGI("[x] [%s:%d]: ADD jni_hash_table = 0x%x, addr = 0x%x \n", FILE, LINE, (u4)global_jni_func_hash, addr);
	return true;
}

/*bool hash_put(struct thread_local_data *tld, u4 addr) {
	int index = HASH_FUNC(addr);

	struct hash_entry * new_entry = (struct hash_entry *)malloc(sizeof(*new_entry));

	if (new_entry == NULL) {
		return false;
	}

	//we do not care last bit address.
	new_entry->func_address = (addr>>1);

	struct hash_entry ** jni_funcs_hash = tld->jni_func_hash;

	struct hash_entry * entry = jni_funcs_hash[index];

	jni_funcs_hash[index] = new_entry;
	new_entry->next = entry;
	
	SANDBOX_LOGI("[x] [%s:%d]: ADD tld = 0x%x, addr = 0x%x \n", FILE, LINE, (u4)tld, addr);

	return true;
}*/


/*
 *
 *  typedef const struct JNINativeInterface_ *JNIEnv;
 struct JNINativeInterface_ {
 void*       reserved0;
 void*       reserved1;
 void*       reserved2;
 void*       reserved3;

 jint        (*GetVersion)(JNIEnv *);

 jclass      (*DefineClass)(JNIEnv*, const char*, jobject, const jbyte*,
 jsize);
 jclass      (*FindClass)(JNIEnv*, const char*);

 xxxx
 }
 *
 */
void init_tld_jni(struct thread_local_data * tld) {
	TRACE_ENTER;
	int i = 0;
	if (global_jni_func_hash != NULL) {
		tld->jni_func_hash = global_jni_func_hash;
		return;
	}
	tld->jni_func_hash = new_hash_table();
	if(global_jni_func_hash == NULL){
		return;
	}

	JNIEnv * env = NULL;
	(*(sbox.vm))->AttachCurrentThread(sbox.vm, (JNIEnv **)&env, NULL);
	
	if (env == NULL) {
		SANDBOX_LOGE("[x] [%s:%d]: can not get JNIEnv \n", FILE, LINE);
		return;
	}

	u4 start = (u4)(*env);
	u4 size = sizeof(*(*env)) / sizeof(void *);

	SANDBOX_LOGI("[I] [%s:%d]: JNI Functions [%d]: [0x%x - 0x%x)\n", FILE, LINE,
			size, start, start + size * sizeof(void *));

	SANDBOX_LOGE( "GetVersion, 0x%8x ", (unsigned)((*env)->GetVersion));
	SANDBOX_LOGE( "DefineClass, 0x%8x ", (unsigned)((*env)->DefineClass));

	for (i = 0; i < size ; i ++) {
		u4 addr = (*(u4*)((u4*)(*env) + i));
		if (addr == 0)
			continue;
		SANDBOX_LOGI("[I] [%s:%d]: hash JNI Functions 0x%x [%d] \n", FILE, LINE, addr, i);
		hash_put(addr);
	}
	TRACE_EXIT;
}

void free_tld_jni(struct thread_local_data * tld) {
	if(global_jni_func_hash == NULL){
		return;
	}
	int i;
	struct hash_entry *tmp, *tmp1;
	struct hash_entry ** jni_func_hash = global_jni_func_hash;
	for(i = 0; i < HASH_LEN; i++){
		tmp = jni_func_hash[i];
		while(tmp){
			tmp1 = tmp->next;
			free(tmp);
			tmp = tmp1;
		}
	}
	free(global_jni_func_hash);
	global_jni_func_hash = 0;

}
/*void init_tld_jni(struct thread_local_data * tld) {
	TRACE_ENTER;
	int i = 0;
	if (tld->jni_func_hash == NULL) {
		new_hash_table(tld);
	}

	JNIEnv * env = NULL;
	(*(sbox.vm))->AttachCurrentThread(sbox.vm, (JNIEnv **)&env, NULL);
	
	if (env == NULL) {
		SANDBOX_LOGE("[x] [%s:%d]: can not get JNIEnv \n", FILE, LINE);
		return;
	}

	u4 start = (u4)(*env);
	u4 size = sizeof(*(*env)) / sizeof(void *);

	SANDBOX_LOGI("[I] [%s:%d]: JNI Functions [%d]: [0x%x - 0x%x)\n", FILE, LINE,
			size, start, start + size * sizeof(void *));

	SANDBOX_LOGE( "GetVersion, 0x%8x ", (unsigned)((*env)->GetVersion));
	SANDBOX_LOGE( "DefineClass, 0x%8x ", (unsigned)((*env)->DefineClass));

	for (i = 0; i < size ; i ++) {
		u4 addr = (*(u4*)((u4*)(*env) + i));
		if (addr == 0)
			continue;
		SANDBOX_LOGI("[I] [%s:%d]: hash JNI Functions 0x%x [%d] \n", FILE, LINE, addr, i);
		hash_put(tld, addr);
	}
	TRACE_EXIT;
}*/

//make sure tld has been created before calling this function
bool validate_jni(u4 addr) {
	TRACE_ENTER;
	struct thread_local_data * tld = get_tld();

	if (!hash_find(tld, addr)) {
		//SANDBOX_LOGI("[I] [%s:%d]: Can not find JNI Function 0x%x\n", FILE, LINE, addr);
	  TRACE_EXIT;
		return false;
	}

	//SANDBOX_LOGI("[I] [%s:%d]: find JNI Function 0x%x\n", FILE, LINE, addr);
	TRACE_EXIT;
	/* TODO: make other check */
	return true;
}
