#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utility.h"
#include "types.h"
#include "sandbox.h"
#include "global.h"
#include "arm.h"


/* Some data are per-thread, we need to create tld structure when entering
 * a new thread and maintain a mapping between tld and thread id.
 *
 */

#define MAX_THREADS    32

struct tld_mapping {
	pid_t tid;
	struct thread_local_data * tld;
};

struct tld_mapping tld_mapping[MAX_THREADS];
int mapping_top = 1;

/* tid -> tld*/
static struct thread_local_data * get_tld_internal() {
	TRACE_ENTER;
	int i = 0;

	pid_t tid = gettid();

	for (i = 0; i < mapping_top; i++) {
		if (tld_mapping[i].tid == tid) {
			TRACE_EXIT;
			return tld_mapping[i].tld;
		}
	}

	//can not find. create a new tld

	struct thread_local_data *new_tld = fbt_init_tls();

	tld_mapping[mapping_top].tid = tid;
	tld_mapping[mapping_top].tld = new_tld;

	mapping_top ++;

	if (mapping_top >MAX_THREADS) {
		SANDBOX_LOGI("[x] [%d] [%s:%d]: too many threads: %d. Max allowed: %d \n",
				gettid(), FILE, LINE, mapping_top, MAX_THREADS);
		return NULL;
	}
	TRACE_EXIT;
	return new_tld;
}

/* the lock to lock the translation of current thread */
pthread_mutex_t translation_mutex = PTHREAD_MUTEX_INITIALIZER;

/* lock current thread and return tld  */
struct thread_local_data * lock_thread(int index) {
	//get value of lr register
	TRACE_ENTER;
	pthread_mutex_lock(&translation_mutex);

	// pid_t tid = gettid();

	/*SANDBOX_LOGI("[x] [%d] [%s:%d]: into lock_thread. func index %d \n",
			tid, FILE, LINE, index);*/
	struct thread_local_data * tld = get_tld_internal();

	//if (tld->untrusted_func_addr == 0) {
	tld->untrusted_func_addr = get_native_func(index);
	//}

	if (tld -> jni_func_hash == NULL) {
		init_tld_jni(tld);
	}

	/*SANDBOX_LOGI("[x] [%d] [%s:%d]: return tld: 0x%x, untrusted stack  0x%x\n",
			tid, FILE, LINE, (u4)tld, tld->ut_stack);*/
	TRACE_EXIT;
	return tld;
}

//called by sandbox_constructor_gate_keeper
struct thread_local_data * lock_thread_1() {
	//get value of lr register
	TRACE_ENTER;
	pthread_mutex_lock(&translation_mutex);

	pid_t tid = gettid();

	SANDBOX_LOGI("[x] [%d] [%s:%d]: into lock_thread_1.  \n", tid, FILE, LINE);

	struct thread_local_data * tld = get_tld_internal();

	// tld->untrusted_func_addr = get_native_func(index);

	if (tld -> jni_func_hash == NULL) {
		init_tld_jni(tld);
	}

	SANDBOX_LOGI("[x] [%d] [%s:%d]: return tld: 0x%x, untrusted stack  0x%x\n",
			tid, FILE, LINE, (u4)tld, tld->ut_stack);

	TRACE_EXIT;
	return tld;
}


struct thread_local_data * unlock_thread() {

	//pid_t tid = gettid();

	struct thread_local_data * tld = get_tld_internal();

	//SANDBOX_LOGI("[x] [%d] [%s:%d]: return tld: 0x%x \n", tid, FILE, LINE, (u4)tld);

	pthread_mutex_unlock(&translation_mutex);
	return tld;
}


struct thread_local_data * get_tld() {
	TRACE_ENTER;
	pid_t tid = gettid();
	//SANDBOX_LOGI("[x] [%d] [%s:%d]: into get_tld\n", tid, FILE, LINE);

	struct thread_local_data * tld = get_tld_internal();

	if(tld == NULL){
		SANDBOX_LOGI("[x] [%d] [%s:%d]: Get tld error \n", tid, FILE, LINE);
		return NULL;
	}
	if (tld -> jni_func_hash == NULL) {
		init_tld_jni(tld);
	}

	//SANDBOX_LOGI("[x] [%d] [%s:%d]: return tld: 0x%x stack 0x%x \n", tid, FILE, LINE, (u4)tld, (u4)tld->t_stack);
	TRACE_EXIT;
	return tld;
}

