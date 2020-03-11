#include <stdio.h>

#include "rbtree.h"
#include "uafdetect.h"

#define HOOK_FUNC_NUM	4

static struct hookfuncpair *hook_func = NULL;

u4 is_hook_needed(u4 addr) {
	//switch(addr
	int i;
	for(i = 0; i < HOOK_FUNC_NUM; i++){
		if(hook_func[i].org_addr == addr){
			UAF_LOGI("replace address 0x%8x with 0x%8x", addr, hook_func[i].hook_addr);
			return hook_func[i].hook_addr & ~0x1;
		}
	}
	return 0;
}

int uafdetect_init() {
	u4 sym_ret = 0;
	/*soinfo *si = find_library("/system/lib/libc.so");
	if(si == NULL){
		UAF_LOGI("[%d] [%s:%d] Failed to find library",gettid(), FILE, LINE);
		return 0;
	} else {
		UAF_LOGI("[%d] [%s:%d] finded library %s",gettid(), FILE, LINE, si->name);
	}*/
	
	hook_func = (struct hookfuncpair *)calloc(4, sizeof(struct hookfuncpair));
	//sym_ret = (u4)dlsym((void *)si, "malloc");
	sym_ret = (u4)malloc;
	if(sym_ret > 0){
		hook_func[0].org_addr = sym_ret;
		if(sym_ret & 0x1){
			hook_func[0].hook_addr = (u4)hook_malloc;
		} else
		{
			hook_func[0].hook_addr = (u4)hook_malloc_arm;
		}
		UAF_LOGI("malloc 0x%8x will be replaced by hook 0x%8x",
				hook_func[0].org_addr, hook_func[0].hook_addr);
	} 
	else {
		UAF_LOGI("get address of malloc error.");
	}
	//sym_ret = (u4)dlsym((void *)si, "calloc");
	sym_ret = (u4)calloc;
	if(sym_ret > 0){
		hook_func[1].org_addr = sym_ret;
		if(sym_ret & 0x1) {
			hook_func[1].hook_addr = (u4)hook_calloc;
		} else {
			hook_func[1].hook_addr = (u4)hook_calloc_arm;
		}
		UAF_LOGI("calloc 0x%8x will be replaced by hook 0x%8x",
				hook_func[1].org_addr, hook_func[1].hook_addr);
	}
	else {
		UAF_LOGI("get address of calloc error.");
	}
	//sym_ret = (u4)dlsym((void *)si, "realloc");
	sym_ret = (u4)realloc;
	if(sym_ret > 0){
		hook_func[2].org_addr = sym_ret;
		if(sym_ret & 0x1) {
			hook_func[2].hook_addr = (u4)hook_realloc;
		} else {
			hook_func[2].hook_addr = (u4)hook_realloc_arm;
		}
		UAF_LOGI("realloc 0x%8x will be replaced by hook 0x%8x",
				hook_func[2].org_addr, hook_func[2].hook_addr);
	}
	else {
		UAF_LOGI("get address of realloc error.");
	}
	//sym_ret = (u4)dlsym((void *)si, "free");
	sym_ret = (u4)free;
	if(sym_ret > 0){
		hook_func[3].org_addr = sym_ret;
		if(sym_ret & 0x1) {
			hook_func[3].hook_addr = (u4)hook_free;
		} else {
			hook_func[3].hook_addr = (u4)hook_free_arm;
		}
		UAF_LOGI("free 0x%8x will be replaced by hook 0x%8x",
				hook_func[3].org_addr, hook_func[3].hook_addr);
	}
	else {
		UAF_LOGI("get address of free error.");
	}
	return 1;
}

/*u4 get_hook_addr(const char *name){
	if(strcmp(name, "malloc") == 0){
		UAF_LOGI("[%d] [%s:%d] hook malloc using 0x%8x.",gettid(), FILE, LINE, (u4)hook_malloc);
		return (u4)hook_malloc;
	} else if(strcmp(name, "calloc") == 0){
		UAF_LOGI("[%d] [%s:%d] hook calloc using 0x%8x.",gettid(), FILE, LINE, (u4)hook_calloc);
		return (u4)hook_calloc;
	} else if(strcmp(name, "realloc") == 0){
		UAF_LOGI("[%d] [%s:%d] hook realloc using 0x%8x.",gettid(), FILE, LINE, (u4)hook_realloc);
		return (u4)hook_realloc;
	} else if(strcmp(name, "free") == 0){
		UAF_LOGI("[%d] [%s:%d] hook free using 0x%8x.",gettid(), FILE, LINE, (u4)hook_free);
		return (u4)hook_free;
	}
	return 0;
}*/
