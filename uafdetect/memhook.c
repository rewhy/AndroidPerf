#include <stdio.h>

#include "debug/debug.h"
#include "uafdetect.h"
#include "rbtree.h"

static RBTreeNode *block_root = NULL;
//static RBTreeNode *freed_block_root = NULL;
static u4 alloced_block_num = 0;

static u4 low_addr = 0;
static u4 high_addr = 0;

static void adjust_addr_edge(u4 start, u4 size) {
	if(low_addr == 0){
		low_addr = start;
		high_addr = start + size - 1;
		return;
	}
	if(low_addr > start) {
		low_addr = start;
	}
	if(high_addr < start + size - 1) {
		high_addr = start + size - 1;
	}
}

u4 addr_check(u4 addr, u4 type){
	if((addr < low_addr) || (addr > high_addr))
	{
		//UAF_LOGI("[type: 0x%2x] addr 0x%8x is not in heap memory.", type, addr);
		return 0;
	}
	RBTreeNode *node = rbSearch(&block_root, (u4)addr);
	if(node) {
		UAF_LOGI("[type: 0x%2x] addr 0x%8x is valid.", type, addr);
		return (u4)node;
	} else {
		UAF_LOGI("[type: 0x%2x] addr 0x%8x is invalid (not found in allocated heap memory).", 
				type, addr);
	}
	return 0;
}

// void* malloc(size_t size);
void* hook_malloc_sys(size_t size) {
	return hook_malloc(size);
}
void* hook_malloc(size_t size) {
	void *ptr = malloc(size);
	if(ptr) {
		rbInsertNode(&block_root, (u4)ptr, size);
		alloced_block_num++;
		adjust_addr_edge((u4)ptr, (u4)size);
		UAF_LOGE("[%d] [%s:%d] 0x%8x-0x%8x is alloced by malloc.",gettid(), FILE, LINE, (u4)ptr, (u4)ptr+size-1);
	} else {
		UAF_LOGE("[%d] [%s:%d] block alloced error.",gettid(), FILE, LINE);
	}
	return ptr;
}
//
// void* calloc(size_t num, size_t size);
void* hook_calloc_sys(size_t num, size_t size) {
	return hook_calloc_sys(num, size);
}
void* hook_calloc(size_t num, size_t size) {
	void *ptr = calloc(num, size);
	if(ptr) {
		rbInsertNode(&block_root, (u4)ptr, size*num);
		alloced_block_num++;
		adjust_addr_edge((u4)ptr, (u4)(num*size));
		UAF_LOGE("[%d] [%s:%d] 0x%8x-0x%8x is alloced by calloc.",gettid(), FILE, LINE, (u4)ptr, (u4)ptr+num*size-1);
	} else {
		UAF_LOGE("[%s:%d] block alloced error.", FILE, LINE);
	}
	return ptr;
}
//
// void* realloc(void *ptr, size_t size);
void* hook_realloc_sys(void *ptr, size_t size) {
	return hook_realloc(ptr, size);
}
void* hook_realloc(void *ptr, size_t size) {
	void *nptr = realloc(ptr, size);
	rbDeleteNode(&block_root, (u4)ptr);
	alloced_block_num--;
	if(ptr) {
		rbInsertNode(&block_root, (u4)nptr, size);
		alloced_block_num++;
		adjust_addr_edge((u4)nptr, (u4)size);
		UAF_LOGE("[%d] [%s:%d] 0x%8x-0x%8x is alloced by realloc.",gettid(), FILE, LINE, (u4)ptr, (u4)ptr+size-1);
	} else {
		UAF_LOGE("[%s:%d] block alloced error.", FILE, LINE);
	}
	return nptr;
}
//
// void free(void *ptr);
void hook_free_sys(void *ptr) {
	hook_free(ptr);
}
void hook_free(void *ptr) {
	u4 res = addr_check((u4)ptr, UAF_CHECK_ADDR_FREE);
	if(res > 0){
		free(ptr);
		rbDeleteNode(&block_root, (u4)ptr);
		UAF_LOGE("[%d] [%s:%d] 0x%8x-??? is freed.",gettid(), FILE, LINE, (u4)ptr);
		alloced_block_num--;
	}
}
