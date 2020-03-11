#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>

#include "ba/ba.h"
#include "sandbox.h"
#include "debug/debug.h"

#include "bt.h"
#include "bt_code_cache.h"
#include "bt_asm_macros.h"



struct ccache_entry {
	u4 *src;
	u4 *dst;
};

void *fbt_ccache_find(struct thread_local_data *tld, void *orig_address) {
	TRACE_ENTER;
	BT_DEBUG("fbt_ccache_find(tld=0x%8x, orig_address=0x%8x)",
			(u4)tld, (u4)orig_address);

	assert(tld != NULL);

	/* calculate offset into hashtable (this instruction is our hash function) */
	u4 offset = C_MAPPING_FUNCTION_ARM((u4)orig_address);
	u4 pos = 0;
	struct ccache_entry *entry = tld->mappingtable + offset;

	/* check entry if src address equals orig_address */
	while (entry->src != 0) {
		if (orig_address == entry->src) {
			/* return corresponding dest address */
			BT_DEBUG("find: entry 0x%8x entry->dst 0x%8x", (u4)entry, (u4)entry->dst);
			assert(entry->dst != NULL);
			if (pos!=0) {
				/* not optimal entry! swap suboptimal entry! */
				void *tmp;
				struct ccache_entry *firstentry = tld->mappingtable +
					C_MAPPING_FUNCTION_ARM((u4)orig_address);
				tmp = firstentry->src;
				firstentry->src = entry->src;
				entry->src = tmp;
				tmp = firstentry->dst;
				firstentry->dst = entry->dst;
				entry->dst = tmp;
				entry = firstentry;
			}
			return entry->dst;
		}
		/* We mustn't access memory beyond the hashtable!!
		 * Bitwise AND with (HASHTABLE_SIZE - 1) is the same as
		 * modulo HASHTABLE_SIZE. */
		offset = (offset + sizeof(struct ccache_entry)) & (MAPPINGTABLE_SIZE-1);
		pos++;
		entry = tld->mappingtable + offset;
	}
	TRACE_EXIT;
	//BT_DEBUG("-> %8x", NULL);
	return NULL;
}

void fbt_ccache_add_entry(struct thread_local_data *tld, void *orig_address,
		void *transl_address) {

	/* calculate offset into hashtable that corresponds to this orig_address*/
	u4 offset = C_MAPPING_FUNCTION_ARM((u4) orig_address);
	BT_DEBUG("fbt_ccache_add_entry(tld=0x%8x, orig_address=0x%8x,transl_address=0x%8x, offset=0x%8x)", 
			(u4)tld, (u4)orig_address,	(u4)transl_address, offset);
	struct ccache_entry *entry = tld->mappingtable + offset;

	int count = 0;

	/* search the hastable for a free position, beginning at offset */
	while (entry->src != 0) {
		offset = (offset + sizeof(struct ccache_entry)) & (MAPPINGTABLE_SIZE - 1);
		entry = tld->mappingtable + offset;
		count++;
		if (count>=MAPPINGTABLE_MAXENTRIES/10) {
			BT_ERR(true,"ERROR: mappingtable out of space\n");
		}
	}

	/* insert entry into hashtable */
	entry->src = orig_address;
	entry->dst = transl_address;
	//DUMP_JMP_TABLE_ENTRY(orig_address, transl_address);
	//PRINT_DEBUG_FUNCTION_END(" ");
}
