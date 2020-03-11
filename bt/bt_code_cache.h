#ifndef __SANDBOX_BT_CODE_CACHE_H__
#define __SANDBOX_BT_CODE_CACHE_H__



/* yajin: these macros may be used in assembly files for trampolines.
 *        (trampoline/xxx.S)
 *
 */

/* code cache (hash table):
 * 20 bits used as index into hash table. each hash table is 8 bytes, so the
 * total size of hash table is 8M.
 *
 *  For arm instruction, the jump target is always 4 bytes aligned. for thumb
 *  instruction, the target is 2 bytes aligned.
 *  So for ARM instruction, we use bit [2: 21] as index
 *     for thumb instruction, we use bit [1:20] as index
 */

#define MAPPINGTABLE_NRBITS 23
//1<<MAPPINGTABLE_NRBITS
#define MAPPINGTABLE_SIZE (0x800000)
//MAPPINGTABLE_SIZE>>3
#define MAPPINGTABLE_MAXENTRIES (0x100000)



#define MAPPING_PATTERN         ((MAPPINGTABLE_SIZE-1)^0x7)


/* ARM: use bit [2:21] as index. (we also need to ) */
#define MAPPING_PATTERN_ARM     (0x3ffffc)
#define C_MAPPING_FUNCTION_ARM(addr)  ((addr & MAPPING_PATTERN_ARM) << 1)

#define MAPPING_PATTERN_ARM_HIGH  (0x3f)
#define MAPPING_PATTERN_ARM_LOW  (0xfffc)


#ifndef _SANDBOX_ASSEMBLY_
//put others which doe not want to be included in assembly files here.
#endif //_SANDBOX_ASSEMBLY_



#endif
