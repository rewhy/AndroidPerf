#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>


#include "utility.h"
#include "debug.h"
//#include "ba/ba.h"
//#include "sandbox.h"
//#include "asm.h"
//#include "global.h"


char pformat[256];

/*
 * It's hard to debug the translated code. This function will be called
 * by first instruction in each translated basic block. See trampoline_asm.S
 *
 */

void bt_debug_print_address(u4 address, int type) {
    if (type == 0) {
        BT_DEBUG("** jump address (original) 0x%8x", address);
    } else if (type == 1) {
        BT_DEBUG("** will execute 0x%8x", address);
    } else if (type == 2) {
        BT_DEBUG("** check mapping. found entry->src: 0x%8x", address);
    } else if (type == 3) {
        BT_DEBUG("** check mapping. found entry address : 0x%8x", address);
    } else if (type == 4) {
        BT_DEBUG("** return to trusted world : 0x%8x", address);
    } else if (type == 5) {
        BT_DEBUG("** jump to translated function (After JNI call): 0x%8x", address);
    } else if (type == 6) {
        BT_DEBUG("** call System function function : 0x%8x", address);
    } else if (type == 7) {
        BT_DEBUG("** current pc address : 0x%8x", address);
    } else if (type == 8) {
        BT_DEBUG("** return lr address : 0x%8x", address);
    } else if (type == 9) {
        BT_DEBUG("** enter stack address : 0x%8x", address);
    } else if (type == 10) {
        BT_DEBUG("** exit stack address : 0x%8x", address);
    } else if (type == 11) {
        BT_DEBUG("** return to untrusted world : 0x%8x", address);
    } else if (type == 12) {
        BT_DEBUG("** jump to untrusted(callback) world : 0x%8x", address);
    } else if (type == 13) {
        BT_DEBUG("** return to trusted(from callback) world : 0x%8x", address);
    } else if (type == 14) {
        BT_DEBUG("** unstrusted stack address : 0x%8x", address);
		}
}

void bt_debug_print_reg(u4 reg_index, u4 value, u4 pc) {
    BT_DEBUG("[0x%x]: dumped reg r%d: 0x%8x", pc, reg_index, value);
}

void bt_debug_print_pc(u4 pc) {
    BT_DEBUG("xx-executing--xx: 0x%8x", pc);
}

