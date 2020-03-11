#ifndef __SANDBOX_ASM_H__
#define __SANDBOX_ASM_H__

#include "arm.h"


#define IDENTIFIER(n)  n
#define HIDDEN(n)  .hidden IDENTIFIER(n)

/* most of these macros are coming from nacl */

#define DEFINE_GLOBAL_HIDDEN_IDENTIFIER(n) \
    .globl IDENTIFIER(n); HIDDEN(n); IDENTIFIER(n)


#define OFFSETOF(type, field)    ((unsigned long) &(((type *) 0)->field))


//define the offset used here
// see bt/bt.h
#define TLD_OFFSET_MAPPINGTABLE             0x0
#define TLD_OFFSET_RET_TRAMPOLINE           0x4
#define TLD_OFFSET_UNTRUSTED_STACK          0x8
#define TLD_OFFSET_TRUSTED_STACK            0x10
#define TLD_OFFSET_UNTRUSTED_FUNC           0x14
#define TLD_OFFSET_JNI_FUNC                 0x18
#define TLD_OFFSET_CALLBACK_RET_TRAMPOLINE  0x1c


//#define TLD_OFFSET_GATE_KEEPER              0x8
//#define TLD_OFFSET_IJUMP_TRAMPOLINE_ARM     0xc


#endif
