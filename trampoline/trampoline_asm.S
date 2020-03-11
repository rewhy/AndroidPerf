#this should be the first.
#define _SANDBOX_ASSEMBLY_

#include "../asm.h"
#include "../bt/bt_code_cache.h"


#in order to call this macro, please make sure
#   (1) r0 <- original address
#   (2) r1 <- address of tld
#
# this macro will change
#   r2, r3, r4, r5
#
# the result is status register.
#
#   r4: the address of found entry in mapping table.
#

.macro check_mapping
    #check the mapping table
    #put bit [2:21] of address into r3

    #the sequence matters!!! always put movw before movt
    movw r3, #MAPPING_PATTERN_ARM_LOW
    movt r3, #MAPPING_PATTERN_ARM_HIGH

    and r3, r0, r3
    #get mapping table address into r4
    ldr r4, [r1, #TLD_OFFSET_MAPPINGTABLE]
    # get the mapping table entry. r3*2 is the real index.
    # address = table + index  = table + r3 *2
    # see C_MAPPING_FUNCTION_ARM macro in bt_code_cache.h
    #r4 -> address of hash mapping entry
    add r4, r4, r3, lsl #1

    # mask last 1 bit in r0 (because this bit is used as mode switch flag)
    bic r2, r0, #0x1

    ldr r5, [r4]
    #now r5 = entry, cmp it with r2
    cmp r5, r2
.endm


#******************  1 ********************************
#This is the entry to jump to untrusted function in sandbox.
# trusted -> untrusted
#
#  Gate keeper for JNI functions
#   When calling untrusted code from JNI interface, the libdvm
#   will first call dlsym to find the address of functions need
#   to call and then jumps to this function.
#
#   Instead of letting libdvm calls untrusted functions directly,
#   we return the address of gate_keeper to libdvm and let libdvm
#   call this gate keeper function. This gate keep function then
#   calls corresponding functions inside sandbox.
#
#   Why do not let libdvm call untrusted functions directly?
#       (1) we need to switch the stack (using the stack inside sandbox)
#       (2) we need to set up something to let trampoline code return to dalvik
#           correctly.
#           when this untrusted function call returns, we want to let it
#           go to trampoline code, not returning back directly out of sandbox
#           (which is not allowed because the code in sandbox can not go out
#           of sandbox except through trampoline code).
#
#
#
###############change this definition accordingly if you push more things into
#stack

#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif
#define TARGET_PC_OFFSET    16

.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_gate_keeper):
    .arm
    #the real return address in libdvm (returning back from JNI call)
    # already done in first stage gate keeper
    # push {lr}

    #push other things into stack.
    # already done in first stage gate keeper
    # r4 - r11
    # push {r4, r5, r6, r7, r8, r9, r10, fp, lr}

    # r4 = index of native functions (passed from first stage gate keeper)
    # see trampoline.c (function init_gate_keeper() )
		
#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, ip, lr}
    mrs  ip, cpsr
    push {ip}

    mov r0, lr
    mov r1, #8

    ldr r3, sandbox_jni_gate_keeper_debug_constant
    blx r3

    pop {ip}
    msr cpsr_nzcvq, ip
    pop {r0, r1, r2, r3, ip, lr}
#endif

		#save original arguments
    push {r0, r1, r2, r3}
    mov r0, r4
    #call lock_thread()
    ldr r5, sandbox_jni_gate_keeper_arm_constant_lock
    blx r5
    #return value is tld for current thread, mov it to r4
    mov r4, r0
    pop {r0, r1, r2, r3}
	
		str sp, [r4, #TLD_OFFSET_TRUSTED_STACK]
    ldr sp, [r4, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r0}
		str sp, [r4, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r4, #TLD_OFFSET_TRUSTED_STACK]

		mov r0, r4
		pop {r4, r5, r6, r7, r8, r9, r10, fp, lr}
		pop {lr}
   
		#store r4-r10, fp, lr
		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
    ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		mov r4, r0
		ldr r0, [sp, #40]
		str sp, [r4, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r4, #TLD_OFFSET_TRUSTED_STACK]
		
		#load ret trampoline address
    ldr r5, [r4 , #TLD_OFFSET_RET_TRAMPOLINE]

    #set lr to address of trampoline address
    mov lr, r5

    ################# now we are using untrusted stack.

    #leave one slot for real code in code cache
    add  sp, sp, #-4

    #push r0,r1,r2 into untrusted stack
    push {r0, r1, r2, r3}

    ##################  before this line, do not use r0-r3
    ################### since they are arguments to untrusted function

    # we first save cpsr to r10 since we will change the flags
    # using cmp instruction.
    ##########################DO NOT USE R10 in the following
    mrs r10, APSR

    #put the target address into r0
    ldr r0, [r4 , #TLD_OFFSET_UNTRUSTED_FUNC]

		#r1->tld address
    mov r1, r4

    #check whether it is in mapping table
    check_mapping

    # not hit, we will do translation
    BNE .gate_keeper_nothit

.gate_keeper_hit:
    #check_mapping will put r4 as the address of hit entry.
    #hit.
    #get the target address
    ldr r2, [r4, #4]

.gate_jump_to_target:

    # put the last bit of original target (determines the target mode)
    # into r2 (so that it changes the CPU mode automatically!)
    bfi r2, r0, #0, #1

    #save the target into stack
    str r2, [sp, #TARGET_PC_OFFSET]

    #before jumping to the target, we need to restore the register and status
    msr APSR_nzcvqg, r10

		pop {r0, r1, r2, r3}

    #jump to target. Because pop {pc} can not change the mode and needs 4 bytes
    #aligned. So we must endure that:
    #       (1) the mode has been changed before this line of code
    #       (2) the translated target should be 4 bytes aligned.
    #
    #  Wrong!!. POP needs the stack address is 4 bytes aligned, (that does not mean
    #    the popped value is 4 bytes aligned!!!!!)
    #
    #  According to the last bit of popped value, the mode will be changed automatically!!
    #
    pop {pc}

    #should not go to here
    SANDBOX_HALT

.gate_keeper_nothit:
    #not hit. we can function fbt_translate_noexecute_bridge to do the translation
    #here, we still use the untrusted stack.
    #TODO: Switch stack to trusted one.

    #move address of fbt_translate_noexecute_bridge into reg r2
    ldr r2, sandbox_jni_gate_keeper_arm_constant_translate

    #save r0, lr
    push {r0, lr}

    # SANDBOX_HALT

    #call function r2. (r0, r1 is the parameters)
    blx r2

    #function returns. r0 -> target address
    mov r2, r0

    #r0 <- original address on stack
    pop {r0, lr}

    b .gate_jump_to_target

    #should not go to here
    SANDBOX_HALT


# .L_thumb_ret_offset:
#     .word  .gate_keeper_return_thumb - .gate_keeper_pc_thumb - 8
# .L_arm_ret_offset:
#     .word  .gate_keeper_return_arm - .gate_keeper_pc_arm - 8
#DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_gate_keeper_arm_constant_tld):
#    #this will be patched as the address of tld
#    .word 0

DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_gate_keeper_arm_constant_lock):
   #this will be patched as the address of function lock_thread()
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_gate_keeper_arm_constant_translate):
    #this will be patched as the address of fbt_translate_noexecute_bridge
    .word 0
#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_gate_keeper_debug_constant):
    #this will be patched as the address of bt_debug_print_address
    .word 0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_gate_keeper_end):


#******************  2  ********************************
#
#  untrusted libraries can have constructor and destructor functions
#  which will be executed before dlopen() returns. (see call_constructors() in
#  linker.c ).
#
#   Before calling the constructor and destructor functions directly, we need
#   to translate these functions....
#
#
#
#

# r0 -> untrusted func addrss.
# r0 - r3 have been saved before calling this function.
.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_constructor_gate_keeper):
    .arm
    #push other things into stack.
    # r4 - r11
    push {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}

    #save original arguments
    push {r0, r1, r2, r3}
    #call lock_thread_1()
    ldr r5, sandbox_constructor_gate_keeper_arm_constant_lock
    blx r5
    #return value is tld for current thread, mov it to r4
    mov r4, r0
    pop {r0, r1, r2, r3}

    #save untrusted function call
    str r0, [r4, #TLD_OFFSET_UNTRUSTED_FUNC]
		
		str sp, [r4, #TLD_OFFSET_TRUSTED_STACK]
    ldr sp, [r4, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r0}
		str sp, [r4, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r4, #TLD_OFFSET_TRUSTED_STACK]

		mov r0, r4
		pop {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
    
		#store r4-r10, fp, lr
    str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
    ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		mov r4, r0
		ldr r0, [sp, #40]
		str sp, [r4, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r4, #TLD_OFFSET_TRUSTED_STACK]

		#load ret trampoline address
    ldr r5, [r4 , #TLD_OFFSET_RET_TRAMPOLINE]

    #set lr to address of ret trampoline address
    mov lr, r5


    ################# now we are using untrusted stack.

    #leave one slot for real code in code cache
    add  sp, sp, #-4

    #push r0,r1,r2 into trusted stack (may be not necessary)
    push {r0, r1, r2, r3}

    ##################  before this line, do not use r0-r3
    ################### since they are arguments to untrusted function

    # we first save cpsr to r10 since we will change the flags
    # using cmp instruction.
    ##########################DO NOT USE R10 in the following
    mrs r10, APSR

    #put the target address into r0
    ldr r0, [r4 , #TLD_OFFSET_UNTRUSTED_FUNC]

    mov r1, r4

    #check whether it is in mapping table
    check_mapping

    # not hit, we will do translation
    BNE .constructor_gate_keeper_nothit

.constructor_gate_keeper_hit:
    #check_mapping will put r4 as the address of hit entry.
    #hit.
    #get the target address
    ldr r2, [r4, #4]

.constructor_gate_jump_to_target:

    # put the last bit of original target (determines the target mode)
    # into r2 (so that it changes the CPU mode automatically!)
    bfi r2, r0, #0, #1

    #save the target into stack
    str r2, [sp, #TARGET_PC_OFFSET]


    #before jumping to the target, we need to restore the register and status
    msr APSR_nzcvqg, r10
    pop {r0, r1, r2, r3}

    #jump to target. Because pop {pc} can not change the mode and needs 4 bytes
    #aligned. So we must endure that:
    #       (1) the mode has been changed before this line of code
    #       (2) the translated target should be 4 bytes aligned.
    #
    #  Wrong!!. POP needs the stack address is 4 bytes aligned, (that does not mean
    #    the popped value is 4 bytes aligned!!!!!)
    #
    #  According to the last bit of popped value, the mode will be changed automatically!!
    #
    pop {pc}

    #should not go to here
    SANDBOX_HALT

.constructor_gate_keeper_nothit:
    #not hit. we can function fbt_translate_noexecute_bridge to do the translation
    #here, we still use the untrusted stack.
    #TODO: Switch stack to trusted one.

    #move address of fbt_translate_noexecute_bridge into reg r2
    ldr r2, sandbox_constructor_gate_keeper_arm_constant_translate

    #save r0, lr
    push {r0, lr}

    # SANDBOX_HALT

    #call function r2. (r0, r1 is the parameters)
    blx r2

    #function returns. r0 -> target address
    mov r2, r0

    #r0 <- original address on stack
    pop {r0, lr}

    b .constructor_gate_jump_to_target

    #should not go to here
    SANDBOX_HALT

DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_constructor_gate_keeper_arm_constant_lock):
   #this will be patched as the address of function lock_thread_1()
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_constructor_gate_keeper_arm_constant_translate):
    #this will be patched as the address of fbt_translate_noexecute_bridge
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_constructor_gate_keeper_end):




#******************  3  ********************************

# This is the indirect jump trampoline. translated code will call this trampoline
#  to lookup indirect jump
#
# When entering this trampoline
#   r0: the target address (in original code)
#   r1: xxxx (the address of tld will be calculated by calling get_tld())
#   r2: the address of ijump trampoline
#
# stack (entering this trampoline):
# high:
#         |slot for pc in code cache
#         |saved r2
#         |saved r1
#         |saved r0
#
#
#
# ***do not change the value of r0,r1 since they may be used as arguments to function xx
# ***do not change the value of r10, since it holds the original value of APSR
#
#

#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#only count the registers pushed in this function
#define TARGET_PC_OFFSET   16

#the ijump trampoline for arm mode.
.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ijump_trampoline_arm):
		.arm
    push {r3, r4, r5, r10}

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    # mov r0, r2
    mov r1, #0

    ldr r3, sandbox_ijump_trampoline_debug_constant
    blx r3

    pop {r0, r1, r2, r3, lr}
#endif

    #put r3 (ret_reg_offset) into reg r10
    mov r10, r3
    #please do not touch r10 in the following!!!

    #get the address of tld and put into r1
    #save original parameters (r3 has been put into r10, r1: we do not care)
    push {r0, r2, lr}

    #call function to get tld
    ldr r5, sandbox_ijump_trampoline_arm_constant_get_tld
    #call get_tld()

    blx r5
    mov r1, r0

    #restore original parameters
    pop {r0, r2, lr}

    #check whether it is in mapping table
    check_mapping

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, ip, lr}
    mrs  ip, cpsr
    push {ip}

    mov r0, r5
    mov r1, #2

    ldr r3, sandbox_ijump_trampoline_debug_constant
    blx r3

    mov r0, r4
    mov r1, #3

    ldr r3, sandbox_ijump_trampoline_debug_constant
    blx r3

    pop {ip}
    msr cpsr_nzcvq, ip
    pop {r0, r1, r2, r3, ip, lr}
#endif

    #debug
    # mov pc, #0

    # not hit, we will do translation
    BNE .ijump_trampoline_nothit

.ijump_trampoline_hit:
    #check_mapping will put r4 as the address of hit entry.
    #hit.
    #get the target address
    ldr r2, [r4, #4]

.ijump_trampoline_jump_to_target:

    # put the last bit of original target (determines the target mode)
    # into r2 (so that it changes the CPU mode automatically!)
    # fbt_translate_noexecute_bridge has set this bit

		bfi r2, r0, #0, #1

    #save the target into stack. position: TARGET_PC_OFFSET + ret_reg_offset
    # ret_reg_offset is in (r10)
    add r10, r10, #TARGET_PC_OFFSET
    str r2, [sp, r10]

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    mov r0, r2
    mov r1, #1

    ldr r3, sandbox_ijump_trampoline_debug_constant
    blx r3

    pop {r0, r1, r2, r3, lr}
#endif

    #before jumping to the target, we need to restore the register
    pop {r3, r4, r5, r10}

    #debug
    # mov pc, #0

    #return to jump code
    bx lr

    #should not go to here
    SANDBOX_HALT

.ijump_trampoline_nothit:
    #not hit. we can function fbt_translate_noexecute_bridge to do the translation

    #here, we still use the untrusted stack.
    #TODO: Switch stack to trusted one.

    #move address of fbt_translate_noexecute into reg r2
    ldr r2, sandbox_ijump_trampoline_arm_constant

    #save r0, lr
    push {r0, lr}

    #debug
    # mov pc, #0

    # SANDBOX_HALT

    #call function r2. (r0, r1 is the parameters)
    blx r2

    #function returns. r0 = target address.  r2 <- r0
    mov r2, r0

    #r0,lr <- saved (original address, lr) on stack
    pop {r0, lr}

    b .ijump_trampoline_jump_to_target

    #should not go to here
    SANDBOX_HALT

#make sure this is 4 bytes aligned!!!
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ijump_trampoline_arm_constant_get_tld):
    #this will be patched as the address of get_tld
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ijump_trampoline_arm_constant):
    #this will be patched as the address of fbt_translate_noexecute_bridge
    .word 0
#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ijump_trampoline_debug_constant):
    #this will be patched as the address of bt_debug_print_address
    .word 0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ijump_trampoline_arm_end):






#******************  4  ***************************
#
# The trampoline for returning back to trusted code.
#
# After finishing the function calls in untrusted code, we need to return back
# to libdvm. However we can just directly jump back since the code in sandbox
# can not jump to target out of sandbox. So we first jump to trampoline and
# the trampoline will restore the context of trusted world and then jump to
# libdvm. (see sandbox_gate_keeper in gkeeper_arm.S)
#
#
#
# This trampoline is the only address that untrusted code is allowed to jump
# out of code sandbox.
#
.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ret_trampoline):
		.arm
    push {r0, r1, r2, r3}

    ldr r5, sandbox_ret_trampoline_constant_unlock
    #call unlock_thread()
    blx r5

		#restore r4-r10, rp, lr
		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
    pop {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		add sp, sp, #4
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		
    pop {r0, r1, r2, r3}
		
		push {lr}
    #debug
    # mov r0, #0
    # ldr r0, [r0]

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    ldr r0, [sp, #20]
    mov r1, #4
    ldr r3, sandbox_ret_trampoline_constant_debug
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

    #now sp +0 -> real address needs to return
    pop {pc}

    #should not go to here
    SANDBOX_HALT

#DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ret_trampoline_constant):
#    #this will be patched as address of tld
#    .word   0

#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ret_trampoline_constant_debug):
#    #this will be patched as address of function bt_debug_print_address
   .word   0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ret_trampoline_constant_unlock):
#    #this will be patched as address of function unlock_thread()
   .word   0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_ret_trampoline_end):






#******************  5  ***************************
#
# JNI call trampoline.
#   When native code uses (*env)->JNIfunctions to call a JNI function
#   provided by dalvik, we can not just jump to this JNI function (in trusted
#    world).
#
#
# jstring Java_org_yajin_nativecontainer_MainActivity_string1(JNIEnv* env,
#                                                        jobject thiz,
#                                                        jstring name) {
#
#    const char *str= (*env)->GetStringUTFChars(env,name,0);
#    SANDBOX_LOGE( "string from java %s ", str);
#    xxxx
#}
#
#00001014 <Java_org_yajin_nativecontainer_MainActivity_string1>:
#    1014:   e92d4800    push    {fp, lr}
#    1018:   e28db004    add fp, sp, #4  ; 0x4
#    101c:   e24dd018    sub sp, sp, #24 ; 0x18
#    1020:   e50b0010    str r0, [fp, #-16]
#    1024:   e50b1014    str r1, [fp, #-20]
#    1028:   e50b2018    str r2, [fp, #-24]
#    102c:   e51b3010    ldr r3, [fp, #-16]
#    1030:   e5933000    ldr r3, [r3]
#    1034:   e59332a4    ldr r3, [r3, #676]
#    1038:   e51b0010    ldr r0, [fp, #-16]
#    103c:   e51b1018    ldr r1, [fp, #-24]
#    1040:   e3a02000    mov r2, #0  ; 0x0
#    1044:   e12fff33    blx r3   -> call (*env)->GetStringUTFChars(env,name,0)
#
#
# translated code for blx r3
#
#I/sandbox (24471): [DIS] 79100030 e301e048 movw<al>  lr, #0x1048
#I/sandbox (24471): [DIS] 79100034 e346ef00 movt<al>  lr, #0x6f00
#I/sandbox (24471): [DIS] 79100038 e24dd004 sub<al>   sp, sp, 0x4
#I/sandbox (24471): [DIS] 7910003c e92d5000 stmdb<al> sp !,,{ip, lr, }
#I/sandbox (24471): [DIS] 79100040 e10fc000 mrs<al>   ip, <spec>
#I/sandbox (24471): [DIS] 79100044 e52dc004 str<al>   ip, [sp - 0x4]
#I/sandbox (24471): [DIS] 79100048 e92d000f stmdb<al> sp !,,{r0, r1, r2, r3, }
#I/sandbox (24471): [DIS] 7910004c e1a00003 mov<al>   r0, r3
#I/sandbox (24471): [DIS] 79100050 e3031000 movw<al>  r1, #0x3000
#I/sandbox (24471): [DIS] 79100054 e3441d46 movt<al>  r1, #0x4d46
#I/sandbox (24471): [DIS] 79100058 e591200c ldr<al>   r2, [r1 + 0xc]
#I/sandbox (24471): [DIS] 7910005c e300301c movw<al>  r3, #0x1c
#I/sandbox (24471): [DIS] 79100060 e12fff32 blx<al>   r2    ->call sandbox_ijump_trampoline_arm
#                                                              when this function returns,
#                                                              the address of JNI function is on stack.
#
#I/sandbox (24471): [DIS] 79100064 e8bd000f ldmia<al> sp !,,{r0, r1, r2, r3, }
#I/sandbox (24471): [DIS] 79100068 e49dc004 ldr<al>   ip, [sp + 0x4]
#I/sandbox (24471): [DIS] 7910006c e128f00c msr<al>   <spec>, ip
#I/sandbox (24471): [DIS] 79100070 e8bd5000 ldmia<al> sp !,,{ip, lr, }
#I/sandbox (24471): [DIS] 79100074 e49df004 ldr<al>   pc, [sp + 0x4]    -> get address from stack and then jump to this function
#                                                                          (call (*env)->GetStringUTFChars(env,name,0) )
#                                                                          ( lr = 0x6f001048(original lr) )
#
#
# So when function (*env)->GetStringUTFChars(env,name,0) returns (bx lr), it will jump to 0x6f001048 (untrusted code)
# directly, which is not allowed (each instruction in untrusted code needs to be translated in order to execute)
#
#
# Solution: for JNI calls, we can not return the address of JNI function directly, Instead,
#            we return jni trampoline.
#

#
#
#  When entering this function, we still use the untrusted stack.
#
#  TODO: In order to prevent untrusted native library from passing invalid
#        parameters into JNI functions, we need to check JNi here.
#        (see paper Robusta)
#

#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#define TARGET_PC_OFFSET 40
.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline):
		.arm
    #store original parameters
		push {r0, r1, r2, r3}
		push {r5, lr}
		
		#call function to get tld
		ldr r5, sandbox_jni_trampoline_constant_get_tld
		#call get_tld()
		blx r5

		pop {r5, lr}
    
		#store r4-r7, r10, lr into untrusted stack
		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r4, r5, r6, r7, r10, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		#r4->tld address
		mov r4, r0

		#restore original parameters
    pop {r0, r1, r2, r3}
	
    #get JNI function address
    ldr r5, [r4, #TLD_OFFSET_JNI_FUNC]
    
#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    mov r0, r5
    mov r1, #6
    ldr r3, sandbox_jni_trampoline_constant_debug
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

    #call JNI function (out of sandbox now)
    blx r5

		#leave one slot for real code in code cache
		sub sp, sp, #4

		#store r0-r3 in trusted stack	
		push {r0, r1, r2, r3}
		
		#now r0-> address of tld
		mov r0, r4

		#restore r4-r7, r10, lr
		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		#restore r4, r5, r7, r10, lr from untrusted stack
		pop {r4, r5, r6, r7, r10, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		#store r4-r7, r10, lr into trusted stack
		push {r4, r5, r6, r7, r10, lr}
		
		mov r4, r0

		mrs r10, APSR
		
		mov r7, lr

    #store target address into r0
		mov r0, lr 
    #store tld address into r1
		mov r1, r4 
	
		ldr r5, sandbox_jni_trampoline_constant_translate
		blx r5
    
		bfi r0, r7, #0, #1
		str r0, [sp, #TARGET_PC_OFFSET]

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    # ldr r0, [sp, #20]
    mov r1, #5
    ldr r3, sandbox_jni_trampoline_constant_debug
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

		msr APSR_nzcvqg, r10

		#restore r1-r7, r10, lr
		pop {r4, r5, r6, r7, r10, lr}
		
		#restore r0-r3
		pop {r0, r1, r2, r3}

		#jump to the target address
		pop {pc}

		SANDBOX_HALT

#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_constant_debug):
#    #this will be patched as address of function bt_debug_print_address
    .word   0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_constant_get_tld):
#    #this will be patched as address of function get_tld()
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_constant_translate):
    #this will be patched as the address of fbt_translate_noexecute_bridge
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_end):


#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#only count the registers pushed in this function
# (pushed r4,r5,r6,r7,r10, lr,  r0-r3)
#define TARGET_PC_OFFSET   40
.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_thumb):
    .thumb
    .syntax unified

    #save original parameters
    push {r0, r1, r2, r3}
		push {r5, lr}

.balign 4
.LDEBUG.PC0:
    #call function to get tld
    ldr r5, [pc, #(sandbox_jni_trampoline_thumb_constant_get_tld - .LDEBUG.PC0 - 4)]
		#call get_tld()
    blx r5

		pop {r5, lr}

    #save r4-7, r10, lr into untrusted(tmp) stack
		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r4, r5, r6, r7, r10, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		mov r4, r0
    #now r4 -> address of tld

    #before calling JNI functions, restore original parameters
    pop {r0, r1, r2, r3}

		#get JNI function address
    ldr r5, [r4, #TLD_OFFSET_JNI_FUNC]

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    mov r0, r5
    mov r1, #6
.balign 4
.LDEBUG.PC1:
    ldr r3, [pc, #(sandbox_jni_trampoline_thumb_constant_debug - .LDEBUG.PC1 - 4)]
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

		#call JNI function (out of sandbox now)
    blx r5
    #JNI function returns

    #reserve a slot to store the address of translated function
		sub sp, sp, #4

		push {r0, r1, r2, r3}

		mov r0, r4

		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		pop {r4, r5, r6, r7, r10, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		
		#store r0-r7, r10, lr into trusted stack
		push {r4, r5, r6, r7, r10, lr}

		mov r4, r0
    #now lr points to the target into original untrusted lib
    #goes into untrusted world again
    #
    # similar to  gate keeper

    #save flags to r10 (DO NOT USE R10 in the following)
    mrs r10, APSR

    #r7 = target address (original address)
    mov r7, lr

    #prepare parameters to call fbt_translate_noexecute_bridge
    #r0 -> target address
    mov r0, lr

    #r1 = tld
    mov r1, r4

.balign 4
.LDEBUG.PC2:
    #call fbt_translate_noexecute_bridge
    ldr r5, [pc, #(sandbox_jni_trampoline_thumb_constant_translate - .LDEBUG.PC2 - 4)]

    #debug
    # mov r9, #0
    # ldr r9, [r9]

    blx r5
    #now r0 = translated function

    # put the last bit of original target (determines the target mode)
    # into r0 (so that it changes the CPU mode automatically!)
    bfi r0, r7, #0, #1

    #save the target into stack
    str r0, [sp, #TARGET_PC_OFFSET]

#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    # ldr r0, [sp, #20]
    mov r1, #5
.balign 4
.LDEBUG.PC3:
    ldr r3, [pc, #(sandbox_jni_trampoline_thumb_constant_debug - .LDEBUG.PC3 - 4)]
    blx r3

    pop {r0, r1, r2,r3, lr}
#endif

    #before jumping to the target, we need to restore the register and status
    msr APSR_nzcvqg, r10

		#restore r0-r7, r10, lr
    pop {r4, r5, r6, r7, r10, lr}
    pop {r0, r1, r2, r3}

    # #debug
    # mov r4, #0
    # ldr r4, [r4]

		#jump to translated function
    pop {pc}

    #should not go to here
    SANDBOX_HALT_THUMB

.balign 4
#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_thumb_constant_debug):
#    #this will be patched as address of function bt_debug_print_address
	.word   0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_thumb_constant_translate):
    #this will be patched as the address of fbt_translate_noexecute_bridge
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_thumb_constant_get_tld):
#    #this will be patched as address of function get_tld()
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_jni_trampoline_thumb_end):




/**************************************6*********************************************/

#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#define TARGET_PC_OFFSET		16

.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline):
		.arm

		push {r0, r1, r2, r3}
		push {lr}

		#ldr r3, sandbox_callback_trampoline_constant_lock
		ldr r3, sandbox_callback_trampoline_constant_get_tld
		blx r3
		
		pop {lr}

		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		mrs r10, APSR

		mov r4, r0
		
		ldr r5, [r4, #TLD_OFFSET_CALLBACK_RET_TRAMPOLINE]

		mov lr, r5
	
		#load orignal callback func address
		ldr r0, [sp, #TARGET_PC_OFFSET]
		
		mov r1, r4
		#check whether it is in mapping table
		check_mapping

		BNE .callback_trampoline_nothit

.callback_trampoline_hit:
		ldr r2, [r4, #4]

.callback_trampoline_jump_to_target:

		bfi r2, r0, #0, #1

		str r2, [sp, #TARGET_PC_OFFSET]	
	
#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    mov r0, r2
    mov r1, #12
    ldr r3, sandbox_callback_trampoline_constant_debug
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

		msr APSR_nzcvqg, r10

		pop {r0, r1, r2, r3}

		pop {pc}

		SANDBOX_HALT

.callback_trampoline_nothit:

		push {r0, lr}

		ldr r2, sandbox_callback_trampoline_constant_translate
		blx r2
		mov r2, r0

		pop {r0, lr}
		
		b .callback_trampoline_jump_to_target

		SANDBOX_HALT

#make sure this is 4 bytes aligned!!!
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_constant_get_tld):
    #this will be patched as the address of get_tld
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_constant_lock):
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_constant_translate):
    #this will be patched as the address of fbt_translate_noexecute_bridge
    .word 0
#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_constant_debug):
    #this will be patched as the address of bt_debug_print_address
    .word 0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_end):

	
/**************************************7*********************************************/

#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#define TARGET_PC_OFFSET		16

.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline):
		.arm
		push {r0, r1, r2, r3}

		#ldr r5, sandbox_callback_ret_trampoline_constant_unlock
		ldr r5, sandbox_callback_ret_trampoline_constant_get_tld
		blx r5

		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		pop {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		pop {r0, r1, r2, r3}
		
		push {lr}

#ifdef DEBUG_BT_RUNTIME
    push {r0, r1, r2, r3, lr}
    mov r0, lr
		mov r1, #13
    ldr r3, sandbox_callback_ret_trampoline_constant_debug
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

		pop {pc}

		SANDBOX_HALT

DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_constant_get_tld):
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_constant_unlock):
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_constant_debug):
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_end):

/***************************************8********************************************/


#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#define TARGET_PC_OFFSET		16

.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_thumb):
    .thumb
    .syntax unified

		push {r0, r1, r2, r3}
		push {lr}

.balign 4
.L.PC1:
		#ldr r3, sandbox_callback_trampoline_constant_lock
		ldr r3, [pc, #(sandbox_callback_trampoline_thumb_constant_get_tld - .L.PC1 - 4)]
		blx r3
		
		pop {lr}

		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		push {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		mrs r10, APSR

		mov r4, r0
		
#ldr r5, [r4, #TLD_OFFSET_CALLBACK_RET_TRAMPOLINE]
.balign 4
.L.PC6:
		ldr r5, [pc, #(sandbox_callback_ret_trampoline_thumb - .L.PC6 - 4)]

		mov lr, r5
	
		#load orignal callback func address
		ldr r0, [sp, #TARGET_PC_OFFSET]
		
		mov r1, r4
		#check whether it is in mapping table
		check_mapping

		BNE .callback_trampoline_thumb_nothit

.callback_trampoline_thumb_hit:
		ldr r2, [r4, #4]

.callback_trampoline_thumb_jump_to_target:

		bfi r2, r0, #0, #1

		str r2, [sp, #TARGET_PC_OFFSET]	
	
#ifdef DEBUG_BT_RUNTIME
    #call debug function
    push {r0, r1, r2, r3, lr}
    mov r0, r2
    mov r1, #12
.balign 4
.L.PC2:
    ldr r3, [pc, #(sandbox_callback_trampoline_thumb_constant_debug - .L.PC2 - 4)]
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

		msr APSR_nzcvqg, r10

		pop {r0, r1, r2, r3}

		pop {pc}

    SANDBOX_HALT_THUMB

.callback_trampoline_thumb_nothit:

		push {r0, lr}

.balign 4
.L.PC3:
		ldr r2, [pc, #(sandbox_callback_trampoline_thumb_constant_translate - .L.PC3 - 4)]
		blx r2
		
		mov r2, r0

		pop {r0, lr}
		
		b .callback_trampoline_thumb_jump_to_target

    SANDBOX_HALT_THUMB

#make sure this is 4 bytes aligned!!!
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_thumb_constant_get_tld):
    #this will be patched as the address of get_tld
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_thumb_constant_lock):
    .word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_thumb_constant_translate):
    #this will be patched as the address of fbt_translate_noexecute_bridge
    .word 0
#ifdef DEBUG_BT_RUNTIME
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_thumb_constant_debug):
    #this will be patched as the address of bt_debug_print_address
    .word 0
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_trampoline_thumb_end):



/***************************************9********************************************/

#ifdef TARGET_PC_OFFSET
#undef TARGET_PC_OFFSET
#endif

#define TARGET_PC_OFFSET		16

.text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_thumb):
		.arm
		push {r0, r1, r2, r3}

.balign 4
.L.PC4:
		#ldr r5, sandbox_callback_ret_trampoline_constant_unlock
		ldr r5, [pc, #(sandbox_callback_ret_trampoline_thumb_constant_get_tld - .L.PC4 - 4)]
		blx r5

		str sp, [r0, #TLD_OFFSET_TRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		pop {r4, r5, r6, r7, r8, r9, r10, fp, ip, lr}
		str sp, [r0, #TLD_OFFSET_UNTRUSTED_STACK]
		ldr sp, [r0, #TLD_OFFSET_TRUSTED_STACK]

		pop {r0, r1, r2, r3}
		
		push {lr}

#ifdef DEBUG_BT_RUNTIME
    push {r0, r1, r2, r3, lr}
    mov r0, lr
.balign 4
.L.PC5:
		mov r1, #13
    ldr r3, [pc, #(sandbox_callback_ret_trampoline_thumb_constant_debug - .L.PC5 - 4)]
    blx r3
    pop {r0, r1, r2, r3, lr}
#endif

		pop {pc}

		SANDBOX_HALT

DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_thumb_constant_get_tld):
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_thumb_constant_unlock):
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_thumb_constant_debug):
	.word 0
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(sandbox_callback_ret_trampoline_thumb_end):
