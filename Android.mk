LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

#compile to arm instead of thumb
LOCAL_ARM_MODE := arm

LOCAL_MODULE    := profiler

LOCAL_SRC_FILES := profiler.c utility.c wrapper.c sandbox.c
LOCAL_SRC_FILES += thread/jni.c thread/thread.c
LOCAL_SRC_FILES += linker/linker.c linker/dlfcn.c
LOCAL_SRC_FILES += ba/ba.c
LOCAL_SRC_FILES += bt/bt.c bt/bt_translate.c bt/bt_mem_mgt.c bt/bt_code_cache.c
LOCAL_SRC_FILES += bt/bt_dis_thumb.c bt/bt_translate_thumb.c 
LOCAL_SRC_FILES += bt/bt_dis_arm.c bt/bt_translate_arm.c
LOCAL_SRC_FILES += trampoline/trampoline.c trampoline/trampoline_asm.S

LOCAL_SRC_FILES += darm/darm.c darm/darm-tbl.c
LOCAL_SRC_FILES += darm/armv7.c darm/armv7-tbl.c            
LOCAL_SRC_FILES += darm/thumb.c darm/thumb-tbl.c
LOCAL_SRC_FILES += darm/thumb2.c darm/thumb2-decoder.c darm/thumb2-tbl.c

LOCAL_SRC_FILES += uafdetect/rbtree.c uafdetect/memhook.c
LOCAL_SRC_FILES += uafdetect/memhook_arm.c.arm uafdetect/uafdetect.c

LOCAL_SRC_FILES += debug/debug.c  debug/bdb.c
#LOCAL_SRC_FILES += log/log.c
#LOCAL_CFLAGS += -O3

# DEBUG_LINKER -> debug output of linker

# DEBUG_SANDBOX -> the debug output of function SANDBOX_LOG/SANDBOX_LOGE...

# DEBUG_BT  ->the debug output of function BT_DEBUGXXX
# DEBUG_BT_RUNTIME -> the debug output at runtime (see trampoline_asm.S) (rely on DDEBUG_BT)
# DIS_THUMB_INSTRUCTION -> disassemble translated thumb instructions (rely on DDEBUG_BT)
# DIS_ARM_INSTRUCTION -> disassemble translated arm instructions (rely on DDEBUG_BT)

# BDB_DEBUGGER -> enable BDB debugger


#LOCAL_CFLAGS += -Wall -Werror -Wno-error=comment -Wno-error=unused-but-set-variable -DARM_SANDBOX -DANDROID_ARM_LINKER -DDEBUG_BT_RUNTIME -DDIS_THUMB_INSTRUCTION -DDIS_ARM_INSTRUCTION -DDEBUG_SANDBOX -DDEBUG_LINKER -march=armv7-a -I. -I./debug



#LOCAL_CFLAGS += -Wall -Werror -Wno-error=comment -Wno-error=unused-but-set-variable -DARM_SANDBOX -DANDROID_ARM_LINKER -DBDB_DEBUGGER -DDEBUG_BT -DDIS_THUMB_INSTRUCTION -DDIS_ARM_INSTRUCTION -DDEBUG_BT_RUNTIME  -march=armv7-a -I.

#LOCAL_CFLAGS += -Wall -Werror -Wno-error=unused-variable -DARM_SANDBOX -DANDROID_ARM_LINKER -DDEBUG_BT -DDEBUG_BT_RUNTIME -DDIS_THUMB_INSTRUCTION -DDIS_ARM_INSTRUCTION -DBDB_DEBUGGER -march=armv7-a -I . -I trampoline
#LOCAL_CFLAGS += -Wall -Werror -Wno-error=unused-variable -DARM_SANDBOX -DANDROID_ARM_LINKER -DDEBUG_BT -DDEBUG_BT_RUNTIME -DDIS_THUMB_INSTRUCTION -DDIS_ARM_INSTRUCTION -march=armv7-a -I . -I trampoline
LOCAL_CFLAGS += -Wall -Werror -Wno-error=unused-variable -DARM_SANDBOX -DANDROID_ARM_LINKER -DDEBUG_BT -DDEBUG_BT_RUNTIME -DDIS_THUMB_INSTRUCTION -DDIS_ARM_INSTRUCTION -march=armv7-a -I . -I trampoline

LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog -ldl -g

include $(BUILD_SHARED_LIBRARY)
