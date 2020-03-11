#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include <netinet/in.h>
#include <stdio.h>

#include "utility.h"
#include "debug.h"
#include "global.h"
#include "bt/bt_asm_macros.h"

/*
 * It's not surprising that it's very hard to debug the translated code...
 * This bdb tool can be used to communicate with a custom debugger.
 *
 *   Why I use this tool instead of implementing a gdb protocol stub?
 *
 *
 *
 */


#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG    "BDB"

#define DEBUG_BDB

#ifdef DEBUG_BDB
#define BDB_LOGE(...)   __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG,__VA_ARGS__)
#define BDB_LOGI(...)   __android_log_print(ANDROID_LOG_INFO,  LOG_TAG,__VA_ARGS__)
#else
/* kill the warning. (and (hopefully) compiler will remove these functions totally) */
#define BDB_LOGE(...)  do { if (0) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG,__VA_ARGS__); } while (0)
#define BDB_LOGI(...)  do { if (0) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG,__VA_ARGS__); } while (0)
#endif


static int listen_sock = -1;
static int in_sock = -1;

bool write_to_client(int fd, char *str){
    if (fd == -1)
        return false;

    write(fd, str, strlen(str));

    return true;
}

bool send_ok(int fd) {
    return write_to_client(fd, "OK\0");
}

bool send_ko(int fd) {
    return write_to_client(fd, "KO\0");
}

#define BREAK_POINT   1
#define WATCH_POINT   2

/* breakpoints */
struct virtual_bp {
    u4 addr;
    /* type:1 -> breakpoints
     * type:2 -> memory watch points
     */
    int type;
    size_t hit_cnt;
    struct virtual_bp * next;
};

/* breakpoints */
struct virtual_bp * bps = NULL;
int num_of_bps = 0;

bool init_bps() {
    bps = (struct virtual_bp *) malloc(sizeof(*bps));
    if (bps == NULL) {
        BDB_LOGE("can not allocate memory for bps");
        return false;
    }

    bps->addr = 0;
    bps->next = NULL;

    num_of_bps = 0;

    return true;
}

bool add_bp(u4 addr, int type) {
    if (bps == NULL) {
        if (!init_bps())
            return false;
    }

    struct virtual_bp * bp = (struct virtual_bp *) malloc(sizeof(*bp));
    if (bp == NULL) {
        BDB_LOGE("can not allocate memory for bps");
        return false;
    }

    bp->addr = addr;
    bp->next = bps->next;
    bps->next = bp;
    bp->type = type;
    bp->hit_cnt = 0;

    BDB_LOGI("add addr 0x%x", bp->addr);

    num_of_bps++;

    return true;
}

bool remove_bp(u4 addr, int type) {
    if (bps == NULL) {
        return false;
    }

    struct virtual_bp * bp = bps->next;
    struct virtual_bp * prev = bps;

    while(bp) {
        if ((bp->addr == addr) && (type == bp->type)) {
            prev->next = bp->next;
            free(bp);
            num_of_bps--;
            return true;
        }
        prev = bp;
        bp = bp->next;
    }

    return false;
}


bool info_bps() {
    if (bps == NULL) {
        return false;
    }

    char b_buffer[256];
    char *dst = b_buffer;
    int index = 0;

    struct virtual_bp * bp = bps->next;

    //break:total_cnt:[addr1]:type:hitcnt
    index = sprintf(dst + index, "break:%d", num_of_bps);
    dst += index;

    if (num_of_bps != 0) {
        while(bp) {
            BDB_LOGI("addr 0x%x", bp->addr);
            index = sprintf(dst,
                ":0x%x:%d:%d", bp->addr, bp->type, bp->hit_cnt);
            dst += index;
            bp = bp->next;
        }
    }

    *dst = '\0';



    BDB_LOGI("send %s", b_buffer);

    write_to_client(in_sock, b_buffer);

    return true;
}


struct virtual_bp * get_bp(u4 addr, int type) {
    if (bps == NULL) {
        return NULL;
    }

    struct virtual_bp * bp = bps->next;

    while(bp) {
        if ((bp->addr == addr) && (type == bp->type)) {
            return bp;
        }

        bp = bp->next;
    }
    return NULL;
}


int readline(int fd, char *bufptr, size_t len)
{
  /* Note that this function is very tricky.  It uses the
     static variables bp, cnt, and b to establish a local buffer.
     The recv call requests large chunks of data (the size of the buffer).
     Then if the recv call reads more than one line, the overflow
     remains in the buffer and it is made available to the next call
     to readline.
     Notice also that this routine reads up to '\n' and overwrites
     it with '\0'. Thus if the line is really terminated with
     "\r\n", the '\r' will remain unchanged.
  */
    char *bufx = bufptr;
    static char *bp;
    static int cnt = 0;
    static char b[1500];
    char c;

    while ( --len > 0 ) {
        if ( --cnt <= 0 ) {
            cnt = recv( fd, b, sizeof( b ), 0);
            if (cnt < 0) {
                if ( errno == EINTR ) {
                    len++;        /* the while will decrement */
                    continue;
                }
            return -1;
            }
            if ( cnt == 0 )
                return 0;
            bp = b;
        }
        c = *bp++;
        *bufptr++ = c;
        if ( c == '\n' ) {
            *bufptr = '\0';
            return bufptr - bufx;
        }
    }
    return -1;
}

char mem_buf[2500];

/* len: should be 4 multiple*/
bool send_memory(char * maddr, int len) {

    if (in_sock == -1)
        return false;

    u4 * addr = (u4 *) maddr;
    int i = 0;

    if (len > 128)
        len = 128;

    if (len < 4)
        len = 4;

    int index = 0;

    memset(mem_buf, 0x0, sizeof(mem_buf));

    for (i = 0; i < len / 4; i ++) {
        index += sprintf(mem_buf + index, "0x%08x:0x%08x", (u4)addr, *addr);
        addr ++;

        if (i < ((len / 4) - 1)) {
            index += sprintf(mem_buf + index, "%s", ",");
        } else {
            index += sprintf(mem_buf + index, "%s", "\n");
        }
    }

    // mem_buf[index] = '\n';

    BDB_LOGI("send %s", mem_buf);

    write_to_client(in_sock, mem_buf);

    return true;
}


bool send_regs();
#define CMD_ERROR   -1
#define INIT_ERROR  -2

/* this function is not secure.!!! */
int consume_cmd(int in_sock) {

    char cmd_buf[128];
    char temp_buf[128];

    int cmd_arg_cnt = 0;

    char ** cmd_args;

    int i = 0;

    while (1) {
        if (readline(in_sock, cmd_buf, sizeof(cmd_buf))) {

            BDB_LOGI("received cmd: %s ", cmd_buf);

            /* change last \n to \n */
            cmd_buf[strlen(cmd_buf) - 1] = '\0';

            strncpy(temp_buf, cmd_buf, sizeof(temp_buf));

            /* parse command */
            char* match = strtok(temp_buf, " ");
            while(match != NULL){
                cmd_arg_cnt++;
                match = strtok(NULL, " ");
            }

            if (cmd_arg_cnt == 0) {
                goto err_cmd;
            }

            cmd_args = (char **) malloc(sizeof(*cmd_args) * cmd_arg_cnt);
            if (cmd_args == NULL) {
                BDB_LOGE("can not allocate memory ");
                return CMD_ERROR;
            }
            cmd_args[cmd_arg_cnt] = NULL;

            i = 0;

            if (cmd_arg_cnt > 0){
                match = strtok(cmd_buf, " ");
                do{
                    cmd_args[i] = strdup(match);
                    i++;
                    match = strtok(NULL, " ");
                } while(match != NULL);
            }

            BDB_LOGI("received cmd: %s ", cmd_args[0]);


            if (strcmp(cmd_args[0], "bp_add") == 0) {
                BDB_LOGI("bp_add, addr %s ", cmd_args[1]);
                /* add break point: bp_add addr */
                if (cmd_arg_cnt < 2) {
                    goto err_cmd;
                }

                u4 b_addr = 0;
                b_addr = strtoul(cmd_args[1], NULL, 0);
                if (add_bp(b_addr, BREAK_POINT)) {
                    send_ok(in_sock);
                } else {
                    send_ko(in_sock);
                }
            } else if (strcmp(cmd_args[0], "bp_del") == 0) {
                /* del break point: bp_del addr */
                if (cmd_arg_cnt < 2) {
                    goto err_cmd;
                }

                u4 b_addr = 0;
                b_addr = strtoul(cmd_args[1], NULL, 0);
                if (remove_bp(b_addr, BREAK_POINT)) {
                    send_ok(in_sock);
                } else {
                    send_ko(in_sock);
                }
            } else if (strcmp(cmd_args[0], "bp_info") == 0) {
                /* info break point: bp_info */
                info_bps();
            } else if (strcmp(cmd_args[0], "regs") == 0) {
                BDB_LOGI("regs: %s ", cmd_args[0]);
                /* read reg: regs */
                send_regs();
            } else if (strcmp(cmd_args[0], "memory") == 0) {
                BDB_LOGI("mem: %s ", cmd_args[0]);
                /* add break point: mem addr len*/
                if (cmd_arg_cnt < 3) {
                    goto err_cmd;
                }

                u4 m_addr = 0;
                m_addr = strtoul(cmd_args[1], NULL, 0);
                u4 len = strtoul(cmd_args[2], NULL, 0);
                send_memory((char *)m_addr, len);
            } else if (strcmp(cmd_args[0], "continue") == 0) {
                BDB_LOGI("continue: %s ", cmd_args[0]);
                send_ok(in_sock);
                /* continue */
                break;
            }
        }
    }

    BDB_LOGI("continue execution ");

    return 0;

err_cmd:
    BDB_LOGE("corrupted command %s ", cmd_buf);
    return CMD_ERROR;
}

/* add the mapping between old pc with translated pc */
bool send_pc_mapping(u4 o_pc, u4 t_pc) {
    if (in_sock == -1)
        return false;

    /* mapping:o_pc:new_pc*/

    char temp_buf[32];
    sprintf(temp_buf, "mapping:0x%x:0x%x\n", o_pc, t_pc);

    BDB_LOGI("send %s", temp_buf);

    write_to_client(in_sock, temp_buf);

    return true;
}

int waiting_connection() {
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

    listen_sock = socket(PF_INET, SOCK_STREAM, 0);

    int tmp = 1;

    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
                                (char *) &tmp, sizeof(tmp)) < 0){
        BDB_LOGE("can not set socket option");
        return INIT_ERROR;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(1234);

    if (bind(listen_sock, (struct sockaddr *) &serv_addr,
                                sizeof(serv_addr)) < 0) {
        BDB_LOGE("ERROR on binding");
        return INIT_ERROR;
    }

    listen(listen_sock, 1);

    clilen = sizeof(cli_addr);

    BDB_LOGI("waiting for connection ...");
    /* block here */
    in_sock = accept(listen_sock, (struct sockaddr *) &cli_addr, &clilen);

    BDB_LOGI("client connected !");


    if (!init_bps()) {
        BDB_LOGE("can not init bps");
        return false;
    }

    consume_cmd(in_sock);


    return 0;
}

// The debugger is initialized when dlsym happens
int bdb_debugger_init() {
    if (listen_sock == -1) {
        return waiting_connection();
    }

    return 0;
}

/*****************************************************************************/

#define OFFSET_STATUS_REG   64

struct arm_context {
    u4 regs[16];      /**/
    u4 status_reg;    /*offset: 64*/
};


/* TODO: multi-thread */
struct arm_context context;

bool send_break(u4 addr) {
    if (in_sock == -1)
        return false;

    /* break:addr*/

    char temp_buf[32];
    sprintf(temp_buf, "break:0x%x\n", addr);

    BDB_LOGI("send %s", temp_buf);

    write_to_client(in_sock, temp_buf);

    return true;
}

/* return the value of all registers */
bool send_regs() {
    if (in_sock == -1)
        return false;

    /* r0:value, r1:value */
    char temp_buf[300];

    int i = 0;
    int index = 0;

    for (i = 0; i < 16; i ++) {
        index += sprintf(temp_buf + index, "r%02d:0x%08x,", i, context.regs[i]);
    }

    sprintf(temp_buf + index, "status:0x%08x\n", context.status_reg);

    BDB_LOGI("send %s", temp_buf);

    write_to_client(in_sock, temp_buf);

    return true;
}

bool send_pc_trace(u4 t_pc) {
    if (in_sock == -1)
        return false;

    /* trace:new_pc*/
    char temp_buf[32];
    sprintf(temp_buf, "trace:0x%x\n", t_pc);

    BDB_LOGI("send %s", temp_buf);

    write_to_client(in_sock, temp_buf);

    return true;
}

// bool bb = false;
void enter_debugger_thumb(struct arm_context * context) {
    // BDB_LOGI("enter_debugger. reg r0 0x%x, pc 0x%x ",
    //                     context->regs[ARMREG_R0],
    //                     context->regs[ARMREG_PC]);

    struct virtual_bp * bp = get_bp(context->regs[ARMREG_PC], BREAK_POINT);
    if (bp) {
        bp->hit_cnt ++;
        send_break(context->regs[ARMREG_PC]);
        consume_cmd(in_sock);
        // bb = true;
    }

    // u4 x1 = 0x51097008;
    // if (bb) {
    //     if (*(u4*)x1 == 0x51097000) {
    //         send_break(context->regs[ARMREG_PC]);
    //         consume_cmd(in_sock);
    //     }
    // }

    //send trace
    send_pc_trace(context->regs[ARMREG_PC]);
}


/*arm_transl_instr is already 2 bytes aligned */
#define ALIGN_4bytes(arm_transl_instr) \
    do {if ((u4)(arm_transl_instr) & 0x3) { \
            *((u2*)(arm_transl_instr)) = 0x46c0; \
            arm_transl_instr += 2; \
        } \
    } while (0)

static inline void gen_put_reg_imm32_thumb(struct translate *ts,
                                        int r, u4 imm32) {
    //the translated code should be 4 bytes aligned
    //since we will use 32bit thumb2 instructions in the following
    // BT_DEBUG_CLEAN("current code cache 0x%8x", ts->transl_instr);
    ALIGN_4bytes(ts->transl_instr);
    /* put load_address into rd */
    //lower 16 bits
    THUMB2_MOVW_IMM(ts->transl_instr, r, imm32 & 0xffff);
    //higher 16 bits
    THUMB2_MOVT_IMM(ts->transl_instr, r,
                                ((imm32 & 0xffff0000)>>16));
}

/*
 * before calling enter_debugger(), we should save current context so that
 * debug can ge them
 *
 *
 *    push {r0 - r3, lr, ip}
 *    //save status
 *    mrs r0
 *    push {r0}
 *
 *   push {r1}
 *   ldr r1, context
 *   //save status
 *   STR R0, [r1 + offset of status]
 *   pop {r1}
 *
 *   ldr r0, context
 *   //use r0 as scratch register. save registers except r0
 *   stmdb r0! <r15-r1>
 *
 *   //restore r0
 *   ldr  r0, [sp + 4] (up saved status register on stack)
 *
 *
 *   ldr r2, address of context
 *   STR r0, [r2]
 *
 *   //prepare parameter
 *   ldr r0, address of context
 *   //call enter_debugger
 *   ldr r2, address of enter_debugger
 *   blx r2
 *
 *   //debugger return.
 *   //restore status register
 *   pop {r0}
 *   msr r0
 *   //restore other registers
 *   pop {r0, r1, r2,r3, lr}
 *
 */

void gen_enter_debugger_thumb(struct translate *ts) {

    // BDB_LOGI("before ");
    ALIGN_4bytes(ts->transl_instr);

    //push {r0, r1, r2, r3, lr, ip}
    THUMB2_PUSH(ts->transl_instr, 0xf | (1<<ARMREG_LR) | (1<<ARMREG_IP));

    // BDB_LOGI("before 0x%x 0x%x", (u4)(ts->transl_instr-4), *(u4*)(ts->transl_instr-4));
    // BDB_LOGI("before 0x%x 0x%x", (u4)(ts->transl_instr), *(u4*)(ts->transl_instr));

    //mrs r0
    THUMB2_RAW(ts->transl_instr, 0xf3ef8000);
    //push {r0} -> save status on stack
    THUMB2_PUSH(ts->transl_instr, 1<< ARMREG_R0);

    //push {R1}
    THUMB2_PUSH(ts->transl_instr, 1<< ARMREG_R1);
    gen_put_reg_imm32_thumb(ts, ARMREG_R1, (u4)&context);
    //THUMB2_STR_IMM8(dst, rs, rn, imm8, index, add, wb)
    //STR R0, [r1 + offset of status register]
    THUMB2_STR_IMM8(ts->transl_instr, ARMREG_R0, ARMREG_R1,
                OFFSET_STATUS_REG, 1, 1, 0);

    // BDB_LOGI("enter_debugger.sizeof (%d) ", sizeof(struct arm_context));
    // last one is saved status reg
    gen_put_reg_imm32_thumb(ts, ARMREG_R0, (u4)(&context) + sizeof(struct arm_context) - 8);

    //we want to put the pc of translated code into context,
    //not current pc( current pc is in this debugger trampoline)

    char * o_transl_instr = (char *)ts->transl_instr;

    //will be patched later
    // f2410200 movw     r2, #0x1000
    // f2c77210 movt     r2, #0x7710
    gen_put_reg_imm32_thumb(ts, ARMREG_R1, 0);

    //STR R1, [r0]
    THUMB2_STR_IMM8(ts->transl_instr, ARMREG_R1, ARMREG_R0,
                                0, 1, 1, 0);

    //restore {R1}
    THUMB2_POP(ts->transl_instr, 1<< ARMREG_R1);

    //stmdb r0! <r14-r1>
    //stmdb r0!, {r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip, sp, lr}
    THUMB2_RAW(ts->transl_instr, 0xe920fffd);

    //restore r0
    //ldr  r0, [sp + 4] (4 bytes up saved status register on stack)
    THUMB2_LDR_IMM8(ts->transl_instr, ARMREG_R0, ARMREG_SP,
                4, 1, 1, 0);

    //save r0 on context
    //ldr r2, addr of context
    gen_put_reg_imm32_thumb(ts, ARMREG_R2, (u4)&context);
    //str r0, [r2]
    THUMB2_STR_IMM8(ts->transl_instr, ARMREG_R0, ARMREG_R2,
                                            0, 1, 1, 0);


    //mov r0, r2 (prepare parameters to call enter_debugger)
    THUMB2_MOVW_REG(ts->transl_instr, ARMREG_R0, ARMREG_R2);
    //call enter_Debugger
    gen_put_reg_imm32_thumb(ts, ARMREG_R2, (u4)enter_debugger_thumb);
    //BLX R2
    THUMB_BLX(ts->transl_instr, ARMREG_R2);

    ALIGN_4bytes(ts->transl_instr);

    //enter_debugger returns

    //restore regs before calling back
    //POP R0
    THUMB2_POP(ts->transl_instr, 1<< ARMREG_R0);
    //msr r0
    THUMB2_RAW(ts->transl_instr, 0xf3808c00);

    //pop {r0,r1,r2,r3,lr,ip}
    THUMB2_POP(ts->transl_instr,  0xf | (1<<ARMREG_LR) | (1<<ARMREG_IP));

    //next is actual start of translated code.
    u4 n_transl_instr = (u4)ts->transl_instr;
     //lower 16 bits
    THUMB2_MOVW_IMM(o_transl_instr, ARMREG_R1, n_transl_instr & 0xffff);
    //higher 16 bits
    // o_transl_instr += 4;
    THUMB2_MOVT_IMM((o_transl_instr), ARMREG_R1,
                                ((n_transl_instr & 0xffff0000)>>16));


}






