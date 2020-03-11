/* 2015-07-27 */

#ifndef __LOG_H
#define __LOG_H

#include <stdio.h>
#include <unistd.h>
#include <android/log.h>

#define DEFAULT_INSN_LOG_FILE		"/tmp/insn.trace"
#define DEFAULT_INSN_BUF_SIZE		1024 * 1024 * 4


static char log_buf[DEFAULT_INSN_BUF_SIZE];
static char *log_cur = log_buf;

#define INSN_LOG_OUTPUT

#define INSN_LOG_TAG		"INSN_LOG"

#ifdef INSN_LOG_OUTPUT
#define INSN_LOG_DUMP {\
	if(log_file) { fwrite(log_buf, 1, log_cur-log_buf, log_file);} \
	else { __android_log_print(ANDROID_LOG_INFO, INSN_LOG_TAG, log_buf);} \
	log_cur = log_buf; }
#define INSN_LOG_ADD(fmt, x...) {\
	int res = = sprintf(log_cur, fmt, ##x); \
	log_cur += res; \
	if(log_cur - log_buf > DEFAULT_INSN_BUF_SIZE - 256) { \
		INSN_LOG_DUMP;} \
}

#define INSN_LOG_FILE(fmt, x...) {\
	int res = 0;										\
	if(log_file) { res = fprintf(log_file, fmt, ##x); } \
	return res; }

#endif



int insn_log_init(const char *file);
void insn_log_exit();

#endif
