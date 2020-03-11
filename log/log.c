#include "log.h"

static FILE *log_file = NULL;
int insn_log_init(const char *f) {
	if(f){
		log_file = fopen(f, "w");
	}
	else {
		log_file = fopen(DEFAULT_INSN_LOG_FILE, "w");
	}
	if(log_file){
		return 1;
	}
	else {
		return 0;
	}
}

void insn_log_exit() {
	if(log_file) {
		fclose(log_file);
		log_file = NULL;
	}
}

