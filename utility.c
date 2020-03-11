#include <string.h>
#include <stdio.h>
#include <elf.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utility.h"
#include "debug/debug.h"


/* Read characters from 'fd' until a newline is encountered. If a newline
  character is not encountered in the first (n - 1) bytes, then the excess
  characters are discarded. The returned string placed in 'buf' is
  null-terminated and includes the newline character if it was read in the
  first (n - 1) bytes. The function return value is the number of bytes
  placed in buffer (which includes the newline character if encountered,
  but excludes the terminating null byte). */

u4 readLine(int fd, void *buffer, size_t n)
{
    ssize_t numRead;                    /* # of bytes fetched by last read() */
    size_t totRead;                     /* Total bytes read so far */
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL) {
        errno = EINVAL;
        return -1;
    }

    buf = buffer;                       /* No pointer arithmetic on "void *" */

    totRead = 0;
    for (;;) {
        numRead = read(fd, &ch, 1);

        if (numRead == -1) {
            if (errno == EINTR)         /* Interrupted --> restart read() */
                continue;
            else
                return -1;              /* Some other error */

        } else if (numRead == 0) {      /* EOF */
            if (totRead == 0)           /* No bytes read; return 0 */
                return 0;
            else                        /* Some bytes read; add '\0' */
                break;

        } else {                        /* 'numRead' must be 1 if we get here */
            if (totRead < n - 1) {      /* Discard > (n - 1) bytes */
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n')
                break;
        }
    }

    *buf = '\0';
    return totRead;
}

/* find the address of GOT table in file
   code is from gingerbreak root exploit :)
*/
u4 find_got(char *file) {
    int fd, i;
    Elf32_Ehdr ehdr;
    Elf32_Phdr phdr;
    Elf32_Dyn *dyn = NULL;
    size_t dyn_size = 0;

    memset(&ehdr, 0, sizeof(ehdr));
    memset(&phdr, 0, sizeof(phdr));

    if ((fd = open(file, O_RDONLY)) < 0) {
        PROFILER_LOGE("[x] [%s:%d] [die]: open %s \n", FILE,LINE,file);
        goto bail;
    }


    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        PROFILER_LOGE("[x] [%s:%d] [die]: read %s \n", FILE,LINE,file);
        goto bail_close;
    }

    if (lseek(fd, ehdr.e_phoff, SEEK_SET) != ehdr.e_phoff) {
        PROFILER_LOGE("[x] [%s:%d] [die]: lseek %s \n", FILE,LINE,file);
        goto bail_close;
    }

    for (i = 0; i < ehdr.e_phnum; ++i) {
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            PROFILER_LOGE("[x] [%s:%d] [die]: read %s \n", FILE,LINE,file);
            goto bail_close;
        }
        if (phdr.p_type == PT_DYNAMIC)
            break;
    }
    if (phdr.p_type != PT_DYNAMIC) {
        PROFILER_LOGE("[x] [%s:%d] [die]: No GOT found %s \n", FILE,LINE,file);
        goto bail_close;
    }

    if (lseek(fd, phdr.p_offset, SEEK_SET) != phdr.p_offset) {
        PROFILER_LOGE("[x] [%s:%d] [die]: lseek %s \n", FILE,LINE,file);
        goto bail_close;
    }
    dyn_size = phdr.p_filesz;
    PROFILER_LOGI("[*] [%s:%d] Found PT_DYNAMIC of size %d (%d entries)\n",
                                               FILE,LINE,dyn_size,
                                       dyn_size/sizeof(Elf32_Dyn));
    if ((dyn = malloc(dyn_size)) == NULL) {
        PROFILER_LOGE("[x] [%s:%d] [die]: malloc %s \n", FILE,LINE,file);
        goto bail_close;
    }
    if (read(fd, dyn, dyn_size) != dyn_size) {
        PROFILER_LOGE("[x] [%s:%d] [die]: read %s \n", FILE,LINE,file);
        goto bail_close_free;
    }

    for (i = 0; i < dyn_size/sizeof(Elf32_Dyn); ++i) {
        if (dyn[i].d_tag == DT_PLTGOT)
            break;
    }
    if (dyn[i].d_tag != DT_PLTGOT) {
        PROFILER_LOGE("[x] [%s:%d] [die]: No GOT found %s \n", FILE,LINE,file);
        goto bail_close_free;
    }

    //SANDBOX_LOGE("[+ %s:%d] Found GOT: 0x%08x\n", FILE,LINE, (u4)dyn[i].d_un.d_ptr);

    u4 ret = (u4) dyn[i].d_un.d_ptr;
    close(fd);
    free(dyn);

    PROFILER_LOGE("[+ %s:%d] Found GOT: 0x%08x\n", FILE,LINE, (u4)ret);

    return ret;

bail:
    return 0;
bail_close:
    close(fd);
    return 0;
bail_close_free:
    close(fd);
    free(dyn);
    return 0;
}

//find the address of func_name in lib (lib_name)
u4 find_func_addr(char * lib_name, char * func_name) {
    void *r = NULL;
    void *dlh = dlopen(lib_name, RTLD_NOW);

    if (!dlh) {
        PROFILER_LOGE("[x] [%s:%d] [die]: can not open library %s \n", FILE,LINE,
                                                              lib_name);
        goto bail;
    }

    if ((r = (void *)dlsym(dlh, func_name)) == NULL) {
        PROFILER_LOGE("[x] [%s:%d] [die]: can not find function %s in library %s \n",
                                                FILE,LINE,func_name,lib_name);
        dlclose(dlh);
        goto bail;
    }
    dlclose(dlh);
    return (u4)r;

bail:
    return 0;
}

/*
4.1 memory layout:
40716000-407b8000 r-xp 00000000 b3:03 690        /system/lib/libdvm.so
407b8000-407b9000 ---p 00000000 00:00 0
407b9000-407bc000 r--p 000a2000 b3:03 690        /system/lib/libdvm.so
407bc000-407c1000 rw-p 000a5000 b3:03 690        /system/lib/libdvm.so
407c1000-407c3000 rw-p 00000000 00:00 0
*/

u4 find_lib_base_addr(char * lib_name) {

    char buf[128];
    int fd = open("/proc/self/maps",O_RDONLY);

    int ret = readLine(fd, buf, sizeof(buf));
    char start_address[16];
    char end_address[16];
    char permissions[5];
    char c_lib_name[64];

    while (ret > 0) {
        //find the libdvm.so first
        int cnt = sscanf (buf,"%8c-%8c %s %*s %*s %*s %s",start_address,
                                    end_address, permissions, c_lib_name);
        if (cnt > 0) {
            if (strcmp(c_lib_name,lib_name) == 0) {
                //check the permissions
                if (permissions[2] == 'x') {
                    start_address[8] = '\0';
                    //SANDBOX_LOGI("[*] [%s:%d] find libdvm %s \n",FILE,LINE,
                    //                                 start_address);
                    u4 ret;
                    sscanf(start_address,"%x",&ret);
                    //SANDBOX_LOGI("[*] [%s:%d] find libdvm %s \n",FILE,LINE,ret);
                    close(fd);
                    return ret;
                }

            }
        }

        memset(buf, 0x0, sizeof(buf));
        memset(buf, 0x0, sizeof(permissions));
        ret = readLine(fd, buf, sizeof(buf));
    }

    close(fd);
    return 0;
}

#ifdef SANDBOX_HALT
#undef SANDBOX_HALT
// mov     pc, #0  ;
#define SANDBOX_HALT 0xe3a0f000
#endif

//size should be power of 4
void fill_memory_hlt(void *dst, u4 size) {
    int i = 0;
    int len = size >> 2;
    // SANDBOX_LOGI("[*] [%s:%d] size %d \n",FILE,LINE,len);
    for (i = 0; i < len; i ++) {
        // if (i > 1000)
            // SANDBOX_LOGI("[*] [%s:%d] i %d \n",FILE,LINE,i);
        *((u4*)dst + i) = SANDBOX_HALT;
    }
}
