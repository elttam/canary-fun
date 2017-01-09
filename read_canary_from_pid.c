/**
 *
 * Use Auxiliary Vector and `process_vm_readv` syscall to dump the canary
 * of a PID.
 *
 * Compile with:
 * $ make read_canary_from_pid
 *
 * Execute with:
 * $ ./read_canary_from_pid <PID>
 *
 * @_hugsy_
 *
 * Copyright (c) 2017 elttam
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#define _GNU_SOURCE

#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <endian.h>
#include <unistd.h>
#include <linux/limits.h>
#include <byteswap.h>

#define AT_RANDOM 25
#define DEBUG 1

#ifdef __x86_64__
#define L 8
#define T uint64_t
#define F "%#lx"
#else
#define L 4
#define T uint32_t
#define F "%#x"
#endif

/**
 * Use /proc/<pid>/auxv to determine the address of AT_RANDOM.
 */
T get_at_random_address(int pid)
{
	char path[PATH_MAX]={0,};
        int pathlen = 0;
        int fd, n;
        T res = 0, key, value;

        snprintf(path, PATH_MAX, "/proc/%d/auxv", pid);
#ifdef DEBUG
	printf("[+] pid=%d, path=%s\n", pid, path);
#endif

        fd = open(path, O_RDONLY);
        if(fd<0){
                perror("[-] open() failed");
                return res;
        }

        while(1){
                key = 0;
                n = read(fd, &key, sizeof(key));
                if(n!=sizeof(key)) break;

                value = 0;
                read(fd, &value, sizeof(value));

                if (key == AT_RANDOM){
                        res = value;
                        break;
                }
        }

        close(fd);
        return res;
}


/**
 * Use the syscall process_vm_readv to peek into targeted process
 * virtual memory.
 */
ssize_t dump_memory(pid_t pid, T addr, char* buf, size_t buflen)
{
	struct iovec local[1];
	struct iovec remote[1];
        ssize_t nread;

	local->iov_base = buf;
	local->iov_len = buflen;
	remote->iov_base = (void*)addr;
	remote->iov_len = buflen;

	nread = process_vm_readv(pid, local, 1, remote, 1, 0);
	if (nread < 0) {
		perror("[-] process_vm_readv()");
		return nread;
	}
#ifdef DEBUG
	printf("[+] got %zd bytes\n", nread);
#endif
        return nread;
}


/**
 * main()
 */
int main(int argc, char** argv, char** envp)
{
	pid_t pid;
	int i;
        T addr;
        char buf[L*2]={0,};
        size_t buflen = sizeof(buf);
        ssize_t nread;
        T canary;

        if (argc!=2){
                printf("[-] Syntax: %s <PID>\n", argv[0]);
                return EXIT_FAILURE;
        }

        pid = atoi(argv[1]);

#ifdef DEBUG
	printf("[+] reading auxv of pid=%d\n", pid);
#endif

        addr = get_at_random_address(pid);
        if (addr==0){
                printf("[-] get_at_random_address() failed\n");
                return EXIT_FAILURE;
        }

#ifdef DEBUG
	printf("[+] reading %zu bytes from pid=%d from address "F"\n", buflen, pid, addr);
#endif

        nread = dump_memory(pid, addr, buf, buflen);
        if (nread<=0){
                printf("[-] dump_memory() failed\n");
                return EXIT_FAILURE;
        }

#ifdef DEBUG
        printf("[+] ");
	for (i=0; i<nread; i++) printf("%02x ", (uint8_t)buf[i]);
        printf("\n");
#endif

        canary = ((T*)buf)[0] & (T)~0xff; // because of glibc-2.24/sysdeps/generic/dl-osinfo.h#L40
        printf("[+] canary for PID=%d is "F"\n", pid, canary);
	return EXIT_SUCCESS;
}
