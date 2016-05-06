/*
 *------------------------------------------------------------------
 * sign.c - sign a binary
 * 
 * Jan 2010, George Spelvin
 * 
 * Copyright (c) 2010 by cisco Systems, Inc.  
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/unix.h>

/* Elf-file magic number */
static unsigned char elfmag[4] = {0x7F, 'E', 'L', 'F'};

int add_signature (char *file, u8 *sigfile)
{
    clib_error_t *e;
    u8 *sigcontents;
    uword siglen;
    struct stat statb;
    int fd;
    char magic[4];
    int i;

    if ((e = unix_file_contents ((char *)sigfile, &sigcontents))) {
        fformat(stderr, "%v", e->what);
        clib_error_free (e);
        return 1;
    }

    siglen = vec_len (sigcontents);

    vec_add1(sigcontents, (siglen>>24)&0xff);
    vec_add1(sigcontents, (siglen>>16)&0xff);
    vec_add1(sigcontents, (siglen>> 8)&0xff);
    vec_add1(sigcontents, (siglen>> 0)&0xff);
    
    /* remember the desired file mode */
    if (stat(file, &statb) < 0) {
        fformat(stderr, "Couldn't stat %s\n", file);
        return 1;
    }
    /* Skip empty / short trout. Don't complain */
    if (statb.st_size < 4) {
        return 0;
    }

    /* make it writeable */
    chmod (file, 0777);

    fd = open (file, O_RDWR | O_APPEND, 0755);
    
    if (fd < 0) {
        fformat (stderr, "Couldn't append to %s\n", file);
        return 1;
    }

    /* 
     * We feed this program a list of files with execute permission.
     * Signing a shell script makes it taste bad, etc. etc.
     */
    if (read(fd, magic, 4) != 4) {
        fformat (stderr, "Couldn't read magic number from %s\n", file);
    }

    for (i = 0; i < 4; i++) {
        if (magic[i] != elfmag[i]) {
            goto skip_write;
        }
    }

    fformat(stdout, "sig: %U\n", 
            format_hex_bytes, sigcontents, vec_len(sigcontents));

    if (write (fd, sigcontents, vec_len(sigcontents)) 
        != vec_len (sigcontents)) {
        fformat (stderr, "Write error on %s\n", file);
        return 1;
    }

 skip_write:
    close(fd);

    /* restore the file mode */
    chmod (file, statb.st_mode);

    return 0;
}

int mypid;

int sign_one_file (char *pemfile, char *password, char *file)
{
    u8 *cmd;
    u8 *t1, *t2;

    t1 = format (0, "/tmp/sha256-%d%c", mypid, 0);
    t2 = format (0, "/tmp/sig-%d%c", mypid, 0);

    cmd = format (0, "openssl dgst -sha256 < %s > %s%c", file, t1, 0);
    if (system((char *)cmd)) {
    barf:
        clib_warning("'%s' failed", cmd);
        return 1;
    }
    vec_free(cmd);

    cmd = format (0, "openssl rsautl -inkey %s -in %s -out %s ",
                  pemfile, t1, t2);
    cmd = format (cmd, "-passin pass:%s -sign%c", password, 0);

    if (system((char *)cmd))
        goto barf;

    vec_free(cmd);

    if (add_signature (file, t2))
        return 1;

    unlink ((char *)t1);
    unlink ((char *)t2);

    return (0);
}

/* usage: sign <foo.pem> <password> <list-of-files> */

int main (int argc, char **argv)
{
    int i;
    mypid = getpid();

    if (argc < 4) {
        fformat(stderr, "usage: %s <xxx.pem> <password> <list-of-files>\n", 
		argv[0]);
        exit (1);
    }

    for (i = 3; i < argc; i++) {
        if (sign_one_file (argv[1], argv[2], argv[i])) {
            fformat(stderr, "Left unsigned: %s\n", argv[i]);
        }
    }

    exit (0);
}
