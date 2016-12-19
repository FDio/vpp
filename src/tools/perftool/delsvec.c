/* 
 *------------------------------------------------------------------
 * Copyright (c) 2006-2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Break up a delimited string into a vector of substrings */

#include <stdio.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <stdarg.h>

/*
 * #define UNIT_TESTS 1
 * #define MATCH_TRACE 1 
 */

/*
 * delsvec
 * break up an input string into a vector of [null-terminated] u8 *'s
 * 
 * Each supplied delimiter character results in a string in the output
 * vector, unless the delimiters occur back-to-back.  When matched,
 * a whitespace character in the delimiter consumes an arbitrary
 * run of whitespace. See the unit tests at the end of this file
 * for a set of examples.
 *
 * Returns a u8 **, or NULL if the input fails to match.  It is assumed
 * that both input and fmt are C strings, not necessarily vectors.
 *
 * Output strings are both vectors and proper C strings.
 */

static u8 **string_cache;
static u8 **svec_cache;

void delsvec_recycle_this_string (u8 *s)
{
    if (s) {
        _vec_len (s) = 0;
        vec_add1(string_cache, s);
    }
}

void delsvec_recycle_this_svec (u8 **svec)
{
    if (svec) {
        if (svec_cache) {
            vec_free (svec_cache);
        }
        _vec_len (svec) = 0;
        svec_cache = svec;
    }
}

int pvl (char *a)
{
    return vec_len(a);
}

u8 **delsvec(void *input_arg, char *fmt)
{
    u8 **rv = 0;
    int input_index=0;
    u8 *this;
    int dirflag=0;
    int i;
    u8 *input = input_arg;

    if (svec_cache) {
        rv = svec_cache;
        svec_cache = 0;
    }

    while (fmt) {
        dirflag=0;
        if (vec_len (string_cache) > 0) {
            this = string_cache [vec_len(string_cache)-1];
            _vec_len (string_cache) = vec_len (string_cache) - 1;
        } else 
            this = 0;
        /*
         * '*' means one of two things: match the rest of the input, 
         * or match as many characters as possible 
         */
        if (fmt[0] == '*') {
            fmt++;
            dirflag=1;
            /*
             * no more format: eat rest of string... 
             */
            if (!fmt[0]) {
                for (;input[input_index]; input_index++)
                    vec_add1(this, input[input_index]);
                if (vec_len(this)) {
                    vec_add1(this, 0);
#ifdef MATCH_TRACE
                    printf("final star-match adds: '%s'\n", this);
#endif
                    vec_add1(rv, this);
                } else {
                    vec_add1(string_cache, this);
                }

                return(rv);
            }
        }
        /*
         * Left-to-right scan, adding chars until next delimiter char 
         * appears.
         */
        if (!dirflag) {
            while (input[input_index]) {
                if (input[input_index] == fmt[0]) {
                    /* If we just (exact) matched a whitespace delimiter */
                    if (fmt[0] == ' '){
                        /* scan forward eating whitespace */
                        while (input[input_index] == ' ' ||
                               input[input_index] == '\t' ||
                               input[input_index] == '\n')
                            input_index++;
                        input_index--;
                    }
                    goto found;
                }
                /* If we're looking for whitespace */
                if (fmt[0] == ' ') {
                    /* and we have whitespace */
                    if (input[input_index] == ' ' ||
                        input[input_index] == '\t' ||
                        input[input_index] == '\n') {
                        /* scan forward eating whitespace */
                        while (input[input_index] == ' ' ||
                               input[input_index] == '\t' ||
                               input[input_index] == '\n') {
                            input_index++;
                        }
                        input_index--;
                        goto found;
                    }
                }
                /* Not a delimiter, save it */
                vec_add1(this, input[input_index]);
                input_index++;
            }
            /*
             * Fell off the wagon, clean up and bail out 
             */
        bail:

#ifdef MATCH_TRACE
            printf("failed, fmt[0] = '%c', input[%d]='%s'\n",
                   fmt[0], input_index, &input[input_index]);
#endif
            delsvec_recycle_this_string(this);
            for (i = 0; i < vec_len(rv); i++)
                delsvec_recycle_this_string(rv[i]);
            delsvec_recycle_this_svec(rv);
            return(0);
            
        found:
            /*
             * Delimiter matched
             */
            input_index++;
            fmt++;
            /*
             * If we actually accumulated non-delimiter characters,
             * add them to the result vector
             */
            if (vec_len(this)) {
                vec_add1(this, 0);
#ifdef MATCH_TRACE
                printf("match: add '%s'\n", this);
#endif
                vec_add1(rv, this);
            } else {
                vec_add1(string_cache, this);
            }
        } else { 
            /*
             * right-to-left scan, '*' not at 
             * the end of the delimiter string 
             */
            i = input_index;
            while (input[++i])
                ; /* scan forward */
            i--;
            while (i > input_index) {
                if (input[i] == fmt[0])
                    goto found2;
                
                if (fmt[0] == ' ' || fmt[0] == '\t' ||
                    fmt[0] == '\n') {
                    if (input[i] == ' ' ||
                        input[i] == '\t' ||
                        input[i] == '\n')
                        goto found2;
                }
                i--;
            }
            goto bail;

        found2:
            for (; input_index < i; input_index++) {
                vec_add1(this, input[input_index]);
            }
            input_index++;
            fmt++;
            vec_add1(this, 0);
#ifdef MATCH_TRACE
                printf("inner '*' match: add '%s'\n", this);
#endif
            vec_add1(rv, this);
        }
    }
    return (rv);
}

#ifdef UNIT_TESTS

typedef struct utest_ {
    char *string;
    char *fmt;
} utest_t;

utest_t tests[] = {
#ifdef NOTDEF
    {"Dec  7 08:56",
     "  :*"},
    {"Dec 17 08:56",
     "  :*"},
    {"Dec  7 08:56:41.239 install/inst_repl 0/9/CPU0 t1  [40989] File List:Successfully blobbified file list. Took 1 milliseconds",
     "  ::. / //  [] *"},
    {"RP/0/9/CPU0:Dec  7 08:55:28.550 : sam_server[291]: SAM backs up digest list to memory file",
     "///:  ::. : []: *"},
    /* Expected to fail */
    {"Dec  7 08:56:41.239 install/inst_repl 0/9/CPU0 t1  [40989] File List:Successfully blobbified file list. Took 1 milliseconds",
     "///:  ::. : : *"},
    /* Expected to fail */
    {"RP/0/9/CPU0:Dec  7 08:55:28.550 : sam_server[291]: SAM backs up digest list to memory file",
     "  ::. / //  [] *"},
    {"THIS that and + theother", "*+ *"}, 
    {"Dec 12 15:33:07.103 ifmgr/errors 0/RP0/CPU0 3# t2  Failed to open IM connection: No such file or directory", "  ::. / //   *"}, 
    {"Dec 16 21:43:47.328 ifmgr/bulk 0/3/CPU0 t8  Bulk DPC async download complete. Partitions 1, node_count 1, total_out 0, out_offset 0, out_expected 0: No error","  ::. / //  *"},
    {"t:0x53034bd6 CPU:00 PROCESS :PROCCREATE_NAME",
     ": :  :*"},
    {"                       pid:1", " *"},
    {"t:0x53034cbb CPU:00 THREAD  :THCREATE      pid:1 tid:1",
     ": :  : pid: tid:*"},
    {"t:0x5303f950 CPU:00 COMM    :REC_PULSE     scoid:0x40000003 pid:364659",
     ": :  : *"},
    {"/hfr-base-3.3.85/lib/libttyconnection.dll 0xfc000000 0x0000306c 0xfc027000 0x000001c8    1", 
     "     *"},
    {"Feb 28 02:38:26.123 seqtrace 0/1/CPU0 t8  :msg_receive:ifmgr/t8:IMC_MSG_MTU_UPDATE:ppp_ma/t1", 
     "  ::.  //  ::::*"},

    {"Feb 28 02:38:26.123 seqtrace 0/1/CPU0 t8  :msg_send_event:call:ifmgr/t8:124/0:cdp/t1", 
     "  ::.  //  :msg_send_event::::*"},

    {"Feb 28 02:38:26.125 seqtrace 0/1/CPU0 t1  :msg_receive_event:cdp/t1:124/0", 
     "  ::.  //  :msg_receive_event::*"}
    {"t:0x645dd86d CPU:00 USREVENT:EVENT:100, d0:0x00000002 d1:0x00000000",
     ": : USREVENT:EVENT:, d0: *"}
    {"t:0x5303f950 CPU:00 COMM    :REC_PULSE     scoid:0x40000003 pid:364659",
     ": :  : *"},
    {"t:0x2ccf9f5a CPU:00 INT_ENTR:0x80000000 (-2147483648)       IP:0x002d8b18", 
     ": : INT_ENTR:  IP:*"}
    {"t:0xd473951c CPU:00 KER_EXIT:SCHED_GET/88 ret_val:2 sched_priority:10",
     ": : KER_EXIT:SCHED_GET : sched_priority:*"}
    {"t:0x00000123 CPU:01 SYSTEM  :FUNC_ENTER thisfn:0x40e62048 call_site:0x00000000",
    ": : SYSTEM :FUNC_ thisfn: *"},
    {"t:0x5af8de95 CPU:00 INT_HANDLER_ENTR:0x0000004d (77)       PID:8200 IP:0x00000000 AREA:0x0bf9b290", ": : INT_HANDLER_*"},
#endif
    {"t:0x6d1ff92f CPU:00 CONTROL: BUFFER sequence = 1053, num_events = 714",
     ": : CONTROL*"},
    {"t:0x6d1ff92f CPU:00 CONTROL :TIME msb:0x0000003c lsb(offset):0x6d1ff921",
     ": : CONTROL*"},
};

int main (int argc, char **argv)
{
    int i, j;
    u8 **svec;

    for (j = 0; j < ARRAY_LEN(tests); j++) {
        printf ("input string: '%s'\n", tests[j].string);
        printf ("delimiter arg: '%s'\n", tests[j].fmt);
        printf ("parse trace:\n");
        svec = delsvec(tests[j].string, tests[j].fmt);
        if (!svec) {
            printf("index %d failed\n", j);
            continue;
        }
        printf("%d substring vectors\n", vec_len(svec));
        for (i = 0; i < vec_len(svec); i++) {
            printf("[%d]: '%s'\n", i, svec[i]);
        }
        printf ("-------------------\n");
    }
    exit(0);
}
#endif
