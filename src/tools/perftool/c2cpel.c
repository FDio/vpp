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
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/elog.h>
#include <vppinfra/mem.h>
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include "cpel.h"
#include "cpel_util.h"

static elog_main_t elog_main;

/*
 * convert_clib_file
 */
void convert_clib_file(char *clib_file)
{
    clib_error_t *error = 0;
    int i;
    elog_main_t *em = &elog_main;
    double starttime, delta;

    error = elog_read_file (&elog_main, clib_file);

    if (error) {
        clib_warning("%U", format_clib_error, error);
        exit (1);
    }

    em = &elog_main;

    starttime = em->events[0].time;

    for (i = 0; i < vec_len (em->events); i++) {
        elog_event_t *e;        /* clib event */
        evt_t *ep;              /* xxx2cpel event */
        u8 *s;
        u64 timestamp;
        elog_event_type_t *t;
        u8 *brief_event_name;
        u8 *track_name;
        int j;

        e = vec_elt_at_index(em->events, i);

        /* Seconds since start of log */
        delta = e->time - starttime;
        
        /* u64 nanoseconds since start of log */
        timestamp = delta * 1e9;

        s = format (0, "%U%c", format_elog_event, em, e, 0);

        /* allocate an event instance */
        vec_add2(the_events, ep, 1);
        ep->timestamp = timestamp;
        
        /* convert string event code to a real number */
        t = vec_elt_at_index (em->event_types, e->type);

        /* 
         * Construct a reasonable event name.
         * Truncate the format string at the first whitespace break
         * or printf format character.
         */
        brief_event_name = format (0, "%s", t->format);

        for (j = 0; j < vec_len (brief_event_name); j++) {
            if (brief_event_name[j] == ' ' ||
                brief_event_name[j] == '%' ||
                brief_event_name[j] == '(') {
                brief_event_name[j] = 0;
                break;
            }
        }
        /* Throw away that much of the formatted event */
        vec_delete (s, j+1, 0);

        ep->event_id = find_or_add_event(brief_event_name, "%s");

        track_name = format (0, "%U%c", format_elog_track, em, e, 0);

        ep->track_id = find_or_add_track (track_name);

        ep->datum = find_or_add_strtab(s);

        vec_free (track_name);
        vec_free(brief_event_name);
        vec_free(s);
    }
}

u8 *vec_basename (char *s)
{
    u8 * rv;
    char *cp = s;

    while (*cp)
        cp++;

    cp--;

    while (cp > s && *cp != '/')
        cp--;

    if (cp > s)
        cp++;

    rv = format (0, "%s", cp);
    return rv;
}


int event_compare (const void *a0, const void *a1)
{
    evt_t *e0 = (evt_t *)a0;
    evt_t *e1 = (evt_t *)a1;

    if (e0->timestamp < e1->timestamp)
        return -1;
    else if (e0->timestamp > e1->timestamp)
        return 1;
    return 0;
}

int main (int argc, char **argv)
{
    int curarg=1;
    char **inputfiles = 0;
    char *outputfile = 0;
    FILE *ofp;

    if (argc < 3)
        goto usage;

    while (curarg < argc) {
        if (!strncmp(argv[curarg], "--input-file", 3)) {
            curarg++;
            if (curarg < argc) {
                vec_add1 (inputfiles, argv[curarg]);
                curarg++;
                continue;
            }
            clib_warning("Missing filename after --input-file\n");
            exit (1);
        }

        if (!strncmp(argv[curarg], "--output-file", 3)) {
            curarg ++;
            if (curarg < argc) {
                outputfile = argv[curarg];
                curarg ++;
                continue;
            }
            clib_warning("Missing filename after --output-file\n");
            exit(1);
        }
        vec_add1 (inputfiles, argv[curarg]);
        curarg++;
        continue;

    usage:
        fformat(stderr, 
                "c2cpel [--input-file] <filename> --output-file <filename>\n");
        exit(1);
    }

    if (vec_len(inputfiles) == 0 || outputfile == 0)
        goto usage;
        
    if (vec_len(inputfiles) > 1)
        goto usage;

    clib_mem_init (0, ((uword)3<<30));

    cpel_util_init();

    convert_clib_file (inputfiles[0]);

    ofp = fopen (outputfile, "w");
    if (ofp == NULL) {
        clib_unix_warning ("couldn't create %s", outputfile);
        exit (1);
    }
    
    alpha_sort_tracks();
    fixup_event_tracks();

    /*
     * Four sections: string-table, event definitions, track defs, events. 
     */
    if (!write_cpel_header(ofp, 4)) {
        clib_warning ("Error writing cpel header to %s...\n", outputfile);
        unlink(outputfile);
        exit(1);
    }

    if (!write_string_table(ofp)) {
        clib_warning ("Error writing string table to %s...\n", outputfile);
        unlink(outputfile);
        exit(1);
    }

    if (!write_event_defs(ofp)) {
        clib_warning ("Error writing event defs to %s...\n", outputfile);
        unlink(outputfile);
        exit(1);
    }

    if (!write_track_defs(ofp)) {
        clib_warning ("Error writing track defs to %s...\n", outputfile);
        unlink(outputfile);
        exit(1);
    }

    if (!write_events(ofp, (u64) 1e9)) {
        clib_warning ("Error writing events to %s...\n", outputfile);
        unlink(outputfile);
        exit(1);
        
    }
    fclose(ofp);
    exit (0);
}
