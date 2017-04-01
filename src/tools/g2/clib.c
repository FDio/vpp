/* 
 *------------------------------------------------------------------
 * Copyright (c) 2009-2016 Cisco and/or its affiliates.
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
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include "cpel.h"
#include "g2.h"

int widest_track_format;

typedef struct bound_track_ {
    u32 track;
    u8  *track_str;
} bound_track_t;

bound_track_t *bound_tracks;

uword *the_evtdef_hash; /* (event-id, event-definition) hash */
uword *the_trackdef_hash; /* (track-id, track-definition) hash */

elog_main_t elog_main;

void *get_clib_event (unsigned int datum)
{
    elog_event_t *ep = vec_elt_at_index (elog_main.events, datum);
    return (void *)ep;
}

/*
 * read_clib_file
 */
int read_clib_file(char *clib_file)
{
    static FILE *ofp;
    clib_error_t *error = 0;
    int i;
    elog_main_t *em = &elog_main;
    double starttime, delta;

    vec_free(em->events);
    vec_free(em->event_types);
    if (the_trackdef_hash)
        hash_free(the_trackdef_hash);

    the_trackdef_hash = hash_create (0, sizeof (uword));

    error = elog_read_file (&elog_main, clib_file);

    if (error) {
        fformat(stderr, "%U", format_clib_error, error);
        return (1);
    }

    if (ofp == NULL) {
        ofp = fdopen(2, "w");
        if (ofp == NULL) {
            fprintf(stderr, "Couldn't fdopen(2)?\n");
            exit(1);
        }
    }

    em = &elog_main;

    for (i = 0; i < vec_len (em->tracks); i++) {
        u32 track_code;
        bound_track_t * btp;
        elog_track_t * t;
        uword * p;
        int track_strlen;

        t = &em->tracks[i];
        track_code = i;
        p = hash_get(the_trackdef_hash, track_code);
        if (p) {
            fprintf(ofp, "track %d redefined, retain first definition\n",
                    track_code);
            continue;
        }
        vec_add2(bound_tracks, btp, 1);
        btp->track = track_code;
        btp->track_str = (u8 *) t->name;
        hash_set(the_trackdef_hash, track_code, btp - bound_tracks);

        track_strlen = strlen((char *)btp->track_str);
        if (track_strlen > widest_track_format)
            widest_track_format = track_strlen;
    }

    initialize_events();

    for (i = 0; i < vec_len (em->event_types); i++) {
        elog_event_type_t *ep;
        u8 *tmp;

        ep = vec_elt_at_index(em->event_types, i);
        tmp = (u8 *) vec_dup(ep->format);
        vec_add1(tmp,0);
        add_event_from_clib_file (ep->type_index_plus_one, (char *) tmp, i);
        vec_free(tmp);
    }

    finalize_events();

    cpel_event_init(vec_len(em->events));

    starttime = em->events[0].time;

    for (i = 0; i < vec_len (em->events); i++) {
        elog_event_t *ep;

        ep = vec_elt_at_index(em->events, i);

        delta = ep->time - starttime;

        add_clib_event (delta, ep->track, ep->type + 1, i);
    }

    cpel_event_finalize();

    set_pid_ax_width(8*widest_track_format);

    return(0);
}

unsigned int vl(void *a)
{
    return vec_len (a);
}
