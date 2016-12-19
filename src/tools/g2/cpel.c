/* 
 *------------------------------------------------------------------
 * Copyright (c) 2005-2016 Cisco and/or its affiliates.
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
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include "cpel.h"
#include "g2.h"

typedef struct bound_event_ {
    u32 event_code;
    u8  *event_str;
    u8  *datum_str;
} bound_event_t;

bound_event_t *bound_events;

int widest_track_format=8;

typedef struct bound_track_ {
    u32 track;
    u8  *track_str;
} bound_track_t;

bound_track_t *bound_tracks;

uword *the_strtab_hash; /* (name, base-VA) hash of all string tables */
uword *the_evtdef_hash; /* (event-id, event-definition) hash */
uword *the_trackdef_hash; /* (track-id, track-definition) hash */
u8 *event_strtab;         /* event string-table */

void fatal(char *s)
{
    fprintf(stderr, "%s", s);
    exit(1);
}

typedef enum {
    PASS1=1,
    PASS2=2,
} pass_t;

typedef struct {
    int (*pass1)(cpel_section_header_t *, int, FILE *);
    int (*pass2)(cpel_section_header_t *, int, FILE *);
} section_processor_t;

int bad_section(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    fprintf(ofp, "Bad (type 0) section, skipped...\n");
    return(0);
}

int noop_pass(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    return(0);
}

int strtab_pass1(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    uword *p;
    u8 *strtab_data_area = (u8 *)(sh+1);
    
    /* Multiple string tables with the same name are Bad... */
    p = hash_get_mem(the_strtab_hash, strtab_data_area);
    if (p) {
        fprintf(ofp, "Duplicate string table name %s", strtab_data_area);
    }
    /*
     * Looks funny, but we really do want key = first string in the
     * table, value = address(first string in the table) 
     */
    hash_set_mem(the_strtab_hash, strtab_data_area, strtab_data_area);
    if (verbose) {
        fprintf(ofp, "String Table %s\n", strtab_data_area);
    }
    return(0);
}

int evtdef_pass1(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    int i, nevents;
    event_definition_section_header_t *edh;
    event_definition_t *ep;
    u8 *this_strtab;
    u32 event_code;
    uword *p;
    bound_event_t *bp;

    edh = (event_definition_section_header_t *)(sh+1);
    nevents = ntohl(edh->number_of_event_definitions);
    
    if (verbose) {
        fprintf(ofp, "Event Definition Section: %d definitions\n",
                nevents);
    }

    p = hash_get_mem(the_strtab_hash, edh->string_table_name);
    if (!p) {
        fprintf(ofp, "Fatal: couldn't find string table\n");
        return(1);
    }
    this_strtab = (u8 *)p[0];

    initialize_events();

    ep = (event_definition_t *)(edh+1);
    
    for (i = 0; i < nevents; i++) {
        event_code = ntohl(ep->event);
        p = hash_get(the_evtdef_hash, event_code);
        if (p) {
            fprintf(ofp, "Event %d redefined, retain first definition\n",
                    event_code);
            continue;
        }
        vec_add2(bound_events, bp, 1);
        bp->event_code = event_code;
        bp->event_str = this_strtab + ntohl(ep->event_format);
        bp->datum_str = this_strtab + ntohl(ep->datum_format);
        hash_set(the_evtdef_hash, event_code, bp - bound_events);

        add_event_from_cpel_file(event_code, (char *) bp->event_str, 
                                 (char *)bp->datum_str);

        ep++;
    }

    finalize_events();
    return (0);
}

int trackdef_pass1(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    int i, nevents;
    track_definition_section_header_t *tdh;
    track_definition_t *tp;
    u8 *this_strtab;
    u32 track_code;
    uword *p;
    bound_track_t *btp;
    int track_strlen;

    tdh = (track_definition_section_header_t *)(sh+1);
    nevents = ntohl(tdh->number_of_track_definitions);
    
    if (verbose) {
        fprintf(ofp, "Track Definition Section: %d definitions\n",
                nevents);
    }

    p = hash_get_mem(the_strtab_hash, tdh->string_table_name);
    if (!p) {
        fprintf(ofp, "Fatal: couldn't find string table\n");
        return(1);
    }
    this_strtab = (u8 *)p[0];

    tp = (track_definition_t *)(tdh+1);
    
    for (i = 0; i < nevents; i++) {
        track_code = ntohl(tp->track);
        p = hash_get(the_trackdef_hash, track_code);
        if (p) {
            fprintf(ofp, "track %d redefined, retain first definition\n",
                    track_code);
            continue;
        }
        vec_add2(bound_tracks, btp, 1);
        btp->track = track_code;
        btp->track_str = this_strtab + ntohl(tp->track_format);
        hash_set(the_trackdef_hash, track_code, btp - bound_tracks);

        track_strlen = strlen((char *)btp->track_str);
        if (track_strlen > widest_track_format)
            widest_track_format = track_strlen;
        tp++;
    }
    return (0);
}

int unsupported_pass (cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    if (verbose) {
        fprintf(ofp, "Unsupported type %d section\n",
                ntohl(sh->section_type));
    }
    return(0);
}

int event_pass2(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    event_section_header_t *eh;
    u32 event_code, track_code, datum;
    u64 starttime = ~0ULL;
    int nevents;
    int i;
    event_entry_t *ep;
    u64 now;
    u64 delta;
    u32 time0, time1;
    double d;
    uword *p;

    eh = (event_section_header_t *)(sh+1);
    nevents = ntohl(eh->number_of_events);
    ticks_per_ns = ntohl(eh->clock_ticks_per_second)/1e9;
    ep = (event_entry_t *)(eh+1);

    p = hash_get_mem(the_strtab_hash, eh->string_table_name);
    if (!p) {
        fprintf(ofp, "Fatal: couldn't find string table\n");
        return(1);
    }
    event_strtab = (u8 *)p[0];

    cpel_event_init(nevents);

    for (i = 0; i < nevents; i++) {
        time0 = ntohl (ep->time[0]);
        time1 = ntohl (ep->time[1]);

        now = (((u64) time0)<<32) | time1;
        
        /* Convert from bus ticks to usec */
        d = now;
        d /= ticks_per_ns;

        now = d;

        if (starttime == ~0ULL)
            starttime = now;
        
        delta = now - starttime;

        /* Delta = time since first event, in usec */
        event_code = ntohl(ep->event_code);
        track_code = ntohl(ep->track);
        datum = ntohl(ep->event_datum);

        add_cpel_event(delta, track_code, event_code, datum);

        ep++;
    }
    cpel_event_finalize();
    return(0);
}

char *strtab_ref(unsigned long datum)
{
    return ((char *)(event_strtab + datum));
}

/* 
 * Note: If necessary, add passes / columns to this table to 
 * handle section order dependencies.
 */

section_processor_t processors[CPEL_NUM_SECTION_TYPES+1] =
{
    {bad_section,	noop_pass}, 		/* type 0 -- f**ked */
    {strtab_pass1, 	noop_pass}, 		/* type 1 -- STRTAB */
    {unsupported_pass,  noop_pass}, 		/* type 2 -- SYMTAB */
    {evtdef_pass1,      noop_pass},             /* type 3 -- EVTDEF */
    {trackdef_pass1,    noop_pass},		/* type 4 -- TRACKDEF */
    {noop_pass,         event_pass2},           /* type 5 -- EVENTS */
};


int process_section(cpel_section_header_t *sh, int verbose, FILE *ofp,
                    pass_t pass)
{
    u32 type;
    type = ntohl(sh->section_type);
    int rv;
    int (*fp)(cpel_section_header_t *, int, FILE *);

    if (type > CPEL_NUM_SECTION_TYPES) {
        fprintf(stderr, "Unknown section type %d\n", type);
        return(1);
    }
    switch(pass) {
    case PASS1:
        fp = processors[type].pass1;
        break;

    case PASS2:
        fp = processors[type].pass2;
        break;
        
    default:
        fprintf(stderr, "Unknown pass %d\n", pass);
        return(1);
    }

    rv = (*fp)(sh, verbose, ofp);

    return(rv);
}

int cpel_dump_file_header(cpel_file_header_t *fh, int verbose, FILE *ofp)
{
    time_t file_time;

    if (verbose) {
        fprintf(ofp, "CPEL file: %s-endian, version %d\n",
                ((fh->endian_version & CPEL_FILE_LITTLE_ENDIAN) ? 
                 "little" : "big"), 
                fh->endian_version & CPEL_FILE_VERSION_MASK);

        file_time = ntohl(fh->file_date);

        fprintf(ofp, "File created %s", ctime(&file_time));
    }

    return(0);
}


int cpel_process(u8 *cpel, int verbose, FILE *ofp)
{
    cpel_file_header_t *fh;
    cpel_section_header_t *sh;
    u16 nsections;
    u32 section_size;
    int i;

    /* First, the file header */
    fh = (cpel_file_header_t *)cpel;
    if (fh->endian_version != CPEL_FILE_VERSION) {
        if (fh->endian_version & CPEL_FILE_LITTLE_ENDIAN) {
            fprintf(stderr, "Little endian data format not supported\n");
            return(1);
        }
        fprintf(stderr, "Unsupported file version 0x%x\n", 
                fh->endian_version);
        return(1);
    }
    cpel_dump_file_header(fh, verbose, ofp);
    nsections = ntohs(fh->nsections);

    /*
     * Take two passes through the file. PASS1 builds
     * data structures, PASS2 actually dumps the file.
     * Just in case the sections are in an unobvious order.
     */
    sh = (cpel_section_header_t *)(fh+1);
    for (i = 0; i < nsections; i++) {
        section_size = ntohl(sh->data_length);

        if(verbose) {
            fprintf(ofp, "Section type %d, size %d\n", ntohl(sh->section_type),
                    section_size);
        }

        if(process_section(sh, verbose, ofp, PASS1))
            return(1);

        sh++;
        sh = (cpel_section_header_t *)(((u8 *)sh)+section_size);
    }

    sh = (cpel_section_header_t *)(fh+1);
    for (i = 0; i < nsections; i++) {
        if(process_section(sh, verbose, ofp, PASS2))
            return(1);
        section_size = ntohl(sh->data_length);
        sh++;
        sh = (cpel_section_header_t *)(((u8 *)sh)+section_size);
    }


    return(0);
}

/*
 * read_cpel_file
 */
int read_cpel_file(char *cpel_file)
{
    int verbose = 0;
    int rv;
    static u8 *cpel;
    static unsigned long size;
    static FILE *ofp;

    if (cpel) {
        unmapfile((char *)cpel, size);
        hash_free(the_strtab_hash);
        the_strtab_hash = 0;
        hash_free(the_evtdef_hash);
        the_evtdef_hash = 0;
        hash_free(the_trackdef_hash);
        the_trackdef_hash = 0;
    }

    cpel = (u8 *)mapfile((char *)cpel_file, &size);
    if (cpel == 0) {
        fprintf(stderr, "Couldn't map %s...\n", cpel_file);
        exit(1);
    }

    if (ofp == NULL) {
        ofp = fdopen(2, "w");
        if (ofp == NULL) {
            fprintf(stderr, "Couldn't fdopen(2)?\n");
            exit(1);
        }
    }

    the_strtab_hash = hash_create_string (0, sizeof (uword));
    the_evtdef_hash = hash_create (0, sizeof (uword));
    the_trackdef_hash = hash_create (0, sizeof (uword));

    rv = cpel_process(cpel, verbose, ofp);

    set_pid_ax_width(8*widest_track_format);

    return(rv);
}

static bound_track_t generic_hex_track = {0, (u8 *) "0x%08x"};
static bound_track_t generic_decimal_track = {0, (u8 *) "%8ld"};

/*
 * get_track_label
 */
char *get_track_label(unsigned long track)
{
    uword *p;
    bound_track_t *tp;

    p = hash_get(the_trackdef_hash, track);
    if (p) {
        tp = &bound_tracks[p[0]];
    } else {
        if (track > 65535) 
            tp = &generic_hex_track;
        else
            tp = &generic_decimal_track;
    }
    return((char *)tp->track_str);
}
