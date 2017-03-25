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
#include <vppinfra/mem.h>
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include "cpel.h"

char *time_format = "%.03d:%.02d:%.02d:%.03d:%.03d ";
static char version[] = "cpeldump 2.0";

#define USEC_PER_MS 1000LL
#define USEC_PER_SECOND (1000*USEC_PER_MS)
#define USEC_PER_MINUTE (60*USEC_PER_SECOND)
#define USEC_PER_HOUR (60*USEC_PER_MINUTE)

uword *the_strtab_hash; /* (name, base-VA) hash of all string tables */
uword *the_evtdef_hash; /* (event-id, event-definition) hash */
uword *the_trackdef_hash; /* (track-id, track-definition) hash */

int widest_name_format=5;
int widest_track_format=5;

typedef struct bound_event_ {
    u32 event_code;
    u8  *event_str;
    u8  *datum_str;
    u32  is_strtab_ref;
} bound_event_t;

bound_event_t *bound_events;

typedef struct bound_track_ {
    u32 track;
    u8  *track_str;
} bound_track_t;

bound_track_t *bound_tracks;

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
        fprintf(stderr, "String Table %s\n", strtab_data_area);
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
    int thislen;

    edh = (event_definition_section_header_t *)(sh+1);
    nevents = ntohl(edh->number_of_event_definitions);
    
    if (verbose) {
        fprintf(stderr, "Event Definition Section: %d definitions\n",
                nevents);
    }

    p = hash_get_mem(the_strtab_hash, edh->string_table_name);
    if (!p) {
        fprintf(ofp, "Fatal: couldn't find string table\n");
        return(1);
    }
    this_strtab = (u8 *)p[0];

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
        bp->is_strtab_ref = 0;
        /* Decide if the datum format is a %s format => strtab reference */
        {
            int j;
            int seen_percent=0;

            for (j = 0; j < strlen((char *)bp->datum_str); j++) {
                if (bp->datum_str[j] == '%'){
                    seen_percent=1;
                    continue;
                }
                if (seen_percent && bp->datum_str[j] == 's') {
                    bp->is_strtab_ref = 1;
                }
            }
        }
        
        hash_set(the_evtdef_hash, event_code, bp - bound_events);

        thislen = strlen((char *)bp->event_str);
        if (thislen > widest_name_format)
            widest_name_format = thislen;

        ep++;
    }
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
    int thislen;

    tdh = (track_definition_section_header_t *)(sh+1);
    nevents = ntohl(tdh->number_of_track_definitions);
    
    if (verbose) {
        fprintf(stderr, "Track Definition Section: %d definitions\n",
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

        thislen = strlen((char *)btp->track_str);
        if (thislen > widest_track_format)
            widest_track_format = thislen;
        tp++;
    }
    return (0);
}

int unsupported_pass (cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    if (verbose) {
        fprintf(stderr, "Unsupported type %d section\n",
                ntohl(sh->section_type));
    }
    return(0);
}

int event_pass2(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    event_section_header_t *eh;
    f64 ticks_per_us;
    u32 event_code, track_code;
    u64 starttime = 0xFFFFFFFFFFFFFFFFULL;
    int nevents;
    int i;
    uword *p;
    event_entry_t *ep;
    u64 now;
    u64 delta;
    u32 hours, minutes, seconds, msec, usec;
    u32 time0, time1;
    double d;
    bound_event_t *bp;
    bound_event_t generic_event;
    bound_track_t *tp=0;
    bound_track_t generic_track;
    u32 last_track_code;
    u8 *s, *evtpad, *trackpad;
    u8 *this_strtab;

    generic_event.event_str = (u8 *)"%d";
    generic_event.datum_str = (u8 *)"0x%08x";
    generic_event.is_strtab_ref = 0;

    generic_track.track_str = (u8 *)"%d";
    last_track_code = 0xdeadbeef;

    eh = (event_section_header_t *)(sh+1);
    nevents = ntohl(eh->number_of_events);
    ticks_per_us = ((double)ntohl(eh->clock_ticks_per_second)) / 1e6;

    if (verbose) {
        fprintf(stderr, "Event section: %d events, %.3f ticks_per_us\n", 
                nevents, ticks_per_us);
    }

    ep = (event_entry_t *)(eh+1);

    p = hash_get_mem(the_strtab_hash, eh->string_table_name);
    if (!p) {
        fprintf(ofp, "Fatal: couldn't find string table\n");
        return(1);
    }
    this_strtab = (u8 *)p[0];

    evtpad = format(0, "%%-%ds ", widest_name_format);
    vec_add1(evtpad, 0);
    trackpad = format(0, "%%-%ds ", widest_track_format);
    vec_add1(trackpad, 0);

    for (i = 0; i < nevents; i++) {
        time0 = ntohl (ep->time[0]);
        time1 = ntohl (ep->time[1]);

        now = (((u64) time0)<<32) | time1;
        
        /* Convert from bus ticks to usec */
        d = now;
        d /= ticks_per_us;

        now = d;

        if (starttime == 0xFFFFFFFFFFFFFFFFULL)
            starttime = now;
        
        delta = now - starttime;

        /* Delta = time since first event, in usec */

        hours = delta / USEC_PER_HOUR;
        if (hours) 
            delta -= ((u64) hours * USEC_PER_HOUR);
        minutes = delta / USEC_PER_MINUTE;
        if (minutes)
            delta -= ((u64) minutes * USEC_PER_MINUTE);
        seconds = delta / USEC_PER_SECOND;
        if (seconds)
            delta -= ((u64) seconds * USEC_PER_SECOND);
        msec = delta / USEC_PER_MS;
        if (msec)
            delta -= ((u64) msec * USEC_PER_MS);

        usec = delta;

        /* Output the timestamp */
        fprintf(ofp, time_format, hours, minutes, seconds, msec, usec);

        /* output the track */
        track_code = ntohl(ep->track);

        if (track_code != last_track_code) {
            p = hash_get(the_trackdef_hash, track_code);
            if (p) {
                tp = &bound_tracks[p[0]];
            } else {
                tp = &generic_track;
            }
        }
        s = format(0, (char *)tp->track_str, track_code);
        vec_add1(s, 0);
        fprintf(ofp, (char *)trackpad, s);
        vec_free(s);

        /* output the event and datum */
        if (0 && verbose) {
            fprintf(stderr, "raw event code %d, raw event datum 0x%x\n",
                    ntohl(ep->event_code), ntohl(ep->event_datum));
        }

        event_code = ntohl(ep->event_code);
        p = hash_get(the_evtdef_hash, event_code);
        if (p) {
            bp = &bound_events[p[0]];
        } else {
            bp = &generic_event;
        }
        s = format(0, (char *)bp->event_str, ntohl(ep->event_code));
        vec_add1(s, 0);
        fprintf(ofp, (char *)evtpad, s);
        vec_free(s);
        if (bp->is_strtab_ref) {
            fprintf(ofp, (char *) bp->datum_str, 
                    &this_strtab[ntohl(ep->event_datum)]);
        } else {
            fprintf(ofp, (char *) bp->datum_str, ntohl(ep->event_datum));
        }
        fputs("\n", ofp);
        ep++;
    }
    vec_free(evtpad);
    vec_free(trackpad);
    return(0);
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
        fprintf(stderr, "CPEL file: %s-endian, version %d\n",
                ((fh->endian_version & CPEL_FILE_LITTLE_ENDIAN) ? 
                 "little" : "big"), 
                fh->endian_version & CPEL_FILE_VERSION_MASK);
        
        file_time = ntohl(fh->file_date);
        
        fprintf(stderr, "File created %s", ctime(&file_time));
        fprintf(stderr, "File has %d sections\n", 
                ntohs(fh->nsections));
    }

    return(0);
}


int cpel_dump(u8 *cpel, int verbose, FILE *ofp)
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
            fprintf(stderr, 
                    "Section type %d, size %d\n", ntohl(sh->section_type),
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


char *mapfile (char *file)
{
    struct stat statb;
    char *rv;
    int maphfile;
    size_t mapfsize;
    
    maphfile = open (file, O_RDONLY);

    if (maphfile < 0)
    {
        fprintf (stderr, "Couldn't read %s, skipping it...\n", file);
        return (NULL);
    }

    if (fstat (maphfile, &statb) < 0)
    {
        fprintf (stderr, "Couldn't get size of %s, skipping it...\n", file);
        return (NULL);
    }

    /* Don't try to mmap directories, FIFOs, semaphores, etc. */
    if (! (statb.st_mode & S_IFREG)) {
        fprintf (stderr, "%s is not a regular file, skipping it...\n", file);
        return (NULL);
    }

    mapfsize = statb.st_size;

    if (mapfsize < 3)
    {
        fprintf (stderr, "%s zero-length, skipping it...\n", file);
        close (maphfile);
        return (NULL);
    }

    rv = mmap (0, mapfsize, PROT_READ, MAP_SHARED, maphfile, 0);

    if (rv == 0)
    {
        fprintf (stderr, "%s problem mapping, I quit...\n", file);
        exit (-1);
    }
    close (maphfile);
    return (rv);
}

/*
 * main 
 */
int main (int argc, char **argv)
{
    char *cpel_file = 0;
    char *outputfile = 0;
    FILE *ofp;
    char *cpel;
    int verbose=0;
    int curarg=1;

    while (curarg < argc) {
        if (!strncmp(argv[curarg], "--input-file", 3)) {
            curarg++;
            if (curarg < argc) {
                cpel_file = argv[curarg];
                curarg++;
                continue;
            }
            fatal("Missing filename after --input-file\n");
        }
        if (!strncmp(argv[curarg], "--output-file", 3)) {
            curarg ++;
            if (curarg < argc) {
                outputfile = argv[curarg];
                curarg ++;
                continue;
            }
            fatal("Missing filename after --output-file\n");
        }
        if (!strncmp(argv[curarg], "--verbose", 3)) {
            curarg++;
            verbose = 1;
            continue;
        }

    usage:
        fprintf(stderr, 
          "cpeldump --input-file <filename> [--output-file <filename>]\n");
        fprintf(stderr, "%s\n", version);
        exit(1);
    }

    if (cpel_file == 0)
        goto usage;

    clib_mem_init (0, ((uword)3<<30));

    cpel = mapfile(cpel_file);
    if (cpel == 0) {
        fprintf(stderr, "Couldn't map %s...\n", cpel_file);
        exit(1);
    }

    if (!outputfile) {
        ofp = fdopen(1, "w");
        if (ofp == NULL) {
            fprintf(stderr, "Couldn't fdopen(1)?\n");
            exit(1);
        }
    } else {
        ofp = fopen(outputfile, "w");
        if (ofp == NULL) {
            fprintf(stderr, "Couldn't create %s...\n", outputfile);
            exit(1);
        }
    }

    the_strtab_hash = hash_create_string (0, sizeof (uword));
    the_evtdef_hash = hash_create (0, sizeof (uword));
    the_trackdef_hash = hash_create (0, sizeof (uword));

#ifdef TEST_TRACK_INFO
    {
        bound_track_t *btp;
        vec_add2(bound_tracks, btp, 1);
        btp->track = 0;
        btp->track_str = "cpu %d";
        hash_set(the_trackdef_hash, 0, btp - bound_tracks);
        hash_set(the_trackdef_hash, 1, btp - bound_tracks);
    }
#endif

    if (cpel_dump((u8 *)cpel, verbose, ofp)) {
        if (outputfile)
            unlink(outputfile);
    }

    fclose(ofp);
    return(0);
}
