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
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include "cpel.h"
#include <math.h>

char *time_format = "%.03d:%.02d:%.02d:%.03d:%.03d ";
static char version[] = "cpelatency 2.0";

#define USEC_PER_MS 1000LL
#define USEC_PER_SECOND (1000*USEC_PER_MS)
#define USEC_PER_MINUTE (60*USEC_PER_SECOND)
#define USEC_PER_HOUR (60*USEC_PER_MINUTE)

uword *the_strtab_hash; /* (name, base-VA) hash of all string tables */
uword *the_evtdef_hash; /* (event-id, event-definition) hash */
uword *the_trackdef_hash;      /* (track-id, track-definition) hash */
uword *the_pidtid_hash;         /* ("pid:xxx tid:yy", track-definition) hash */

f64 ticks_per_us;
u32 start_event_code = 2;       /* default: XR thread ready event */
u32 end_event_code = 1;         /* default: XR thread running event */
int exclude_kernel_from_summary_stats=1;
int summary_stats_only;
int scatterplot;
u8 *name_filter;
int have_trackdefs;

typedef enum {
    SORT_MAX_TIME=1,
    SORT_MAX_OCCURRENCES,
    SORT_NAME,
} sort_t;

sort_t sort_type = SORT_MAX_TIME;

int widest_name_format=5;
int widest_track_format=20;

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
    u64 state_start_ticks;
    u64 *ticks_in_state; /* vector of state occurrences */
    f64  mean_ticks_in_state;
    f64  variance_ticks_in_state;
    f64  total_ticks_in_state;
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
    int thislen;

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

            for (j = 0; j < strlen((char *) bp->datum_str); j++) {
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

        thislen = strlen((char *) bp->event_str);
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
    u8 *pidstr;
    u8 *pidtid_str;
    u8 *cp;
    int tid, pid;

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
            fprintf(stderr, "track %d redefined, retain first definition\n",
                    track_code);
            continue;
        }
        vec_add2(bound_tracks, btp, 1);
        btp->track = track_code;
        btp->track_str = this_strtab + ntohl(tp->track_format);
        hash_set(the_trackdef_hash, track_code, btp - bound_tracks);

        if (verbose) {
            fprintf(stderr, "adding track '%s'\n", btp->track_str);
        }

        thislen = strlen((char *) btp->track_str);
        if (thislen > widest_track_format)
            widest_track_format = thislen;

        /* convert track_str "eth_server t11(20498)" to "pid:20498 tid:11" */
        cp = btp->track_str;
        while (*cp && *cp != '(')
            cp++;
        if (!*cp) {
            fprintf(stderr, "error canonicalizing '%s'\n", btp->track_str);
            goto out;
        }
        pidstr = cp+1;          /* remember location of PID */

        while (cp > btp->track_str && *cp != 't')
            cp--;

        if (cp == btp->track_str) {
            fprintf(stderr, "error canonicalizing '%s'\n", btp->track_str);
            goto out;
        }
        tid = atol((char *)(cp+1));
        pid = atol((char *) pidstr);
        pidtid_str = format(0, "pid:%d tid:%d", pid, tid);
        vec_add1(pidtid_str, 0);

        /* 
         * Note: duplicates are possible due to thread create / 
         * thread destroy operations.
         */
        p = hash_get_mem(the_pidtid_hash, pidtid_str);
        if (p) {
            vec_free(pidtid_str);
            goto out;
        }
        hash_set_mem(the_pidtid_hash, pidtid_str, btp - bound_tracks);

    out:
        tp++;
    }
    have_trackdefs = 1;
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
    int nevents;
    int i;
    uword *p;
    event_entry_t *ep;
    u64 now;
    u32 time0, time1;
    u32 track_code;
    u8 *this_strtab;
    u64 ticks_in_state;
    bound_track_t *btp;
    bound_track_t *state_track=0;
    u8 *pidtid_str;
    u8 *pidtid_dup;
    u8 *ecp;
    u32 event_code;

    eh = (event_section_header_t *)(sh+1);
    nevents = ntohl(eh->number_of_events);
    ticks_per_us = ((double)ntohl(eh->clock_ticks_per_second)) / 1e6;

    if (verbose) {
        fprintf(ofp, "%.3f ticks_per_us\n", ticks_per_us);
    }

    ep = (event_entry_t *)(eh+1);

    p = hash_get_mem(the_strtab_hash, eh->string_table_name);
    if (!p) {
        fprintf(ofp, "Fatal: couldn't find string table\n");
        return(1);
    }
    this_strtab = (u8 *)p[0];

    /*
     * Some logger implementation that doesn't produce
     * trackdef sections, synthesize the bound_tracks vector
     */
    if (!have_trackdefs) {
        for (i = 0; i < nevents; i++) {
            track_code = ntohl(ep->track);
            pidtid_dup = format(0, "%d", track_code);
            vec_add1(pidtid_dup, 0);
            p = hash_get_mem(the_pidtid_hash, pidtid_dup);
            if (!p) {
                vec_add2(bound_tracks, btp, 1);
                btp->track = track_code;
                btp->track_str = pidtid_dup;
                hash_set(the_trackdef_hash, track_code, btp - bound_tracks);
                hash_set_mem(the_pidtid_hash, pidtid_dup, btp - bound_tracks);
            } else {
                vec_free(pidtid_dup);
            }
            ep++;
        }
    }

    ep = (event_entry_t *)(eh+1);

    for (i = 0; i < nevents; i++) {
        time0 = ntohl (ep->time[0]);
        time1 = ntohl (ep->time[1]);

        now = (((u64) time0)<<32) | time1;
        
        event_code = ntohl(ep->event_code);

        /* Find the corresponding track via the pidtid hash table */
        if (event_code == start_event_code || event_code == end_event_code) {
            if (have_trackdefs) {
                pidtid_str = this_strtab + ntohl(ep->event_datum);
                pidtid_dup = format(0, (char *) pidtid_str);
                vec_add1(pidtid_dup, 0);
                ecp = &pidtid_dup[vec_len(pidtid_dup)-1];
                while (*--ecp == ' ')
                    *ecp = 0;
            } else {
                pidtid_dup = format(0, "%d", ntohl(ep->track));
                vec_add1(pidtid_dup, 0);
            }

            p = hash_get_mem(the_pidtid_hash, pidtid_dup);
            if (!p) {
                fprintf(stderr, "warning: couldn't find '%s'\n",
                        pidtid_dup);
                vec_free(pidtid_dup);
                ep++;
                continue;
            }
            state_track = &bound_tracks[p[0]];
        }
        /* Found the start-event code ? */
        if (event_code == start_event_code) {
            state_track->state_start_ticks = now;
        } else if (event_code == end_event_code) {
            /*
             * Add a ticks-in-state record, unless
             * e.g. the log started with the exit event
             */
            if (state_track->state_start_ticks) {
                ticks_in_state = now - state_track->state_start_ticks;
                vec_add1(state_track->ticks_in_state, ticks_in_state);
                state_track->state_start_ticks = 0;
            }
            /* Otherwise, nothing */
        }
        ep++;
    }
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
        fprintf(ofp, "CPEL file: %s-endian, version %d\n",
                ((fh->endian_version & CPEL_FILE_LITTLE_ENDIAN) ? 
                 "little" : "big"), 
                fh->endian_version & CPEL_FILE_VERSION_MASK);

        file_time = ntohl(fh->file_date);
        
        fprintf(ofp, "File created %s", ctime(&file_time));
        fprintf(ofp, "File has %d sections\n", 
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

void compute_state_statistics(int verbose, FILE *ofp)
{
    int i, j;
    bound_track_t *bp;
    f64 fticks;

    /* Across the bound tracks */
    for (i = 0; i < vec_len(bound_tracks); i++) {
        bp = &bound_tracks[i];
        bp->mean_ticks_in_state = 0.0;
        bp->variance_ticks_in_state = 0.0;
        bp->total_ticks_in_state = 0.0;
        for (j = 0; j < vec_len(bp->ticks_in_state); j++) {
            bp->total_ticks_in_state += (f64) bp->ticks_in_state[j];
        }
        /* Compute mean */
        if (vec_len(bp->ticks_in_state)) {
            bp->mean_ticks_in_state = bp->total_ticks_in_state / 
                ((f64) vec_len(bp->ticks_in_state));
        }
        /* Accumulate sum: (Xi-Xbar)**2 */
        for (j = 0; j < vec_len(bp->ticks_in_state); j++) {
            fticks = bp->ticks_in_state[j];
            bp->variance_ticks_in_state += 
                (fticks - bp->mean_ticks_in_state)*
                (fticks - bp->mean_ticks_in_state);
        }
        /* Compute s**2, the unbiased estimator of sigma**2 */
        if (vec_len(bp->ticks_in_state) > 1) {
            bp->variance_ticks_in_state /= (f64) 
                (vec_len(bp->ticks_in_state)-1);
        }
    }
}

int track_compare_max (const void *arg1, const void *arg2)
{
    bound_track_t *a1 = (bound_track_t *)arg1;
    bound_track_t *a2 = (bound_track_t *)arg2;
    f64 v1, v2;

    v1 = a1->total_ticks_in_state;
    v2 = a2->total_ticks_in_state;
    
    if (v1 < v2)
        return (1);
    else if (v1 == v2)
        return (0);
    else return (-1);
}

int track_compare_occurrences (const void *arg1, const void *arg2)
{
    bound_track_t *a1 = (bound_track_t *)arg1;
    bound_track_t *a2 = (bound_track_t *)arg2;
    f64 v1, v2;

    v1 = (f64) vec_len(a1->ticks_in_state);
    v2 = (f64) vec_len(a2->ticks_in_state);
    
    if (v1 < v2)
        return (1);
    else if (v1 == v2)
        return (0);
    else return (-1);
}

int track_compare_name (const void *arg1, const void *arg2)
{
    bound_track_t *a1 = (bound_track_t *)arg1;
    bound_track_t *a2 = (bound_track_t *)arg2;

    return (strcmp((char *)(a1->track_str), (char *)(a2->track_str)));
}

void sort_state_statistics(sort_t type, FILE *ofp)
{
    int (*compare)(const void *, const void *) = 0;

    if (summary_stats_only)
        return;

    switch(type) {
    case SORT_MAX_TIME:
        fprintf(ofp, "Results sorted by max time in state.\n\n");
        compare = track_compare_max;
        break;

    case SORT_MAX_OCCURRENCES:
        fprintf(ofp, "Results sorted by max occurrences of state.\n\n");
        compare = track_compare_occurrences;
        break;

    case SORT_NAME:
        compare = track_compare_name;
        fprintf(ofp, "Results sorted by process name, thread ID, PID\n\n");
        break;

    default:
        fatal("sort type not set?");
    }
    
    qsort (bound_tracks, vec_len(bound_tracks), 
           sizeof (bound_track_t), compare);    
}

void print_state_statistics(int verbose, FILE *ofp)
{
    int i,j;
    u8 *trackpad;
    bound_track_t *bp;
    f64 total_time = 0.0;
    f64 total_switches = 0.0;

    trackpad = format(0, "%%-%ds ", widest_track_format);
    vec_add1(trackpad, 0);

    if (!summary_stats_only) {
        fprintf(ofp, (char *)trackpad, "ProcName Thread(PID)");
        fprintf(ofp, "  Mean(us)     Stdev(us)   Total(us)      N\n");
    }
        
    for (i = 0; i < vec_len(bound_tracks); i++) {
        bp = &bound_tracks[i];
        if (bp->mean_ticks_in_state == 0.0)
            continue;

        if (name_filter &&
            strncmp((char *)bp->track_str, (char *)name_filter, 
                    strlen((char *)name_filter)))
            continue;

        /*
         * Exclude kernel threads (e.g. idle thread) from
         * state statistics 
         */
        if (exclude_kernel_from_summary_stats && 
            !strncmp((char *) bp->track_str, "kernel ", 7))
            continue;

        total_switches += (f64) vec_len(bp->ticks_in_state);
        
        if (!summary_stats_only) {
            fprintf(ofp, (char *) trackpad, bp->track_str);
            fprintf(ofp, "%10.3f +- %10.3f", 
                    bp->mean_ticks_in_state / ticks_per_us,
                    sqrt(bp->variance_ticks_in_state) 
                    / ticks_per_us);
            fprintf(ofp, "%12.3f", 
                    bp->total_ticks_in_state / ticks_per_us);
            fprintf(ofp, "%8d\n", vec_len(bp->ticks_in_state));
        }

        if (scatterplot) {
            for (j = 0; j < vec_len(bp->ticks_in_state); j++) {
                fprintf(ofp, "%.3f\n", 
                        (f64)bp->ticks_in_state[j] / ticks_per_us);
            }
        }

        total_time += bp->total_ticks_in_state;
    }
    
    if (!summary_stats_only)
        fprintf(ofp, "\n");
    fprintf(ofp, "Note: the following statistics %s kernel-thread activity.\n",
            exclude_kernel_from_summary_stats ? "exclude" : "include");
    if (name_filter)
        fprintf(ofp, 
                "Note: only pid/proc/threads matching '%s' are included.\n",
                name_filter);

    fprintf(ofp, 
      "Total time in state: %10.3f (us), Total state occurrences: %.0f\n", 
            total_time / ticks_per_us, total_switches);
    fprintf(ofp, "Average time in state: %10.3f (us)\n",
            (total_time / total_switches) / ticks_per_us);
    fprintf(ofp, "State start event: %d, state end event: %d\n",
            start_event_code, end_event_code);
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
            verbose++;
            continue;
        }
        if (!strncmp(argv[curarg], "--scatterplot", 4)) {
            curarg++;
            scatterplot=1;
            continue;
        }

        if (!strncmp(argv[curarg], "--start-event", 4)) {
            curarg++;
            if (curarg < argc) {
                start_event_code = atol(argv[curarg]);
                curarg ++;
                continue;
            }
            fatal("Missing integer after --start-event\n");
        }
        if (!strncmp(argv[curarg], "--end-event", 4)) {
            curarg++;
            if (curarg < argc) {
                end_event_code = atol(argv[curarg]);
                curarg ++;
                continue;
            }
            fatal("Missing integer after --end-event\n");
        }
        if (!strncmp(argv[curarg], "--max-time-sort", 7)) {
            sort_type = SORT_MAX_TIME;
            curarg++;
            continue;
        }
        if (!strncmp(argv[curarg], "--max-occurrence-sort", 7)) {
            sort_type = SORT_MAX_OCCURRENCES;
            curarg++;
            continue;
        }
        if (!strncmp(argv[curarg], "--name-sort", 3)) {
            sort_type = SORT_NAME;
            curarg++;
            continue;
        }
        if (!strncmp(argv[curarg], "--kernel-included", 3)) {
            exclude_kernel_from_summary_stats = 0;
            curarg++;
            continue;
        }
        if (!strncmp(argv[curarg], "--summary", 3)) {
            summary_stats_only=1;
            curarg++;
            continue;
        }
        if (!strncmp(argv[curarg], "--filter", 3)) {
            curarg ++;
            if (curarg < argc) {
                name_filter = (u8 *) argv[curarg];
                curarg ++;
                continue;
            }
            fatal("Missing filter string after --filter\n");
        }
        

    usage:
        fprintf(stderr, 
          "cpelatency --input-file <filename> [--output-file <filename>]\n");
        fprintf(stderr, 
          "          [--start-event <decimal>] [--verbose]\n");
        fprintf(stderr, 
          "          [--end-event <decimal>]\n");
        fprintf(stderr, 
          "          [--max-time-sort(default) | --max-occurrence-sort |\n");

        fprintf(stderr, 
          "           --name-sort-sort] [--kernel-included]\n");

        fprintf(stderr, 
          "          [--summary-stats-only] [--scatterplot]\n");

        fprintf(stderr, "%s\n", version);
        exit(1);
    }

    if (cpel_file == 0)
        goto usage;

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
    the_pidtid_hash = hash_create_string (0, sizeof(uword));

    if (cpel_dump((u8 *)cpel, verbose, ofp)) {
        if (outputfile)
            unlink(outputfile);
    }

    compute_state_statistics(verbose, ofp);
    sort_state_statistics(sort_type, ofp);
    print_state_statistics(verbose, ofp);

    fclose(ofp);
    return(0);
}
