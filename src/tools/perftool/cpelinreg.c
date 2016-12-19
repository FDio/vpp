/* 
 *------------------------------------------------------------------
 * Copyright (c) 2008-2016 Cisco and/or its affiliates.
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

/*
 * Search for O(N**2) functions bracketed by before/after
 * events. The "before" event's datum is used as a tag, e.g. which function
 * did we call that's strongly O(N).
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

FILE *g_ifp;
char *g_ifile;

typedef unsigned long long ulonglong;

void process_traces (void);
void record_instance (ulong tag, ulonglong time);
void report_actors (void);
void scatterplot_data(void);
int entry_event, exit_event;
int nokey;
char *version = "cpelinreg 2.0";
int model_these[10];
int model_index;
int summary_stats;
ulonglong first_start_time;
ulonglong last_end_time;
ulonglong total_time;
ulong scatterkey;
int inline_mokus;

typedef struct bound_track_ {
    u32 track_code;
    u32 *start_datum;
    u8  *dup_event;
    int state;
    u64 *start_time;
    u64 thread_timestamp;
    u64 time_thread_on_cpu;
} bound_track_t;

bound_track_t *bound_tracks;
uword *the_trackdef_hash;


#define MAXSTACK 128

typedef struct instance_ {
    struct instance_ *next;
    ulonglong time;
}instance_t;

typedef struct actor_ {
    struct actor_ *next;
    ulong key;
    struct instance_ *first;
    struct instance_ *last;
    double a;
    double b;
    double min;
    double max;
    double mean;
    double r;
    ulong ninst;
} actor_t;

#define NBUCKETS 1811

actor_t *hash[NBUCKETS];

actor_t *find_or_create_actor (ulong key)
{
    ulong bucket;
    actor_t *ap;
    u8 *mem;

    bucket = key % NBUCKETS;

    ap = hash[bucket];

    if (ap == NULL) {
        /* Ensure 8-byte alignment to avoid (double) alignment faults */
        mem = malloc(sizeof(*ap) + 4);
        if (((uword)(mem)) & 0x7)
            mem += 4;
        ap = (actor_t *)mem;

        if (ap == NULL) {
            fprintf (stderr, "out of memory...\n");
            exit (1);
        }
        ap->next = 0;
        ap->key = key;
        ap->first = 0;
        ap->last = 0;
        ap->a = 0.00;
        ap->b = 0.00;
        hash [bucket] = ap;
        return (ap);
    }
    
    while (ap) {
        if (ap->key == key)
            return (ap);
        ap = ap->next;
    }

    mem = malloc(sizeof(*ap)+4);
    if (((uword)(mem) & 0x7))
        mem += 4;
    ap = (actor_t *)mem;

    if (ap == NULL) {
        fprintf (stderr, "out of memory...\n");
        exit (1);
    }
    ap->key = key;
    ap->first = 0;
    ap->last = 0;
    ap->a = 0.00;
    ap->b = 0.00;

    ap->next = hash[bucket];
    hash[bucket] = ap;

    return (ap);
}

void record_instance (ulong key, ulonglong time)
{
    actor_t *ap;
    instance_t *ip;

    if (nokey)
        key = 0;

    ap = find_or_create_actor (key);

    ip = (instance_t *)malloc(sizeof(*ip));
    if (ip == NULL) {
        fprintf (stderr, "out of memory...\n");
        exit (1);
    }
    ip->time = time;
    ip->next = 0;

    if (ap->first == 0) {
        ap->first = ip;
        ap->last = ip;
        ap->ninst = 1;
    } else {
        ap->last->next = ip;
        ap->last = ip;
        ap->ninst++;
    }
}

#define NINSTANCE 200000

double x[NINSTANCE];
double y[NINSTANCE];

int actor_compare (const void *arg1, const void *arg2)
{
    double e10k1, e10k2;
    actor_t **a1 = (actor_t **)arg1;
    actor_t **a2 = (actor_t **)arg2;
    double ninst1, ninst2;

    ninst1 = ((double)((*a1)->ninst));
    ninst2 = ((double)((*a2)->ninst));
    
    e10k1 = ninst1 * ((*a1)->mean);
    e10k2 = ninst2 * ((*a2)->mean);

    if (e10k1 < e10k2)
        return (1);
    else if (e10k1 == e10k2)
        return (0);
    else
        return (-1);
}

void report_actors (void)
{
    int i;
    actor_t *ap;
    instance_t *ip;
    int nactors = 0;
    int ninstance;
    actor_t **actor_vector;
    double e10k;
    extern void linreg (double *x, double *y, int nitems, double *a, double *b,
                        double *minp, double *maxp, double *meanp, double *r);

    for (i = 0; i < NBUCKETS; i++) {
        ap = hash[i];
        if (ap == NULL)
            continue;
        while (ap) {
            nactors++;
            ninstance = 0;

            ip = ap->first;

            while (ip) {
                if (ninstance < NINSTANCE) {
                    x[ninstance] = ninstance;
                    y[ninstance] = ((double)ip->time);
                    ninstance++;
                }
                ip = ip->next;
            }
            if (ninstance > 1) {
#if DEBUG > 0
                int j;
                
                for (j = 0; j < ninstance; j++) {
                    printf("x[%d] = %10.2f, y[%d] = %10.2f\n",
                           j, x[j], j, y[j]);
                }
#endif                    
                
                linreg (x, y, ninstance, &ap->a, &ap->b, &ap->min,
                        &ap->max, &ap->mean, &ap->r);
            } else {
                ap->a = 0.00;
                ap->b = 0.00;
            }
            
            ap = ap->next;
        }
    }
            
    actor_vector = (actor_t **)malloc (nactors*sizeof(*actor_vector));
    nactors = 0;

    for (i = 0; i < NBUCKETS; i++) {
        ap = hash[i];
        if (ap == NULL)
            continue;
        while (ap) {
            if ((ap->a != 0.00) || (ap->b != 0.00)) {
                actor_vector[nactors++] = ap;
            }
            ap = ap->next;
        }
    }
        
    qsort (actor_vector, nactors, sizeof (actor_t *), actor_compare);

    if (summary_stats)
        printf("NInst       Offset       Slope    T(Ninst)         Min         Max         Avg   %%InstTime           R    Key");
    else
        printf("NInst       Offset       Slope    T(Ninst)    Key");

    for (i = 0; i < model_index; i++) {
        printf ("T @ %-8d ", model_these[i]);
    }

    printf ("\n");

    for (i = 0; i < nactors; i++) {
        int j;
        double ninst;
        double pcttot;
        ap = actor_vector[i];
        ninst = ap->ninst;

        e10k = ninst * (ap->a + ap->b*((ninst-1.0)/2.0));

        if (ap->ninst) {
            if (summary_stats) {
                pcttot = (e10k / ((double)total_time)) * 100.0;
                printf ("%6ld %11.2f %11.2f %11.2f %11.2f %11.2f %11.2f %11.2f %11.2f 0x%08lx ",
                        ap->ninst, ap->a, ap->b, e10k, ap->min,
                        ap->max, ap->mean, pcttot, ap->r, ap->key);
            }
            else
                printf ("%6ld %11.2f %11.2f %11.2f 0x%08lx ",
                        ap->ninst, ap->a, ap->b, e10k, ap->key);

            for (j = 0; j < model_index; j++) {
                ninst = model_these[j];
                e10k = ninst * (ap->a + ap->b*((ninst-1.0)/2.0));
                printf ("%10.2f ", e10k);
            }
            printf ("\n");
        }
    }
}

void scatterplot_data(void)
{
    actor_t *ap;
    int i;
    instance_t *ip;
    double time;
    int count=0;

    for (i = 0; i < NBUCKETS; i++) {
        ap = hash[i];
        if (ap == NULL)
            continue;
        while (ap) {
            if (ap->key == scatterkey){
                ip = ap->first;
                while (ip) {
                    time = ((double)ip->time);
                    printf ("%d\t%.0f\n", count++, time);
                    ip = ip->next;
                }
                return;
            }
            ap = ap->next;
        }
    }
}


void fatal(char *s)
{
    fprintf(stderr, "%s", s);
    fprintf(stderr, "\n");
    exit(1);
}

typedef enum {
    PASS1=1,
} pass_t;

typedef struct {
    int (*pass1)(cpel_section_header_t *, int, FILE *);
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

int unsupported_pass (cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    if (verbose) {
        fprintf(ofp, "Unsupported type %d section\n",
                ntohl(sh->section_type));
    }
    return(0);
}

int trackdef_pass(cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    int i, nevents;
    track_definition_section_header_t *tdh;
    track_definition_t *tp;
    u32 track_code;
    uword *p;
    bound_track_t *btp;

    tdh = (track_definition_section_header_t *)(sh+1);
    nevents = ntohl(tdh->number_of_track_definitions);
    
    if (verbose) {
        fprintf(stderr, "Track Definition Section: %d definitions\n",
                nevents);
    }

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
        btp->track_code = track_code;
        hash_set(the_trackdef_hash, track_code, btp - bound_tracks);
        tp++;
    }
    return (0);
}


int event_pass (cpel_section_header_t *sh, int verbose, FILE *ofp)
{
    event_section_header_t *eh;
    event_entry_t *ep;
    f64 ticks_per_us;
    long output_count;
    long dup_events = 0;
    ulonglong end_time = 0;
    double t;
    int sp, ancestor;
    int nevents, i;
    u64 now;
    u64 time0, time1;
    double d;
    u32 last_track_code = 0xdeafb00b;
    u32 track_code;
    u32 event_code, event_datum;
    bound_track_t *tp = 0;
    uword *p;

    output_count = 0;
    total_time = 0;

    eh = (event_section_header_t *)(sh+1);
    nevents = ntohl(eh->number_of_events);
    ticks_per_us = ((double)ntohl(eh->clock_ticks_per_second))/1e6;

    if (verbose) {
        fprintf(ofp, "%.3f ticks_per_us\n", ticks_per_us);
    }

    ep = (event_entry_t *)(eh+1);

    time0 = ntohl (ep->time[0]);
    time1 = ntohl (ep->time[1]);
    
    now = (((u64) time0)<<32) | time1;
    d = now;
    d /= ticks_per_us;
    first_start_time = d;

    for (i = 0; i < nevents; i++) {
        time0 = ntohl (ep->time[0]);
        time1 = ntohl (ep->time[1]);

        now = (((u64) time0)<<32) | time1;
        
        /* Convert from bus ticks to usec */
        d = now;
        d /= ticks_per_us;

        now = d;

        track_code = ntohl(ep->track);
        event_code = ntohl(ep->event_code);
        event_datum = ntohl(ep->event_datum);

        if (track_code != last_track_code) {
            if (tp) {
                tp->thread_timestamp += now - tp->time_thread_on_cpu;
                tp->time_thread_on_cpu = 0;
            }
            p = hash_get(the_trackdef_hash, track_code);
            if (!p) {
                /* synthesize a new track */
                vec_add2(bound_tracks, tp, 1);
                tp->track_code = track_code;
                hash_set(the_trackdef_hash, track_code, tp - bound_tracks);
            } else {
                tp = bound_tracks + p[0];
            }
            last_track_code = track_code;
            tp->time_thread_on_cpu = now;
        }

        if (event_code != entry_event &&
            event_code != exit_event) {
            ep++;
            continue;
        }
        
    again:
        switch (tp->state) {
        case 0:                 /* not in state */
            /* Another exit event? Stack pop */
            if (event_code == exit_event) {
                /* Only if we have something on the stack */
                if (vec_len(tp->start_datum) > 0) {
                    tp->state = 1;
                    goto again;
                } else {
                    fprintf (stderr, 
                             "End event before start event, key 0x%x.", 
                             ntohl(ep->event_datum));
                    fprintf (stderr, " Interpret results carefully...\n");
                }
            }

            tp->state = 1;
            if (vec_len(tp->start_datum) >= MAXSTACK) {
                int j;

                fprintf (stderr, "stack overflow..\n");
                for (j = vec_len(tp->start_datum)-1; j >= 0; j--) {
                    fprintf(stderr, "stack[%d]: datum 0x%x\n", 
                            j, tp->start_datum[j]);
                }
                fprintf (stderr, 
                         "Stack overflow... This occurs when "
                         "(start, datum)...(end, datum) events\n"
                         "are not properly paired.\n\n"
                         "A typical scenario looks like this:\n\n"
                         "    ...\n"
                         "    ELOG(..., START_EVENT, datum);\n"
                         "    if (condition)\n"
                         "       return; /*oops, forgot the end event*/\n"
                         "    ELOG(..., END_EVENT, datum);\n"
                         "    ...\n\n"
                         "The datum stack dump (above) should make it clear\n"
                         "where to start looking for a sneak path...\n");

                exit (1);
            }
            vec_add1(tp->start_datum, event_datum);
            vec_add1(tp->start_time, (tp->thread_timestamp + (now - tp->time_thread_on_cpu)));
#ifdef HAVING_TROUBLE
            printf ("sp %lld key 0x%x start time %llu\n", 
                    (long long) vec_len(tp->start_time)-1, event_datum, 
                    (unsigned long long) 
                    tp->start_time [vec_len(tp->start_time)-1]);
            printf ("timestamp %llu, now %llu, thread on cpu %llu\n",
                    (unsigned long long) tp->thread_timestamp, 
                    (unsigned long long) now, 
                    (unsigned long long) tp->time_thread_on_cpu);
#endif
            

            
            /* 
             * Multiple identical enter events? If the user knows that
             * gcc is producing bogus events due to inline functions,
             * trash the duplicate.
             */
            if (inline_mokus 
                && vec_len (tp->start_datum) > 1
                && tp->start_datum [vec_len(tp->start_datum)-1] ==
                tp->start_datum [vec_len(tp->start_datum)-2]) {
                vec_add1 (tp->dup_event, 1);
            } else {
                vec_add1 (tp->dup_event, 0);
            }


            ep++;
            continue;

        case 1:                 /* in state */
            /* Another entry event? Stack push*/
            if (event_code == entry_event) {
                tp->state = 0;
                goto again;
            }
            
            if (vec_len(tp->start_datum) == 0) {
                fprintf (stderr, "Stack underflow...\n");
                exit (1);
            }

            sp = vec_len(tp->start_time)-1;

            end_time = tp->thread_timestamp + (now - tp->time_thread_on_cpu);

            if (!tp->dup_event[sp]) {
#ifdef HAVING_TROUBLE
                printf ("sp %d key 0x%x charged %llu\n", sp, 
                        tp->start_datum[sp], end_time - tp->start_time[sp]);
                printf ("  start %llu, end %llu\n", (unsigned long long) tp->start_time[sp],
                        (unsigned long long) end_time);
#endif
            
                record_instance (tp->start_datum[sp], (end_time -
                                                       tp->start_time[sp]));
            
                /* Factor out our time from surrounding services, if any */
                for (ancestor = sp-1; ancestor >= 0; ancestor--) {
#ifdef HAVING_TROUBLE
                    printf ("Factor out %lld from key 0x%08x\n",
                            (end_time - tp->start_time[sp]), tp->start_datum[ancestor]);
#endif
                    tp->start_time[ancestor] += (end_time - tp->start_time[sp]);
                }
                output_count++;
                total_time += (end_time - tp->start_time[sp]);
                tp->state = 0;
            } else {
                dup_events++;
            }
            _vec_len(tp->start_datum) = sp;
            _vec_len(tp->start_time) = sp;
            _vec_len(tp->dup_event) = sp;
        }

        ep++;
    }
    last_end_time = now;

    if (scatterkey) {
        scatterplot_data();
        exit (0);
    }

    if (output_count) {
        t = (double)total_time;
        printf ("%ld instances of state, %.2f microseconds average\n",
                output_count, t / output_count);

        printf ("Total instrumented runtime: %.2f microseconds\n",
                ((double)total_time));
        printf ("Total runtime: %lld microseconds\n",
                last_end_time - first_start_time);

        t /= (double)(last_end_time - first_start_time);
        t *= 100.0;

        if (dup_events) {
            printf ("Suppressed %ld duplicate state entry events\n",
                    dup_events);
        }
        printf ("Instrumented code accounts for %.2f%% of total time.\n\n",
                t);
        report_actors();
    } else {
        printf ("No instances of state...\n");
    }

    return(0);
}

/* 
 * Note: If necessary, add passes / columns to this table to 
 * handle section order dependencies.
 */

section_processor_t processors[CPEL_NUM_SECTION_TYPES+1] =
{
    {unsupported_pass},		/* type 0 -- f**ked */
    {noop_pass}, 		/* type 1 -- STRTAB */
    {noop_pass}, 		/* type 2 -- SYMTAB */
    {noop_pass},                /* type 3 -- EVTDEF */
    {trackdef_pass},		/* type 4 -- TRACKDEF */
    {event_pass},               /* type 5 -- EVENTS */
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

    default:
        fprintf(stderr, "Unknown pass %d\n", pass);
        return(1);
    }

    rv = (*fp)(sh, verbose, ofp);

    return(rv);
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

int process_file (u8 *cpel, int verbose)
{
    cpel_file_header_t *fh;
    cpel_section_header_t *sh;
    u16 nsections;
    u32 section_size;
    int i;
    FILE *ofp = stderr;

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
    nsections = ntohs(fh->nsections);

    /*
     * Take a passe through the file. 
     */
    sh = (cpel_section_header_t *)(fh+1);
    for (i = 0; i < nsections; i++) {
        section_size = ntohl(sh->data_length);

        if(verbose) {
            fprintf(ofp, "Section type %d, size %d\n", 
                    ntohl(sh->section_type),
                    section_size);
        }

        if(process_section(sh, verbose, ofp, PASS1))
            return(1);

        sh++;
        sh = (cpel_section_header_t *)(((u8 *)sh)+section_size);
    }

    return(0);
}

/****************************************************************************
* main - 
****************************************************************************/

int main (int argc, char **argv)
{
    int curarg = 1;
    u8 *cpel = 0;
    int verbose = 0;

    if (argc < 6)
    {
        fprintf (stderr, "usage: cpelinreg -i <file>\n");
        fprintf (stderr, "       -s start-event --e end-event [-nokey]\n");
        fprintf (stderr, "       [-m <ninst-to-model>][-xtra-stats]\n");
        fprintf (stderr, "       [-keyscatterplot <hex-key>]\n\n");
        fprintf (stderr, "%s\n", version);
        exit (1);
    }

    while (curarg < argc) {
        if (!strncmp (argv[curarg], "-ifile", 2)) {
            curarg++;
            g_ifile = argv[curarg++];
            continue;
        }
        if (!strncmp (argv[curarg], "-start", 2)) {
            curarg++;
            entry_event = atol (argv [curarg++]);
            continue;
        }
        if (!strncmp (argv[curarg], "-end", 2)) {
            curarg++;
            exit_event = atol (argv [curarg++]);
            continue;
        }

        if (!strncmp(argv[curarg], "-badinlines", 2)) {
            curarg++;
            inline_mokus = 1;
            continue;
        }

        if (!strncmp (argv[curarg], "-x", 2)) {
            curarg++;
            summary_stats=1;
            continue;
        }
        if (!strncmp (argv[curarg], "-nokey", 2)) {
            curarg++;
            nokey = 1;
            continue;
        }
        if (!strncmp (argv[curarg], "-keyscatterplot", 2)) {
            curarg++;
            sscanf (argv[curarg], "%lx", &scatterkey);
            curarg++;
            continue;
        }

        if (!strncmp (argv[curarg], "-model", 2)) {
            if (model_index >= sizeof(model_these) / sizeof(int)) {
                fprintf (stderr, "Too many model requests\n");
                exit (1);
            }
            curarg++;
            model_these[model_index++] = atol (argv [curarg++]);
            continue;
        }
        if (!strncmp (argv[curarg], "-verbose", 2)) {
            verbose++;
            curarg++;
            continue;
        }

        fprintf (stderr, "unknown switch '%s'\n", argv[curarg]);
        exit (1);
    }
                
    cpel = (u8 *)mapfile(g_ifile);

    if (cpel == NULL)
    {
        fprintf (stderr, "Couldn't open %s\n", g_ifile);
        exit (1);
    }

    printf ("Extracting state info from %s\nentry_event %d, exit_event %d\n",
            g_ifile, entry_event, exit_event);
    if (nokey) {
        printf ("All state instances mapped to a single actor chain\n");
    }

    the_trackdef_hash = hash_create (0, sizeof (uword));

    process_file(cpel, verbose);
    exit (0);
}
