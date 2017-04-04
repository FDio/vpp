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

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <gtk/gtk.h>
#include "g2.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

/*
 * globals
 */
boolean g_little_endian;
event_t *g_events;
ulong g_nevents;
pid_sort_t *g_pids;
pid_sort_t *g_original_pids;
int g_npids;
pid_data_t *g_pid_data_list;

/*
 * locals
 */
pid_data_t **s_pidhash;

/*
 * config parameters
 */

double ticks_per_ns=1000.0;
boolean ticks_per_ns_set;

/****************************************************************************
* event_init
****************************************************************************/

void event_init(void)
{
    ulong endian;
    char *ep;
    char *askstr;
    int tmp;

    ep = (char *)&endian;
    endian = 0x12345678;
    if (*ep != 0x12)
        g_little_endian = TRUE;
    else
        g_little_endian = FALSE;

    askstr = getprop("dont_ask_ticks_per_ns_initially");
    
    if (askstr && (*askstr == 't' || *askstr == 'T')) {
        tmp = atol(getprop_default("ticks_per_ns", 0));
        if (tmp > 0) {
            ticks_per_ns = tmp;
            ticks_per_ns_set = TRUE;
        }
    }
}

/****************************************************************************
* find_or_add_pid
****************************************************************************/

pid_data_t *find_or_add_pid (ulong pid)
{
    pid_data_t *pp;
    ulong bucket;

    bucket = pid % PIDHASH_NBUCKETS;

    pp = s_pidhash[bucket];

    if (pp == 0) {
        pp = g_malloc0(sizeof(pid_data_t));
        pp->pid_value = pid;
        s_pidhash[bucket] = pp;
        g_npids++;
        return(pp);
    }
    while (pp) {
        if (pp->pid_value == pid)
            return(pp);
        pp = pp->next;
    }

    pp = g_malloc0(sizeof(pid_data_t));
    pp->pid_value = pid;
    pp->next = s_pidhash[bucket];
    s_pidhash[bucket] = pp;
    g_npids++;
    return(pp);
}

/****************************************************************************
* pid_cmp
****************************************************************************/

int pid_cmp(const void *a1, const void *a2)
{
    pid_sort_t *p1 = (pid_sort_t *)a1;
    pid_sort_t *p2 = (pid_sort_t *)a2;

    if (p1->pid_value < p2->pid_value)
        return(-1);
    else if (p1->pid_value == p2->pid_value)
        return(0);
    else
        return(1);
}

/****************************************************************************
* make_sorted_pid_vector
****************************************************************************/

static void make_sorted_pid_vector(void)
{
    pid_data_t *pp;
    pid_data_t **p_previous;
    pid_sort_t *psp;
    int i;

    psp = g_pids = g_malloc0(sizeof(pid_sort_t)*g_npids);

    for (i = 0; i < PIDHASH_NBUCKETS; i++) {
        pp = s_pidhash[i];
        while(pp) {
            psp->pid = pp;
            psp->pid_value = pp->pid_value;
            psp++;
            pp = pp->next;
        }
    }

    qsort(&g_pids[0], g_npids, sizeof(pid_sort_t), pid_cmp);

    /* put the sort order into the pid objects */
    psp = g_pids;

    /*
     * This is rather gross.
     *
     * We happen to know that whenever this function is called, the hash table
     * structure itself is immediately torn down. So the "next" pointers in the
     * pid_data_t elements are about to become useless.
     *
     * So we re-use them, to link all the pid_data_t elements together into a
     * single unified linked list, with g_pid_data_list pointing to the head.
     * This means we can walk all the pid_data_t objects if we really want to.
     * Reading snapshots from disk is one example.
     *
     * Alternatively we could just leave the hash table in place; this is
     * far nicer, but as it happens, trading O(n) lookups for O(1) lookups
     * isn't actually a problem for the restricted post-tear-down usage. So for
     * now we take the memory savings and swap our hash table for a list.
     */
    p_previous = &g_pid_data_list;
    for (i = 0; i < g_npids; i++) {
        pp = psp->pid;
        pp->pid_index = i;
        *p_previous = pp;
        p_previous = &pp->next;
        psp++;
    }
    *p_previous = NULL;

    /*
     * Squirrel away original (sorted) vector, so we can
     * toggle between "chase" mode, snapshots, and the original
     * display method on short notice 
     */
    g_original_pids = g_malloc0(sizeof(pid_sort_t)*g_npids);
    memcpy (g_original_pids, g_pids, sizeof(pid_sort_t)*g_npids); 
}

/****************************************************************************
* read_events
****************************************************************************/

void read_events(char *filename)
{
    ulong *ulp;
    ulong size;
    event_t *ep;
    raw_event_t *rep;
    ulonglong start_time=0ULL;
    ulonglong low_time;
    boolean once=TRUE;
    int i;
    char tmpbuf [128];

    ulp = (ulong *)mapfile(filename, &size);

    if (ulp == NULL) {
        sprintf(tmpbuf, "Couldn't open %s\n", filename);
        infobox("Read Event Log Failure", tmpbuf);
        return;
    }

    g_nevents = ntohl(*ulp);

    if (size != (g_nevents*sizeof(raw_event_t) + sizeof(g_nevents))) {
        sprintf(tmpbuf, "%s was damaged, or isn't an event log.\n", filename);
        infobox("Bad Input File", tmpbuf);
        g_nevents = 0;
        unmapfile((char *)ulp, size);
        return;
    }

    rep = (raw_event_t *)(ulp+1);

    if (g_events)
        g_free(g_events);

    g_events = (event_t *)g_malloc(g_nevents * sizeof(event_t));
    ep = g_events;

    while (g_npids > 0) {
        g_free((g_pids + g_npids-1)->pid);
        g_npids--;
    }
    if (g_pids) {
        g_free(g_pids);
        g_free(g_original_pids);
        g_pids = 0;
        g_original_pids = 0;
    }

    s_pidhash = (pid_data_t **)g_malloc0(
        PIDHASH_NBUCKETS*sizeof(pid_data_t *));

    /* $$$ add a SEGV handler... */
    for (i = 0; i < g_nevents; i++) {
        if (once) {
            once = FALSE;
            start_time = ((ulonglong)ntohl(rep->time[0]));
            start_time <<= 32;
            low_time = ntohl(rep->time[1]);
            low_time &= 0xFFFFFFFF;
            start_time |= low_time;
            ep->time = 0LL;
        } else {
            ep->time = ((ulonglong)ntohl(rep->time[0]));
            ep->time <<= 32;
            low_time = ntohl(rep->time[1]);
            low_time &= 0xFFFFFFFF;
            ep->time |= low_time;
            ep->time -= start_time;
            ep->time /= ticks_per_ns;
        }
        ep->code = ntohl(rep->code);
        ep->pid = find_or_add_pid(ntohl(rep->pid));
        ep->datum = ntohl(rep->datum);
        ep->flags = 0;
        ep++;
        rep++;
    }

    unmapfile((char *)ulp, size);
    
    make_sorted_pid_vector();
    g_free(s_pidhash);
    s_pidhash = 0;

    /* Give the view-1 world a chance to reset a few things... */
    view1_read_events_callback();
}

static event_t *add_ep;

/****************************************************************************
* cpel_event_init
****************************************************************************/
void cpel_event_init (ulong nevents)
{
    g_nevents = nevents;
    if (g_events)
        g_free(g_events);
    add_ep = g_events = (event_t *)g_malloc(g_nevents * sizeof(event_t));
    while (g_npids > 0) {
        g_free((g_pids + g_npids-1)->pid);
        g_npids--;
    }
    if (g_pids) {
        g_free(g_pids);
        g_free(g_original_pids);
        g_pids = 0;
        g_original_pids = 0;
    }
    s_pidhash = (pid_data_t **)g_malloc0(
        PIDHASH_NBUCKETS*sizeof(pid_data_t *));
}

/****************************************************************************
* add_cpel_event
****************************************************************************/

void add_cpel_event(ulonglong delta, ulong track, ulong event, ulong datum)
{
    event_t *ep;

    ep = add_ep++;
    ep->time = delta;
    ep->pid = find_or_add_pid(track);
    ep->code = event;
    ep->datum = datum;
    ep->flags = 0;
}

/****************************************************************************
* add_clib_event
****************************************************************************/

void add_clib_event(double delta, unsigned short track, 
                    unsigned short event, unsigned int index)
{
    event_t *ep;

    ep = add_ep++;
    ep->time = (ulonglong) (delta * 1e9); /* time in intger nanoseconds */
    ep->pid = find_or_add_pid(track);
    ep->code = event;
    ep->datum = index;
    ep->flags = EVENT_FLAG_CLIB;
}

/****************************************************************************
* cpel_event_finalize
****************************************************************************/

void cpel_event_finalize(void)
{
    make_sorted_pid_vector();
    g_free(s_pidhash);
    s_pidhash = 0;
    
    /* Give the view-1 world a chance to reset a few things... */
    view1_read_events_callback();
}

/****************************************************************************
* mapfile
****************************************************************************/

char *mapfile (char *file, ulong *sizep)
{
    struct stat statb;
    char *rv;
    int maphfile;
    size_t mapfsize;
    
    maphfile = open (file, O_RDONLY);

    if (maphfile < 0)
        return (NULL);

    if (fstat (maphfile, &statb) < 0) {
        return (NULL);
    }

    /* Don't try to mmap directories, FIFOs, semaphores, etc. */
    if (! (statb.st_mode & S_IFREG)) {
        return (NULL);
    }

    mapfsize = statb.st_size;

    if (mapfsize < 3) {
        close (maphfile);
        return (NULL);
    }

    rv = mmap (0, mapfsize, PROT_READ, MAP_SHARED, maphfile, 0);

    if (rv == 0) {
        g_error ("%s mapping problem, I quit...\n", file);
    }

    close (maphfile);

    if (madvise (rv, mapfsize, MADV_SEQUENTIAL) < 0) {
        return (rv);
    }

    if (sizep) {
        *sizep = mapfsize;
    }
    return (rv);
}

/****************************************************************************
* unmapfile
****************************************************************************/

boolean unmapfile (char *addr, ulong size)
{
    if (munmap (addr, size) < 0) {
        g_warning("Unmap error, addr 0x%lx size 0x%x\n", 
                  (unsigned long) addr, (unsigned int)size);
        return(FALSE);
    }
    return(TRUE);
}

/****************************************************************************
* find_event_index
* Binary search for first event whose time is >= t
****************************************************************************/

int find_event_index (ulonglong t)
{
    int index, bottom, top;
    event_t *ep;

    bottom = g_nevents-1;
    top = 0;

    while (1) {
	index = (bottom + top) / 2;

        ep = (g_events + index);

        if (ep->time == t)
            return(index);

        if (top >= bottom) {
            while (index > 0 && ep->time > t) {
                ep--;
                index--;
            }
            while (index < g_nevents && ep->time < t) {
                ep++;
                index++;
            }
            return(index);
        }

        if (ep->time < t)
            top = index + 1;
        else 
            bottom = index - 1;
    }
}

/****************************************************************************
* events_about
****************************************************************************/

void events_about (char *tmpbuf)
{
    sprintf(tmpbuf+strlen(tmpbuf), "%d total events, %.3f ticks per us\n", 
            (int)g_nevents, ticks_per_ns);
}
