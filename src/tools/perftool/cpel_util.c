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
#include <vppinfra/bitmap.h>
#include <vppinfra/byte_order.h>
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include "cpel.h"
#include "cpel_util.h"

evt_t *the_events;

track_t *the_tracks;
u32 *track_alpha_map;

event_definition_t *the_event_definitions;
i64 min_timestamp;

/* Hash tables, used to find previous instances of the same items */
uword *the_track_hash;
uword *the_msg_event_hash;
uword *the_strtab_hash;
uword *the_pidtid_hash;
uword *the_pid_to_name_hash;
u8 *the_strtab;

uword *the_event_id_bitmap;

/*
 * find_or_add_strtab
 * Finds or adds a string to the string table
 */
u32 find_or_add_strtab(void *s_arg)
{
    uword *p;
    int len;
    u8 *this_string;
    u8 *scopy=0;
    char *s = s_arg;

    p = hash_get_mem(the_strtab_hash, s);
    if (p) {
        return (p[0]);
    }

    /*
     * Here's a CLIB bear-trap. We can't add the string-table 
     * strings to the to the hash table (directly), since it 
     * expands and moves periodically. All of the hash table
     * entries turn into dangling references, yadda yadda. 
     */

    len = strlen(s)+1;
    vec_add2(the_strtab, this_string, len);
    memcpy(this_string, s, len);
    
    /* Make a copy which won't be moving around... */
    vec_validate(scopy, len);
    memcpy(scopy, s, len);

    hash_set_mem(the_strtab_hash, scopy, this_string - the_strtab);

    return(this_string - the_strtab);
}

/*
 * find_or_add_track
 * returns index in track table
 */
u32 find_or_add_track(void *s_arg)
{
    uword *p;
    track_t *this_track;
    u8 *copy_s;
    char *s=s_arg;

    p = hash_get_mem(the_track_hash, s);
    if (p) {
        return (p[0]);
    }
    vec_add2(the_tracks, this_track, 1);

    this_track->original_index = this_track - the_tracks;
    this_track->strtab_offset = find_or_add_strtab(s);

    copy_s = (u8 *)vec_dup(s);

    hash_set_mem(the_track_hash, copy_s, this_track - the_tracks);
    return(this_track - the_tracks);
}

/* 
 * find_or_add_event
 * Adds an event to the event definition vector and add it to
 * the event hash table
 */

u32 find_or_add_event(void *s_arg, char *datum_format)
{
    uword *p;
    u8 *copy_s;
    event_definition_t *this_event_definition;
    u32 event_id;
    char *s=s_arg;

    p = hash_get_mem(the_msg_event_hash, s);
    if (p) {
        return (p[0]);
    }
    vec_add2(the_event_definitions, this_event_definition, 1);

    /* Allocate a new event-id */
    event_id = clib_bitmap_first_clear (the_event_id_bitmap);
    the_event_id_bitmap = clib_bitmap_set(the_event_id_bitmap, event_id, 1);
    this_event_definition->event = event_id;
    this_event_definition->event_format = find_or_add_strtab(s);
    this_event_definition->datum_format = find_or_add_strtab(datum_format);

    copy_s = (u8 *)vec_dup(s);

    hash_set_mem(the_msg_event_hash, copy_s, event_id);

    return(event_id);
}

/*
 * write_string_table
 */
int write_string_table(FILE *ofp)
{
    cpel_section_header_t sh;

    /* Round up string table size */
    while (vec_len(the_strtab) & 0x7)
        vec_add1(the_strtab, 0);

    sh.section_type = ntohl(CPEL_SECTION_STRTAB);
    sh.data_length = ntohl(vec_len(the_strtab));
    
    if (fwrite(&sh, sizeof(sh), 1, ofp) != 1)
        return(0);
    
    if (fwrite(the_strtab, 1, vec_len(the_strtab), ofp) != 
        vec_len(the_strtab))
        return(0);

    return(1);
}

/*
 * write_cpel_header
 */
int write_cpel_header(FILE *ofp, u32 nsections)
{
    cpel_file_header_t h;
    
    h.endian_version = CPEL_FILE_VERSION;
    h.pad = 0; 
    h.nsections = ntohs(nsections);
    h.file_date = ntohl(time(0));
    if (fwrite(&h, sizeof(h), 1, ofp) != 1)
        return (0);

    return(1);
}

/* 
 * write_event_defs
 */
int write_event_defs(FILE *ofp)
{
    cpel_section_header_t sh;
    event_definition_section_header_t edsh;
    event_definition_t *this_event_definition;
    int i;

    /* Next, the event definitions */
    sh.section_type = ntohl(CPEL_SECTION_EVTDEF);
    sh.data_length = ntohl(vec_len(the_event_definitions)
                           *sizeof(the_event_definitions[0]) 
                           + sizeof(event_definition_section_header_t));

    if (fwrite(&sh, sizeof(sh), 1, ofp) != 1)
        return(0);

    clib_memset(&edsh, 0, sizeof(edsh));

    strcpy(edsh.string_table_name, "FileStrtab");
    edsh.number_of_event_definitions = ntohl(vec_len(the_event_definitions));
    
    if (fwrite(&edsh, sizeof(edsh), 1, ofp) != 1)
        return(0);

    for (i = 0; i < vec_len(the_event_definitions); i++) {
        this_event_definition = &the_event_definitions[i];
        /* Endian fixup */
        this_event_definition->event = ntohl(this_event_definition->event);
        this_event_definition->event_format = 
            ntohl(this_event_definition->event_format);
        this_event_definition->datum_format =
            ntohl(this_event_definition->datum_format);

        if (fwrite(this_event_definition, sizeof(the_event_definitions[0]), 
                   1, ofp) != 1)
            return(0);
    }
    return(1);
}

/*
 * ntohll
 */
u64 ntohll (u64 x) {
    if (clib_arch_is_little_endian)
	x = ((((x >> 0) & 0xff) << 56)
	     | (((x >> 8) & 0xff) << 48)
	     | (((x >> 16) & 0xff) << 40)
	     | (((x >> 24) & 0xff) << 32)
	     | (((x >> 32) & 0xff) << 24)
	     | (((x >> 40) & 0xff) << 16)
	     | (((x >> 48) & 0xff) << 8)
	     | (((x >> 56) & 0xff) << 0));
    
    return x;
}

/* 
 * write_events
 */
int write_events(FILE *ofp, u64 clock_ticks_per_second)
{
    cpel_section_header_t sh;
    event_section_header_t eh;
    u32 number_of_events;
    int i;
    event_entry_t e;
    u64 net_timestamp;
    evt_t *this_event;
    u32 time0, time1;

    number_of_events = vec_len(the_events);

    sh.section_type = ntohl(CPEL_SECTION_EVENT);
    sh.data_length = ntohl(number_of_events * sizeof(e) +
                           sizeof(event_section_header_t));

    if (fwrite(&sh, sizeof(sh), 1, ofp) != 1)
        return(0);
    
    clib_memset(&eh, 0, sizeof(eh));
    strcpy(eh.string_table_name, "FileStrtab");
    eh.number_of_events = ntohl(number_of_events);
    eh.clock_ticks_per_second = ntohl(clock_ticks_per_second);
    
    if (fwrite(&eh, sizeof(eh), 1, ofp) != 1)
        return(0);

    for (i = 0; i < number_of_events; i++) {
        this_event = &the_events[i];
        net_timestamp = ntohll(this_event->timestamp);
    
        time1 = net_timestamp>>32;
        time0 = net_timestamp & 0xFFFFFFFF;
        
        e.time[0] = time0;
        e.time[1] = time1;
        e.track = ntohl(this_event->track_id);
        e.event_code = ntohl(this_event->event_id);
        e.event_datum = ntohl(this_event->datum);
        
        if (fwrite(&e, sizeof(e), 1, ofp) != 1)
            return(0);
    }
    return(1);
}

/*
 * write_track_defs
 */
int write_track_defs(FILE *ofp)
{
    cpel_section_header_t sh;
    track_definition_section_header_t tdsh;
    track_definition_t record;
    track_definition_t *this_track_definition = &record;
    int i;
    event_definition_section_header_t edsh;

    /* Next, the event definitions */
    sh.section_type = ntohl(CPEL_SECTION_TRACKDEF);
    sh.data_length = ntohl(vec_len(the_tracks)
                           *sizeof(this_track_definition[0]) 
                           + sizeof(track_definition_section_header_t));

    if (fwrite(&sh, sizeof(sh), 1, ofp) != 1)
        return(0);

    clib_memset(&tdsh, 0, sizeof(tdsh));

    strcpy(tdsh.string_table_name, "FileStrtab");
    tdsh.number_of_track_definitions = ntohl(vec_len(the_tracks));
    
    if (fwrite(&tdsh, sizeof(edsh), 1, ofp) != 1)
        return(0);

    for (i = 0; i < vec_len(the_tracks); i++) {
        this_track_definition->track = ntohl(i);
        this_track_definition->track_format = 
            ntohl(the_tracks[i].strtab_offset);

        if (fwrite(this_track_definition, sizeof(this_track_definition[0]),
                   1, ofp) != 1)
            return(0);
    }
    return(1);
}

void cpel_util_init (void)
{
    u8 *eventstr;

    the_strtab_hash = hash_create_string (0, sizeof (uword));
    the_msg_event_hash = hash_create_string (0, sizeof (uword));
    the_track_hash = hash_create_string (0, sizeof (uword));
    the_pidtid_hash = hash_create_string (0, sizeof(uword));
    the_pid_to_name_hash = hash_create(0, sizeof(uword));
    
    /* Must be first, or no supper... */
    find_or_add_strtab("FileStrtab");

    /* Historical canned events, no longer used. */
    if (0) {
        /* event 0 (not used) */
        eventstr = format(0, "PlaceholderNotUsed");
        vec_add1(eventstr, 0);
        find_or_add_event(eventstr, "%s");
        vec_free(eventstr);
        
        /* event 1 (thread on CPU) */
        eventstr = format(0, "THREAD/THRUNNING");
        vec_add1(eventstr, 0);
        find_or_add_event(eventstr, "%s");
        vec_free(eventstr);
        
        /* event 2 (thread ready) */
        eventstr = format(0, "THREAD/THREADY");
        vec_add1(eventstr, 0);
        find_or_add_event(eventstr, "%s");
        vec_free(eventstr);
        
        /* event 3 (function enter) */
        eventstr = format(0, "FUNC/ENTER");
        vec_add1(eventstr, 0);
        find_or_add_event(eventstr, "0x%x");
        vec_free(eventstr);
        
        /* event 4 (function enter) */
        eventstr = format(0, "FUNC/EXIT");
        vec_add1(eventstr, 0);
        find_or_add_event(eventstr, "0x%x");
        vec_free(eventstr);
    }
}

/*
 * alpha_compare_tracks
 */
static int alpha_compare_tracks(const void *a1, const void *a2)
{
    int i;
    track_t *t1 = (track_t *)a1;
    track_t *t2 = (track_t *)a2;
    u8 *s1 = &the_strtab[t1->strtab_offset];
    u8 *s2 = &the_strtab[t2->strtab_offset];

    for (i = 0; s1[i] && s2[i]; i++) {
        if (s1[i] < s2[i])
            return(-1);
        if (s1[i] > s2[i])
            return(1);
    }
    return(0);
}

/*
 * alpha_sort_tracks
 * Alphabetically sort tracks, set up a mapping
 * vector so we can quickly map the original track index to
 * the new/improved/alpha-sorted index
 */
void alpha_sort_tracks(void)
{
    track_t *this_track;
    int i;

    qsort(the_tracks, vec_len(the_tracks), sizeof(track_t),
          alpha_compare_tracks);

    vec_validate(track_alpha_map, vec_len(the_tracks));
    _vec_len(track_alpha_map) = vec_len(the_tracks);

    for (i = 0; i < vec_len(the_tracks); i++) {
        this_track = &the_tracks[i];
        track_alpha_map[this_track->original_index] = i;
    }
}

/*
 * fixup_event_tracks
 * Use the track alpha mapping to account for the alphabetic
 * sort performed by the previous routine
 */
void fixup_event_tracks(void)
{
    int i;
    u32 old_track;

    for (i = 0; i < vec_len(the_events); i++) {
        old_track = the_events[i].track_id;
        the_events[i].track_id = track_alpha_map[old_track];
    }
}

/* Indispensable for debugging in gdb... */

u32 vl(void *x)
{
    return vec_len(x);
}
