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

#ifndef __cpel_util_h__
#define __cpel_util_h__

/*
 * Our idea of an event, as opposed to a CPEL event
 */
typedef struct evt_ {
    u64 timestamp;
    u32 track_id;               
    u32 event_id;
    u32 datum;
} evt_t;

evt_t *the_events;

/*
 * Track object, so we can sort the tracks alphabetically and
 * fix the events later 
 */
typedef struct track_ {
    u32 original_index;
    u32 strtab_offset;
} track_t;

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

u32 find_or_add_strtab(void *s_arg);
u32 find_or_add_track(void *s_arg);
u32 find_or_add_event(void *s_arg, char *datum_format);
int write_string_table(FILE *ofp);
int write_cpel_header(FILE *ofp, u32 nsections);
int write_event_defs(FILE *ofp);
u64 ntohll (u64 x);
int write_events(FILE *ofp, u64 clock_ticks_per_second);
int write_track_defs(FILE *ofp);
void cpel_util_init (void);
void alpha_sort_tracks(void);
void fixup_event_tracks(void);

#endif /* __cpel_util_h__ */
