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

#ifndef _CPEL_H_
#define _CPEL_H_ 1

typedef struct cpel_file_header_ {
    unsigned char endian_version;
    unsigned char pad;
    unsigned short nsections;
    unsigned file_date;
} cpel_file_header_t;

#define CPEL_FILE_LITTLE_ENDIAN	0x80
#define CPEL_FILE_VERSION       0x01
#define CPEL_FILE_VERSION_MASK  0x7F

typedef struct cpel_section_header_ {
    unsigned int section_type;
    unsigned int data_length;        /* does NOT include type and itself */
} cpel_section_header_t;

#define CPEL_SECTION_STRTAB	1
/* string at offset 0 is the name of the table */

#define CPEL_SECTION_SYMTAB     2
#define CPEL_SECTION_EVTDEF     3

typedef struct event_definition_section_header_ {
    char string_table_name[64];
    unsigned int number_of_event_definitions;
} event_definition_section_header_t;

typedef struct event_definition_ {
    unsigned int event;
    unsigned int event_format;
    unsigned int datum_format;
} event_definition_t;

#define CPEL_SECTION_TRACKDEF   4

typedef struct track_definition_section_header_ {
    char string_table_name[64];
    unsigned int number_of_track_definitions;
} track_definition_section_header_t;

typedef struct track_definition_ {
    unsigned int track;
    unsigned int track_format;
} track_definition_t;

#define CPEL_SECTION_EVENT      5

typedef struct event_section_header_ {
    char string_table_name[64];
    unsigned int number_of_events;
    unsigned int clock_ticks_per_second;
} event_section_header_t;

typedef struct event_entry_ {
    unsigned int time[2];
    unsigned int track;
    unsigned int event_code;
    unsigned int event_datum;
} event_entry_t;

#define CPEL_NUM_SECTION_TYPES 5

#endif /* _CPEL_H_ */

