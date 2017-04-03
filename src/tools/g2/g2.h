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

/*
 * typedefs and so forth
 */
#include <sys/types.h>
#include <gtk-2.0/gtk/gtk.h>
#include <stdio.h>
#include "props.h"

typedef char boolean;
typedef unsigned long long ulonglong;

/*
 * main.c
 */

GtkWidget *g_mainwindow;
GtkWidget *g_mainvbox;
GtkWidget *g_mainhbox;

/*
 * pointsel.c
 */
void point_selector_init(void);
boolean read_event_definitions (char *filename);
char *sxerox(char *);
void pointsel_about(char *);
void pointsel_next_snapshot(void);
void initialize_events(void);
void finalize_events(void);

#define NEVENTS 100000

typedef struct event_def_ {
    ulong event;
    char *name;
    char *format;
    boolean selected;
    boolean is_clib;
    char pad[2];
} event_def_t;

event_def_t *find_event_definition (ulong code);

event_def_t g_eventdefs[NEVENTS];

/*
 * config params
 */
int c_maxpointsel;        /* max # points shown in selector dlg */
gint c_view1_draw_width;
gint c_view1_draw_height;

/*
 * menu1.c
 */

void menu1_init(void);
void modal_dialog (char *label_text, char *retry_text, char *default_value, 
                   boolean (*cb)(char *));
void infobox(char *label_text, char *text);
/*
 * view1.c
 */
GdkFont *g_font;
GdkColor fg_black, bg_white;
void view1_init(void);
void view1_display(void);
void view1_read_events_callback(void);
void view1_display_when_idle(void);
void view1_print_callback(GtkToggleButton *item, gpointer data);
void view1_about(char *);
void set_pid_ax_width(int width);
void set_window_title(const char *filename);

enum view1_tbox_fn {
    TBOX_DRAW_BOXED = 1,        /* note: order counts */
	TBOX_DRAW_EVENT,
    TBOX_DRAW_PLAIN,
    TBOX_PRINT_BOXED,
	TBOX_PRINT_EVENT,
    TBOX_PRINT_PLAIN,           /* end restriction */
    TBOX_GETRECT_BOXED,
	TBOX_GETRECT_EVENT,
    TBOX_GETRECT_PLAIN,
};

enum view1_line_fn {
    LINE_DRAW_BLACK = 1,
    LINE_DRAW_WHITE,
    LINE_PRINT,
};

GdkRectangle *tbox (char *s, int x, int y, enum view1_tbox_fn function);
void line (int x1, int y1, int x2, int y2, enum view1_line_fn function);
gint view1_handle_key_press_event (GtkWidget *widget, GdkEventKey *event);

/*
 * events.c
 */

void events_about (char *);

typedef struct raw_event {
    unsigned long time[2];
    unsigned long pid;
    unsigned long code;
    unsigned long datum;
} raw_event_t;

void event_init(void);
char *mapfile (char *file, ulong *sizep);
boolean unmapfile (char *addr, ulong size);
void read_events (char *);
int find_event_index (ulonglong t);
int read_cpel_file(char *file);
int read_clib_file(char *file);
void cpel_event_init(ulong);
void add_event_from_cpel_file(ulong, char * , char *);
void add_event_from_clib_file(unsigned int event, char *name, 
                              unsigned int vec_index);
void add_cpel_event(ulonglong delta, ulong, ulong, ulong);
void add_clib_event(double delta, unsigned short track, 
                    unsigned short event, unsigned int index);
void cpel_event_finalize(void);
void *get_clib_event (unsigned int datum);

typedef struct pid_data {
    struct pid_data *next;
    ulong pid_value;            /* The actual pid value */
    ulong pid_index;            /* Index in pid sort order */
} pid_data_t;
    
#define EVENT_FLAG_SELECT 	0x00000001 /* This event is selected */
#define EVENT_FLAG_SEARCHRSLT   0x00000002 /* This event is the search rslt */
#define EVENT_FLAG_CLIB         0x00000004 /* clib event */

typedef struct pid_sort {
    struct pid_data *pid;
    ulong pid_value;
    /*
     * This is a bit of a hack, since this is used only by the view:
     */
    unsigned color_index;
    int selected;
} pid_sort_t;

typedef struct event {
    ulonglong time;
    ulong code;
    pid_data_t *pid;
    ulong datum;
    ulong flags;
} event_t;


boolean g_little_endian;
event_t *g_events;
ulong g_nevents;
pid_sort_t *g_pids;
pid_sort_t *g_original_pids;
int g_npids;
pid_data_t *g_pid_data_list;

#define PIDHASH_NBUCKETS	20021 /* Should be prime */

boolean ticks_per_ns_set;
double ticks_per_ns;

/*
 * version.c
 */
const char *version_string;
const char *minor_v_string;

/*
 * cpel.c
 */
char *get_track_label(unsigned long);
int widest_track_format;
char *strtab_ref(unsigned long);
