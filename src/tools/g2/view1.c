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
#include <errno.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include "g2.h"
#include <time.h>
#include <string.h>
#include <vppinfra/format.h>
#include <vppinfra/elog.h>

/*
 * The main event display view.
 * 
 * Important variables:
 *
 * "da" -- the drawing area, aka the screen representation of the
 *         event view.
 *
 * "pm" -- the backing pixmap for the drawing area. Note that
 *         all graphics operations target this backing
 *         store, then call gtk_widget_draw to copy a rectangle from
 *         the backing store onto the screen.
 *
 * "s_v1" -- pointer to the current v1_geometry_t object.
 * 
 * Box heirarchy:
 * s_view1_vbox
 *     s_view1_hbox
 *         da  s_view1_vmenubox
 *                  s_view1_topbutton("Top")
 *                  s_view1_vscroll (vertical scrollbar)
 *                  s_view1_bottombutton("Bottom")
 *     s_view1_hmenubox
 *         s_view1_startbutton("Start");
 *         s_view1_hscroll(horizontal scrollbar)
 *         s_view1_endbutton("End")
 *         s_view1_zoominbutton("Zoomin")
 *         s_view1_searchbutton("Search")
 *         s_view1_searchagainbutton("Search Again")
 *         s_view1_zoomoutbutton("Zoomout")
 *     s_view1_label
 */

/*
 * Globals
 */

GdkFont *g_font;                /* a fixed-width font to use */
/* color format: 0 (for static colors), r (0-64k), g (0-64k), b (0-64k) */
GdkColor fg_black = {0, 0, 0, 0};
GdkColor fg_red   = {0, 65535, 0, 0};
GdkColor bg_white = {0, 65535, 65535, 65535};
static boolean summary_mode = TRUE; /* start out in summary mode */
static boolean color_mode   = FALSE; /* start out in monochrome mode   */

/*
 * Locals
 */

/* 
 * user_data values passed to view1_button_click_callback,
 * which is used by the various action buttons noted above
 */
enum view1_button_click {
    TOP_BUTTON=1,
    BOTTOM_BUTTON,
    START_BUTTON,
    ZOOMIN_BUTTON,
    SEARCH_BUTTON,
    SEARCH_AGAIN_BUTTON,
    ZOOMOUT_BUTTON,
    END_BUTTON,
    MORE_TRACES_BUTTON,
    LESS_TRACES_BUTTON,
    SNAP_BUTTON,
    NEXT_BUTTON,
    DEL_BUTTON,
    CHASE_EVENT_BUTTON,
    CHASE_DATUM_BUTTON,
    CHASE_TRACK_BUTTON,
    UNCHASE_BUTTON,
    FORWARD_BUTTON,
    BACKWARD_BUTTON,
    SUMMARY_BUTTON,
    NOSUMMARY_BUTTON,
    SLEW_LEFT_BUTTON,
    SLEW_RIGHT_BUTTON,
};

enum chase_mode {
    CHASE_EVENT=1,
    CHASE_DATUM,
    CHASE_TRACK,
};

enum sc_dir {
    SRCH_CHASE_FORWARD = 0,
    SRCH_CHASE_BACKWARD = 1,
};

static GtkWidget *s_view1_hbox; /* see box heirarchy chart */
static GtkWidget *s_view1_vbox; /* see box heirarchy chart */
static GtkWidget *da;           /* main drawing area */
static GdkPixmap *pm;           /* and its backing pixmap */
static GdkCursor *norm_cursor;  /* the "normal" cursor */

/*
 * view geometry parameters
 *
 * Remember:
 *    Y increases down the page.
 *    Strip origin is at the top
 *    Payday is Friday
 *    Don't put your fingers in your mouth.
 *
 * Most of these values are in pixels
 */

typedef struct v1_geometry {
    int pid_ax_width;           /* Width of the PID axis */
    int time_ax_height;         /* Height of the time axis */
    int time_ax_spacing;        /* TimeAxis: Space between tick-marks */
    int strip_height;           /* Height of a regular PID trace */
    int pop_offset;             /* Vertical offset of the detail box */
    int pid_ax_offset;          /* Vertical offset of the PID axis */
    int event_offset;           /* Vertical offset of the event boxes */
    int total_height;           /* total height of da, see configure_event */
    int total_width;            /* ditto, for width */
    double last_time_interval;  /* last time interval, in f64 seconds */
    
    /* Derived values */
    int first_pid_index;        /* Index of first displayed PID */
    int npids;                  /* Max number of displayed pids */
    ulonglong minvistime;       /* in usec */
    ulonglong maxvistime;       /* in usec */
} v1_geometry_t;


/* The active geometry object */
static v1_geometry_t s_v1record; 
static v1_geometry_t *s_v1 = &s_v1record; 

/* The color array */
static GdkColor *s_color;

/* Snapshot ring */
typedef struct snapshot {
    struct snapshot *next;
    /* Screen geometry */
    v1_geometry_t geometry;
    boolean show_event[NEVENTS];
    pid_sort_t *pidvec;
    /*
     * Note: not worth recomputing the vertical scrollbar, just save
     *  its value here
     */
    gfloat vscroll_value;
    boolean summary_mode;
    boolean color_mode;
} snapshot_t;

static snapshot_t *s_snapshots;
static snapshot_t *s_cursnap;
static event_t *s_last_selected_event;

/*
 * various widgets, see the box heirarchy chart above
 * The toolkit keeps track of these things, we could lose many of 
 * these pointers. 
 */
static GtkWidget *s_view1_vmenubox;
static GtkWidget *s_view1_topbutton;
static GtkWidget *s_view1_bottombutton;
static GtkWidget *s_view1_more_traces_button;
static GtkWidget *s_view1_less_traces_button;

static GtkWidget *s_view1_hmenubox;
static GtkWidget *s_view1_hmenubox2;
static GtkWidget *s_view1_startbutton;
static GtkWidget *s_view1_zoominbutton;
static GtkWidget *s_view1_searchbutton;
static GtkWidget *s_view1_srchagainbutton;
static GtkWidget *s_view1_zoomoutbutton;
static GtkWidget *s_view1_endbutton;

static GtkWidget *s_view1_snapbutton;
static GtkWidget *s_view1_nextbutton;
static GtkWidget *s_view1_delbutton;

static GtkWidget *s_view1_chase_event_button;
static GtkWidget *s_view1_chase_datum_button;
static GtkWidget *s_view1_chase_track_button;
static GtkWidget *s_view1_unchasebutton;

static GtkWidget *s_view1_forward_button;
static GtkWidget *s_view1_backward_button;

static GtkWidget *s_view1_summary_button;
static GtkWidget *s_view1_nosummary_button;

static GtkWidget *s_view1_time_slew_right_button;
static GtkWidget *s_view1_time_slew_left_button;

static GtkWidget *s_view1_hscroll;
static GtkObject *s_view1_hsadj;

static GtkWidget *s_view1_vscroll;
static GtkObject *s_view1_vsadj;

static GtkWidget *s_view1_label;

/*
 * Search context 
 */
static ulong s_srchcode;        /* search event code */
static int s_srchindex;         /* last hit was at this event index */
static boolean s_result_up;     /* The SEARCH RESULT dongle is displayed */
static boolean s_srchfail_up;   /* The status line "Search Failed" is up */
static int srch_chase_dir;      /* search/chase dir, 0=>forward */


/*
 * Print context 
 */
static int s_print_offset;      /* Magic offset added to line, tbox fn codes */
static FILE *s_printfp;         

/*
 * Forward reference prototypes
 */
static void display_pid_axis(v1_geometry_t *vp);
static void display_event_data(v1_geometry_t *vp);
static void display_time_axis(v1_geometry_t *vp);
static void view1_button_click_callback(GtkButton *item, gpointer data);

/*
 * config params
 */

gint c_view1_draw_width;
gint c_view1_draw_height;

/*
 * Zoom-In / Time Ruler cursor
 */

#define zi_width 32
#define zi_height 32
#define zi_x_hot 22
#define zi_y_hot 14
static unsigned char zi_bits[] = {
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x88, 0x00,
   0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0xc0, 0x00,
   0x00, 0xfc, 0xff, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0xa0, 0x00,
   0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x84, 0x00,
   0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static unsigned char zi_bkgd[] = {
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x88, 0x00,
   0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0xc0, 0x00,
   0x00, 0xfc, 0xff, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0xa0, 0x00,
   0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x84, 0x00,
   0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static GdkCursor *zi_cursor;
static GdkPixmap *zi_source, *zi_mask;

/* 
 * Frequently-used small computations, best
 * done correctly once and instantiated.
 */

/****************************************************************************
* dtime_per_pixel
****************************************************************************/

static inline double dtime_per_pixel(v1_geometry_t *vp)
{
    return ((double)(vp->maxvistime - vp->minvistime)) /
        ((double)(vp->total_width - vp->pid_ax_width));
}

/****************************************************************************
* message_line
* Changes the status line.  Pass "" to clear the status line.
****************************************************************************/

void message_line (char *s)
{
    gtk_label_set_text (GTK_LABEL(s_view1_label), s);
}

/****************************************************************************
* set_window_title
* Changes the window title to include the specified filename.
****************************************************************************/

void set_window_title (const char *filename)
{
    char title[128];
    snprintf(title, sizeof(title), "g2 (%s)", filename);
    gtk_window_set_title(GTK_WINDOW(g_mainwindow), title);
}

/****************************************************************************
* recompute_hscrollbar
* Adjust the horizontal scrollbar's adjustment object.
* 
* GtkAdjustments are really cool, but have to be set up exactly
* right or the various client objects screw up completely.
*
* Note: this function is *not* called when the user clicks the scrollbar.
****************************************************************************/

static void recompute_hscrollbar (void)
{
    ulonglong current_width;
    ulonglong event_incdec;
    GtkAdjustment *adj;
    event_t *ep;

    if (g_nevents == 0)
        return;

    ep = (g_events + (g_nevents-1));
    current_width = s_v1->maxvistime - s_v1->minvistime;
    event_incdec = (current_width) / 6;

    adj = GTK_ADJUSTMENT(s_view1_hsadj);

    /* 
     * Structure member decoder ring
     * -----------------------------
     * lower             the minimum possible value
     * value             the current value
     * upper             the maximum possible value
     * step_increment    end button click increment
     * page_increment    click in trough increment
     * page_size         size of currently visible area
     */

    adj->lower = (gfloat)0.00;  
    adj->value = (gfloat)s_v1->minvistime;

    /* Minor click: move about 1/6 of a page */
    adj->step_increment = (gfloat)event_incdec;

    /* Major click: move about 1/3 of a page. */
    adj->page_increment = (gfloat)(2*event_incdec);

    /* allow the user to go a bit past the end */
    adj->upper = adj->page_increment/3 + (gfloat)(ep->time);
    adj->page_size = (gfloat)(current_width);

    /*
     * Tell all clients (e.g. the visible scrollbar) to 
     * make themselves look right 
     */
    gtk_adjustment_changed(adj);
    gtk_adjustment_value_changed(adj);
}

/****************************************************************************
* recompute_vscrollbar
* Ditto, for the vertical scrollbar
****************************************************************************/

static void recompute_vscrollbar (void)
{
    GtkAdjustment *adj;

    adj = GTK_ADJUSTMENT(s_view1_vsadj);

    adj->lower = (gfloat)0.00;
    adj->upper = (gfloat)g_npids;
    adj->value = (gfloat)0.00;
    adj->step_increment = 1.00;
    adj->page_increment = (gfloat)(s_v1->npids / 3);
    adj->page_size = (gfloat)s_v1->npids;
    gtk_adjustment_changed(adj);
    gtk_adjustment_value_changed(adj);
}

/****************************************************************************
* format_popbox_string
****************************************************************************/

elog_main_t elog_main;

void format_popbox_string (char *tmpbuf, int len, event_t *ep, event_def_t *edp)
{
    char *fp;

#ifdef NOTDEF
    sprintf(tmpbuf,"%d:", ep->code);
#endif
    if (ep->flags & EVENT_FLAG_CLIB) {
        elog_event_t *eep;
        u8 *s;

        eep = get_clib_event (ep->datum);
        
        s = format (0, "%U", format_elog_event, &elog_main, eep);
        memcpy (tmpbuf, s, vec_len(s));
        tmpbuf[vec_len(s)] = 0;
        vec_free(s);
        return;
    }

    snprintf(tmpbuf, len, "%s", edp->name);
    fp = edp->format;
    /* Make sure there's a real format string. If so, add it */
    while (fp && *fp) {
        if (*fp != ' ') {
            snprintf(tmpbuf+strlen(tmpbuf), len - strlen(tmpbuf), ": ");
            /* %s only supported for cpel files */
            if (fp[1] == 's') {
                snprintf(tmpbuf+strlen(tmpbuf), len - strlen(tmpbuf), 
                         edp->format, strtab_ref(ep->datum));
            } else {
                snprintf(tmpbuf+strlen(tmpbuf), len - strlen(tmpbuf), 
                        edp->format, ep->datum);
            }
            return;
        }
        fp++;
    }
}

/****************************************************************************
 * add_snapshot
 ****************************************************************************/

static void add_snapshot(void)
{
    int i;
    snapshot_t *new = g_malloc(sizeof(snapshot_t));

    memcpy(&new->geometry, s_v1, sizeof(new->geometry));
    for (i = 0; i < NEVENTS; i++) {
        new->show_event[i] = g_eventdefs[i].selected;
    }
    new->pidvec = g_malloc(sizeof(pid_sort_t)*g_npids);
    memcpy(new->pidvec, g_pids, sizeof(pid_sort_t)*g_npids);
    new->vscroll_value =  GTK_ADJUSTMENT(s_view1_vsadj)->value;
    new->summary_mode = summary_mode;
    new->color_mode = color_mode;

    if (s_snapshots) {
        new->next = s_snapshots;
        s_snapshots = new;
    } else {
        new->next = 0;
        s_snapshots = new;
    }
    s_cursnap = new;
}

/****************************************************************************
 * next_snapshot
 ****************************************************************************/

static void next_snapshot(void)
{
    snapshot_t *next;
    int i;
    pid_sort_t *psp;
    pid_data_t *pp;

    if (!s_snapshots) {
        infobox("No snapshots", "\nNo snapshots in the ring...\n");        
        return;
    }
    
    next = s_cursnap->next;
    if (next == 0)
        next = s_snapshots;

    s_cursnap = next;

    memcpy(s_v1, &next->geometry, sizeof(next->geometry));
    for (i = 0; i < NEVENTS; i++) {
        g_eventdefs[i].selected = next->show_event[i];
    }
    memcpy(g_pids, next->pidvec, sizeof(pid_sort_t)*g_npids);
    color_mode = next->color_mode;
    /*
     * Update summary mode via a button push so that the button state is
     * updated accordingly. (Should ideally clean up the view/controller
     * separation properly one day.)
     */
    if (summary_mode != next->summary_mode) {
        view1_button_click_callback
            (NULL, (gpointer)(unsigned long long)
             (summary_mode ? NOSUMMARY_BUTTON : SUMMARY_BUTTON));
    }

    /* Fix the pid structure index mappings */
    psp = g_pids;

    for (i = 0; i < g_npids; i++) {
        pp = psp->pid;
        pp->pid_index = i;
        psp++;
    }
    GTK_ADJUSTMENT(s_view1_vsadj)->value = next->vscroll_value;
    gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
    recompute_hscrollbar();
    pointsel_next_snapshot();
    view1_display_when_idle();
}


/****************************************************************************
 * del_snapshot
 ****************************************************************************/

static void del_snapshot(void)
{
    snapshot_t *prev;
    snapshot_t *this;

    if (!s_snapshots) {
        infobox("No snapshots", "\nNo snapshots to delete...\n");        
        return;
    }

    prev = NULL;
    this = s_snapshots;

    while (this && this != s_cursnap) {
        prev = this;
        this = this->next;
    }

    if (this != s_cursnap) {
        infobox("BUG", "\nSnapshot AWOL!\n");        
        return;
    }
 
    s_cursnap = this->next;

    /* middle of the list? */
    if (prev) {
        prev->next = this->next;
        g_free(this->pidvec);
        g_free(this);
    } else { /* start of the list */
        s_snapshots = this->next;
        g_free(this->pidvec);
        g_free(this);
    }
    
    /* Note: both will be NULL after last delete */
    if (s_cursnap == NULL)
        s_cursnap = s_snapshots;
}

/****************************************************************************
 * write_snapshot
 *
 * VERY primitive right now - not endian or version independent, and only
 * writes to "snapshots.g2" in the current directory
 ****************************************************************************/
static void write_snapshot(void)
{
    FILE *file = NULL;
    snapshot_t *snap;
    char *error = NULL;
    int records = 0;
    
    if (s_snapshots == NULL) {
        error = "No snapshots defined";
        errno = 0;
    }

    if (!error) {
        file = fopen("snapshots.g2", "w");
        if (file == NULL) {
            error = "Unable to open snapshots.g2";
        }
    }

    /*
     * Simply serialize the arch-dependent binary data, without a care in the
     * world. Don't come running to me if you try to read it and crash.
     */
    for (snap = s_snapshots; !error && snap != NULL; snap = snap->next) {
        if (fwrite(&snap->geometry, 
                   sizeof(snap->geometry), 1, file) != 1 ||
            fwrite(&snap->show_event, 
                   sizeof(snap->show_event), 1, file) != 1 ||
            fwrite(snap->pidvec, 
                   sizeof(pid_sort_t) * g_npids, 1, file) != 1 ||
            fwrite(&snap->vscroll_value, 
                   sizeof(snap->vscroll_value), 1, file) != 1 ||
            fwrite(&snap->summary_mode,  
                   sizeof(snap->summary_mode),   1, file) != 1 ||
            fwrite(&snap->color_mode,  
                   sizeof(snap->color_mode),   1, file) != 1) {
            error = "Error writing data";
        }
        records++;
    }

    if (!error) {
        if (fclose(file)) {
            error = "Unable to close file";
        }
    }

    if (error) {
        infobox(error, strerror(errno));
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrote %d snapshots to snapshots.g2", 
                 records);
        message_line(buf);
    }
}

/****************************************************************************
 * read_snapshot
 *
 * VERY primitive right now - not endian or version independent, and only reads
 * from "snapshots.g2" in the current directory
 ****************************************************************************/
static void read_snapshot(void)
{
    FILE *file;
    snapshot_t *snap, *next_snap;
    snapshot_t *new_snaps = NULL;
    char *error = NULL;
    int len, i, records = 0;
    pid_data_t *pp;

    file = fopen("snapshots.g2", "r");
    if (file == NULL) {
        error = "Unable to open snapshots.g2";
    }

    /*
     * Read in the snapshots and link them together. We insert them backwards,
     * but that's tolerable. If the data is in anyway not what we expect, we'll
     * probably crash. Sorry.
     */
    while (!error && !feof(file)) {
        snap = g_malloc(sizeof(*snap));
        snap->pidvec = NULL; /* so we can free this if there's an error */

        len = fread(&snap->geometry, sizeof(snap->geometry), 1, file);
        if (len == 0) {
            /* EOF */
            g_free(snap);
            break;
        } else {
            /* insert into list straight away */
            snap->next = new_snaps;
            new_snaps = snap;
        }
        if (len != 1) {
            error = "Problem reading first item from file";
            break;
        }
        if (fread(&snap->show_event, sizeof(snap->show_event), 1, file) != 1) {
            error = "Problem reading second item from file";
            break;
        }
        len = sizeof(pid_sort_t) * g_npids;
        snap->pidvec = g_malloc(len);
        if (fread(snap->pidvec, len, 1, file) != 1) {
            error = "Problem reading third item from file";
            break;
        }
        if (fread(&snap->vscroll_value, 
                  sizeof(snap->vscroll_value), 1, file) != 1 ||
            fread(&snap->summary_mode,  
                  sizeof(snap->summary_mode),  1, file) != 1 ||
            fread(&snap->color_mode,  
                  sizeof(snap->color_mode),  1, file) != 1) {
            error = "Problem reading final items from file";
            break;
        }

        /*
         * Fix up the pointers from the sorted pid vector back into our pid
         * data objects, by walking the linked list of pid_data_t objects for
         * every one looking for a match. This is O(n^2) grossness, but in real
         * life there aren't that many pids, and it seems zippy enough.
         */
        for (i = 0; i < g_npids; i++) {
            for (pp = g_pid_data_list; pp != NULL; pp = pp->next) {
                if (pp->pid_value == snap->pidvec[i].pid_value) {
                    break;
                }
            }
            if (pp != NULL) {
                snap->pidvec[i].pid = pp;
            } else {
                error = "Snapshot file referenced unknown pids";
                break;
            }
        }

        records++;
    }

    if (!error) {
        if (fclose(file)) {
            error = "Unable to close file";
        }
    }
        
    if (error) {
        /*
         * Problem - clear up any detritus
         */
        infobox(error, strerror(errno));
        for (snap = new_snaps; snap != NULL; snap = next_snap) {
            next_snap = snap->next;
            g_free(snap);
            g_free(snap->pidvec);
        }
    } else {
        /*
         * Success! trash the old snapshots and replace with the new
         */
        for (snap = s_snapshots; snap != NULL; snap = next_snap) {
            next_snap = snap->next;
            g_free(snap->pidvec);
            g_free(snap);
        }
        
        s_cursnap = s_snapshots = new_snaps;
    }

    if (error) {
        infobox(error, strerror(errno));
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), 
                 "Read %d snapshots from snapshots.g2", records);
        message_line(buf);
    }
}

/****************************************************************************
* set_color
*
* Set the color for the specified pid_index, or COLOR_DEFAULT to return it
* to the usual black.
****************************************************************************/
#define COLOR_DEFAULT (-1)
static void set_color(int pid_index)
{
    pid_sort_t *psp;

    psp = (g_pids + pid_index);
    
    if (psp->selected)
        gdk_gc_set_foreground(da->style->black_gc, &s_color[0]);
    else if (pid_index == COLOR_DEFAULT || !color_mode) {
        gdk_gc_set_foreground(da->style->black_gc, &fg_black);
    } else {
        gdk_gc_set_foreground(da->style->black_gc, 
                              &s_color[g_pids[pid_index].color_index]);
    }
}

/****************************************************************************
* toggle_event_select
****************************************************************************/

static int toggle_event_select(GdkEventButton *event, v1_geometry_t *vp)
{
    int pid_index, start_index;
    int x, y;
    GdkRectangle *rp;
    GdkRectangle hit_rect;
    GdkRectangle dummy;
    event_t *ep;
    event_def_t *edp;
    char tmpbuf [1024];
    double time_per_pixel;

    if (g_nevents == 0)
        return 0;

    time_per_pixel = dtime_per_pixel(vp);

    start_index = find_event_index (vp->minvistime);

    /* Too far right? */
    if (start_index >= g_nevents)
        return 0;
    
    /* 
     * To see if the mouse hit a visible event, use a variant
     * of the event display loop.
     */

    hit_rect.x = (int)event->x;
    hit_rect.y = (int)event->y;
    hit_rect.width = 1;
    hit_rect.height = 1;
    
    ep = (g_events + start_index);
    
    while ((ep->time < vp->maxvistime) && 
           (ep < (g_events + g_nevents))) {
        pid_index = ep->pid->pid_index;
        
        /* First filter: pid out of range */
        if ((pid_index < vp->first_pid_index) ||
            (pid_index >= vp->first_pid_index + vp->npids)) {
            ep++;
            continue;
        }

        /* Second filter: event hidden */
        edp = find_event_definition (ep->code);
        if (!edp->selected) {
            ep++;
            continue;
        }
        
        /* 
         * At this point, we know that the point is at least on the
         * screen. See if the mouse hit within the bounding box 
         */

        /* 
         * $$$$ maybe keep looping until off the edge,
         * maintain a "best hit", then declare that one the winner?
         */

        pid_index -= vp->first_pid_index;
        
        y = pid_index*vp->strip_height + vp->event_offset;
        
        x = vp->pid_ax_width + 
            (int)(((double)(ep->time - vp->minvistime)) / time_per_pixel);

        /* Perhaps we're trying to toggle the detail box? */
        if (ep->flags & EVENT_FLAG_SELECT) {
            /* Figure out the dimensions of the detail box */
            format_popbox_string(tmpbuf, sizeof(tmpbuf), ep, edp);
            rp = tbox(tmpbuf, x, y - vp->pop_offset, TBOX_GETRECT_BOXED);
            if (gdk_rectangle_intersect(rp, &hit_rect, &dummy)) {
                ep->flags &= ~EVENT_FLAG_SELECT;
                view1_display_when_idle();
                return 0;
            }
        } 

        sprintf(tmpbuf, "%ld", ep->code);

        /* Figure out the dimensions of the regular box */
        rp = tbox(tmpbuf, x, y, TBOX_GETRECT_EVENT);

        if (gdk_rectangle_intersect(rp, &hit_rect, &dummy)) {
            /* we hit the rectangle. */
            if (ep->flags & EVENT_FLAG_SELECT) {
                ep->flags &= ~EVENT_FLAG_SELECT;
                view1_display_when_idle();
                return 0;
            } else {
                set_color(ep->pid->pid_index);

                /* It wasn't selected, so put up the detail box */
                format_popbox_string(tmpbuf, sizeof(tmpbuf), ep, edp);
                tbox(tmpbuf, x, y - vp->pop_offset, TBOX_DRAW_BOXED);
                line(x, y-vp->pop_offset, x, y, LINE_DRAW_BLACK);
                ep->flags |= EVENT_FLAG_SELECT;
                ep->flags &= ~EVENT_FLAG_SEARCHRSLT;
                s_last_selected_event = ep;
            }
            return 0;
        }
        ep++;
    }
    return -1;
}

/****************************************************************************
* toggle_track_select
****************************************************************************/

static void toggle_track_select (GdkEventButton *event, 
                                 v1_geometry_t  *vp)
{
    int i;
    int pid_index;
    int y, delta_y;
    pid_sort_t *psp;
    
    if (g_nevents == 0)
        return;

    /* Scan pid/track axis locations, looking for a match */
    for (i = 0; i < vp->npids; i++) {
        y = i*vp->strip_height + vp->pid_ax_offset;
        delta_y = y - event->y;
        if (delta_y < 0)
            delta_y = -delta_y;
        if (delta_y < 10) {
            goto found;
        }

    }
    infobox("NOTE", "\nNo PID/Track In Range\nPlease Try Again");
    return;
    
 found:
    pid_index = i + vp->first_pid_index;
    psp = (g_pids + pid_index);
    psp->selected ^= 1;
    view1_display_when_idle();
}

/****************************************************************************
* deselect_tracks
****************************************************************************/
static void deselect_tracks (void)
{
    int i;

    for (i = 0; i < g_npids; i++)
        g_pids[i].selected = 0;

}


/****************************************************************************
* move_current_track
****************************************************************************/

typedef enum { MOVE_TOP, MOVE_BOTTOM } move_type;

static void move_current_track(GdkEventButton *event, 
                               v1_geometry_t  *vp,
                               move_type       type)
{
    int i;
    int pid_index;
    int y, delta_y;
    pid_sort_t *new_pidvec;
    pid_sort_t *psp;
    pid_sort_t *pold, *pnew;
    pid_data_t *pp;

    if (g_nevents == 0)
        return;

    /* Scan pid/track axis locations, looking for a match */
    for (i = 0; i < vp->npids; i++) {
        y = i*vp->strip_height + vp->pid_ax_offset;
        delta_y = y - event->y;
        if (delta_y < 0)
            delta_y = -delta_y;
        if (delta_y < 10) {
            goto found;
        }

    }
    infobox("NOTE", "\nNo PID/Track In Range\nPlease Try Again");
    return;
    
 found:
    pid_index = i + vp->first_pid_index;

    new_pidvec = g_malloc0(sizeof(pid_sort_t)*g_npids);
    pold = g_pids;
    pnew = new_pidvec;

    if (type == MOVE_TOP) {
        /* move to top */
        *pnew++ = g_pids[pid_index];
        for (i = 0; i < pid_index; i++)
            *pnew++ = *pold++;
        pold++;
        i++;
        for (; i < g_npids; i++)
            *pnew++ = *pold++;
    } else {
        /* move to bottom */
        for (i = 0; i < pid_index; i++)
            *pnew++ = *pold++;
        pold++;
        i++;
        for (; i < g_npids; i++)
            *pnew++ = *pold++;
        *pnew = g_pids[pid_index];
    }

    g_free(g_pids);
    g_pids = new_pidvec;

    /*
     * Revert the pid_index mapping to an identity map, 
     */
    psp = g_pids;

    for (i = 0; i < g_npids; i++) {
        pp = psp->pid;
        pp->pid_index = i;
        psp++;
    }
    view1_display_when_idle();
}

/****************************************************************************
* zoom_event
* Process a zoom gesture. The use of doubles is required to avoid 
* truncating the various variable values, which in turn would lead to
* some pretty random-looking zoom responses.
****************************************************************************/

void zoom_event(GdkEventButton *e1, GdkEventButton *e2, v1_geometry_t *vp)
{
    double xrange;
    double time_per_pixel;
    double width_in_pixels;
    double center_on_time, width_in_time;
    double center_on_pixel;

    /* 
     * Clip the zoom area to the event display area. 
     * Otherwise, center_on_time - width_in_time is in hyperspace
     * to the left of zero 
     */
       
    if (e1->x < vp->pid_ax_width)
	e1->x = vp->pid_ax_width;
    
    if (e2->x < vp->pid_ax_width)
	e2->x = vp->pid_ax_width;

    if (e2->x == e1->x)
	goto loser_zoom_repaint;

    xrange = (double) (e2->x - e1->x);
    if (xrange < 0.00)
        xrange = -xrange;

    /* Actually, width in pixels of half the zoom area */
    width_in_pixels = xrange / 2.00;
    time_per_pixel = dtime_per_pixel(vp);
    width_in_time = width_in_pixels * time_per_pixel;

    /* Center the screen on the center of the zoom area */
    center_on_pixel = (double)((e2->x + e1->x) / 2.00) - 
        (double)vp->pid_ax_width;
    center_on_time = center_on_pixel*time_per_pixel + (double)vp->minvistime;

    /*
     * Transform back to 64-bit integer microseconds, reset the
     * scrollbar, schedule a repaint. 
     */
    vp->minvistime = (ulonglong)(center_on_time - width_in_time);
    vp->maxvistime = (ulonglong)(center_on_time + width_in_time);

loser_zoom_repaint:
    recompute_hscrollbar();
    
    view1_display_when_idle();
}

/****************************************************************************
* scroll_y
*
* Scroll up or down by the specified delta
*
****************************************************************************/
static void scroll_y(int delta)
{
    int new_index = s_v1->first_pid_index + delta;
    if (new_index + s_v1->npids > g_npids)
        new_index = g_npids - s_v1->npids;
    if (new_index < 0)
        new_index = 0;
    
    if (new_index != s_v1->first_pid_index) {
        s_v1->first_pid_index = new_index;
        GTK_ADJUSTMENT(s_view1_vsadj)->value = (gdouble)new_index;
        gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
        view1_display_when_idle();
    }
}

/****************************************************************************
* view1_handle_key_press_event
* Relevant definitions in: /usr/include/gtk-1.2/gdk/gdktypes.h
*
* This routine implements hotkeys for the Quake generation:
*
*   W - zoom in
*   S - zoom out
*   A - pan left
*   D - pan right
*   R - pan up
*   F - pan down
*   T - more traces
*   G - fewer traces
*
*   E - toggle summary mode
*   C - toggle color mode
*
*   X - take snapshot
*   Z - next snapshot
*   P - persist snapshots to file
*   L - load snapshots from file
*
* ctrl-Q - exit
*
****************************************************************************/
gint
view1_handle_key_press_event (GtkWidget *widget, GdkEventKey *event)
{
    long long delta;

    switch (event->keyval) {
        case GDK_w: // zoom in
            view1_button_click_callback(NULL, (gpointer)ZOOMIN_BUTTON);
            break;

        case GDK_s: // zoom out
            view1_button_click_callback(NULL, (gpointer)ZOOMOUT_BUTTON);
            break;

        case GDK_a: // pan left
            delta = (s_v1->maxvistime - s_v1->minvistime) / 6;
            if (s_v1->minvistime < delta) {
                delta = s_v1->minvistime;
            }
            s_v1->minvistime -= delta;
            s_v1->maxvistime -= delta;
            recompute_hscrollbar();
            break;

        case GDK_d: // pan right
            delta = (s_v1->maxvistime - s_v1->minvistime) / 6;
            if (s_v1->maxvistime + delta > g_events[g_nevents - 1].time) {
                /*
                 * @@@ this doesn't seem to quite reach the far right hand
                 * side correctly - not sure why.
                 */
                delta = g_events[g_nevents - 1].time - s_v1->maxvistime;
            }
            s_v1->minvistime += delta;
            s_v1->maxvistime += delta;
            recompute_hscrollbar();
            break;

        case GDK_r: // pan up
            scroll_y(-1);
            break;

        case GDK_f: // pan down
            scroll_y(+1);
            break;

        case GDK_t: // fewer tracks
            view1_button_click_callback(NULL, (gpointer)LESS_TRACES_BUTTON);
            break;

        case GDK_g: // more tracks
            view1_button_click_callback(NULL, (gpointer)MORE_TRACES_BUTTON);
            break;

        case GDK_e: // toggle summary mode
            view1_button_click_callback
                (NULL, (gpointer)(unsigned long long)
                 (summary_mode ? NOSUMMARY_BUTTON : SUMMARY_BUTTON));
            break;

        case GDK_c: // toggle color mode
            color_mode ^= 1;
            view1_display_when_idle();
            break;

        case GDK_p: // persist snapshots
            write_snapshot();
            break;

        case GDK_l: // load snapshots
            read_snapshot();
            break;

        case GDK_x: // take snapshot
            view1_button_click_callback(NULL, (gpointer)SNAP_BUTTON);
            break;

        case GDK_z: // next snapshot
            view1_button_click_callback(NULL, (gpointer)NEXT_BUTTON);
            break;

        case GDK_q: // ctrl-q is exit
            if (event->state & GDK_CONTROL_MASK) {
                gtk_main_quit();
            }
            break;
    }
    return TRUE;
}

/****************************************************************************
* button_press_event
* Relevant definitions in: /usr/include/gtk-1.2/gdk/gdktypes.h
*
* This routine implements three functions: zoom-to-area, time ruler, and
* show/hide event detail popup. 
*
* The left mouse button (button 1) has two simultaneous functions: event 
* detail popup, and zoom-to-area. If the press and release events occur
* within a small delta-x, it's a detail popup event.  Otherwise, it's
* an area zoom.
*
* The right mouse button (button 3) implements the time ruler.
****************************************************************************/

static gint
button_press_event (GtkWidget *widget, GdkEventButton *event)
{
    static GdkEventButton press1_event;
    static boolean press1_valid;
    static GdkEventButton press3_event;
    static guint32 last_truler_time;
    static boolean press3_valid;
    static boolean zoom_bar_up;
    int time_ax_y, xdelta;
    char tmpbuf [128];
    double time_per_pixel;

    time_ax_y = 0;

    switch(event->type) {
    case GDK_BUTTON_PRESS:
        /* Capture the appropriate starting point */
        if (event->button == 1) {
            press1_valid = TRUE;
            press1_event = *event;
            return(TRUE);
        }
        if (event->button == 3) {
            press3_valid = TRUE;
            press3_event = *event;
            return(TRUE);
        }
        return(TRUE);

    case GDK_BUTTON_RELEASE:
        /* Time ruler */
        if (press3_valid) {
            press3_valid = FALSE;
            /* Fix the cursor, and repaint the screen from scratch */
            gdk_window_set_cursor (da->window, norm_cursor);
            view1_display_when_idle();
            return(TRUE);
        }
        /* Event select / zoom-to-area */
        if (press1_valid) {
            press1_valid = FALSE;
            xdelta = (int)(press1_event.x - event->x);
            if (xdelta < 0)
                xdelta = -xdelta;

            /* is the mouse more or less where it started? */
            if (xdelta < 10) {
                /* Control-left-mouse => sink the track */
                /* Shift-left-mouse => raise the track */
                if ((press1_event.state & GDK_CONTROL_MASK) ==
                    GDK_CONTROL_MASK) {
                    move_current_track(event, s_v1, MOVE_BOTTOM);
                } else if ((press1_event.state & GDK_SHIFT_MASK) ==
                           GDK_SHIFT_MASK) {
                    move_current_track(event, s_v1, MOVE_TOP);
                } else {
                    /* No modifiers: toggle the event / select track */
                    if (toggle_event_select(event, s_v1))
                        toggle_track_select(event, s_v1);
                }
                /* Repaint to get rid of the zoom bar */
                if (zoom_bar_up) {
                    /* Fix the cursor and leave. No zoom */
                    gdk_window_set_cursor (da->window, norm_cursor);
                    zoom_bar_up = FALSE;
                    break;
                }
            } else { /* mouse moved enough to zoom */
                zoom_event(&press1_event, event, s_v1);
                gdk_window_set_cursor (da->window, norm_cursor);
                zoom_bar_up = FALSE;
            }
        }  else if (event->button == 4) {
            /* scroll wheel up */
            scroll_y(event->state & GDK_SHIFT_MASK ? -10 : -1);
        } else if (event->button == 5) {
            /* scroll wheel down */
            scroll_y(event->state & GDK_SHIFT_MASK ? +10 : +1);
        }
        return(TRUE);

    case GDK_MOTION_NOTIFY:
        /* Button one followed by motion: draw zoom fence and fix cursor */
        if (press1_valid) {
            /* Fence, cursor already set */
            if (zoom_bar_up)
                return(TRUE);
            
            xdelta = (int)(press1_event.x - event->x);
            if (xdelta < 0)
                xdelta = -xdelta;
            
            /* Haven't moved enough to declare a zoom sequence yet */
            if (xdelta < 10) 
                return(TRUE);
            
            /* Draw the zoom fence, use the key-down X coordinate */
            time_ax_y = s_v1->npids * s_v1->strip_height + s_v1->pid_ax_offset;
            
            line((int)(press1_event.x), s_v1->pop_offset, 
                 (int)(press1_event.x), time_ax_y, LINE_DRAW_BLACK);
            tbox("Zoom From Here...", (int)(press1_event.x), s_v1->pop_offset,
                 TBOX_DRAW_BOXED);
            gdk_window_set_cursor(da->window, zi_cursor);
            zoom_bar_up = TRUE;
            return(TRUE);
        }
        if (press3_valid) {
            double nsec;

            gdk_window_set_cursor(da->window, zi_cursor);

            /* 
             * Some filtration is needed on Solaris, or the server will hang
             */
            if (event->time - last_truler_time < 75)
                return(TRUE);

            last_truler_time = event->time;

            line((int)(press3_event.x), s_v1->pop_offset, 
                 (int)(press3_event.x), time_ax_y, LINE_DRAW_BLACK);

            xdelta = (int)(press3_event.x - event->x);
            if (xdelta < 0)
                xdelta = -xdelta;
            
            time_per_pixel = ((double)(s_v1->maxvistime - s_v1->minvistime)) / 
                ((double)(s_v1->total_width - s_v1->pid_ax_width)); 

            time_ax_y = s_v1->npids * s_v1->strip_height + s_v1->pid_ax_offset;

            line((int)(press3_event.x), s_v1->pop_offset, 
                 (int)(press3_event.x), time_ax_y, LINE_DRAW_BLACK);
            /*
             * Note: use a fixed-width format so it looks like we're
             * erasing and redrawing the box. 
             */
            nsec = ((double)xdelta)*time_per_pixel;
            if (nsec >1e9) {
                sprintf(tmpbuf, "%8.3f sec ", nsec/1e9);
            } else if (nsec > 1e6) {
                sprintf(tmpbuf, "%8.3f msec", nsec/1e6);
            } else if (nsec > 1e3) {
                sprintf(tmpbuf, "%8.3f usec", nsec/1e3);
            } else {
                sprintf(tmpbuf, "%8.0f nsec", nsec);
            }
            s_v1->last_time_interval = nsec;
            tbox(tmpbuf, (int)(press3_event.x), s_v1->pop_offset,
                 TBOX_DRAW_BOXED);
            return(TRUE);
        }

    default:
        break;
#ifdef DEBUG
        g_print("button:\ttype = %d\n", event->type);
        g_print("\twindow = 0x%x\n", event->window);
        g_print("\tsend_event = %d\n", event->send_event);
        g_print("\ttime = %d\n", event->time);
        g_print("\tx = %6.2f\n", event->x);
        g_print("\ty = %6.2f\n", event->y);
        g_print("\tpressure = %6.2f\n", event->pressure);
        g_print("\txtilt = %6.2f\n", event->xtilt);
        g_print("\tytilt = %6.2f\n", event->ytilt);
        g_print("\tstate = %d\n", event->state);
        g_print("\tbutton = %d\n", event->button);
        g_print("\tsource = %d\n", event->source);
        g_print("\tdeviceid = %d\n", event->deviceid);
        g_print("\tx_root = %6.2f\n", event->x_root);
        g_print("\ty_root = %6.2f\n", event->y_root);
        return(TRUE);
#endif
    }

    view1_display_when_idle();

    return(TRUE);
}

/****************************************************************************
* configure_event
* Happens when the window manager resizes the viewer's main window.
****************************************************************************/

static gint
configure_event (GtkWidget *widget, GdkEventConfigure *event)
{
    /* Toss the previous drawing area backing store pixmap */
    if (pm)
        gdk_pixmap_unref(pm);
    
    /* Create a new pixmap, paint it */
    pm = gdk_pixmap_new(widget->window,
                        widget->allocation.width,
                        widget->allocation.height,
                        -1);
    gdk_draw_rectangle (pm,
                        widget->style->white_gc,
                        TRUE,
                        0, 0,
                        widget->allocation.width,
                        widget->allocation.height);

    /* Reset the view geometry parameters, as required */
    s_v1->total_width = widget->allocation.width;
    s_v1->total_height = widget->allocation.height;
    s_v1->npids = (s_v1->total_height - s_v1->time_ax_height) / 
        s_v1->strip_height;

    /* Schedule a repaint */
    view1_display_when_idle();
    return(TRUE);
}

/****************************************************************************
* expose_event
* Use backing store to fix the screen.
****************************************************************************/
static gint expose_event (GtkWidget *widget, GdkEventExpose *event)
{
    gdk_draw_pixmap(widget->window,
                    widget->style->fg_gc[GTK_WIDGET_STATE (widget)],
                    pm,
                    event->area.x, event->area.y,
                    event->area.x, event->area.y,
                    event->area.width, event->area.height);
    
    return(FALSE);
}

/****************************************************************************
* event_search_internal
* This routine searches forward from s_srchindex, looking for s_srchcode;
* wraps at the end of the buffer.
****************************************************************************/

boolean event_search_internal (void)
{
    event_t *ep;
    int i;
    int index;
    int pid_index;
    boolean full_redisplay = FALSE;
    ulonglong current_width;
    char tmpbuf [64];

    /* No events yet?  Act like the search worked, to avoid a loop */
    if (g_nevents == 0)
        return(TRUE);

    ep = (g_events + s_srchindex);
    ep->flags &= ~EVENT_FLAG_SEARCHRSLT;

    /* 
     * Assume the user wants to search [plus or minus]
     * from where they are.
     */
#ifdef notdef
    if (ep->time < s_v1->minvistime)
        s_srchindex = find_event_index (s_v1->minvistime);
#endif

    for (i = 1; i <= g_nevents; i++) {
        index = (srch_chase_dir == SRCH_CHASE_BACKWARD) ?
            (s_srchindex - i) % g_nevents :
            (i + s_srchindex) % g_nevents;
        
        ep = (g_events + index);
        
        if (ep->code == s_srchcode) {
            if (s_srchfail_up)
                message_line("");
            s_srchindex = index;
            pid_index = ep->pid->pid_index;
            
            /* Need a vertical scroll? */
            if ((pid_index < s_v1->first_pid_index) ||
                (pid_index >= s_v1->first_pid_index + s_v1->npids)) {
                if (pid_index > (g_npids - s_v1->npids))
                    pid_index = (g_npids - s_v1->npids);
                s_v1->first_pid_index = pid_index;
                GTK_ADJUSTMENT(s_view1_vsadj)->value = 
                    (gdouble)s_v1->first_pid_index;
                gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
                full_redisplay = TRUE;
            }
            
            /* Need a horizontal scroll? */
            if (ep->time < s_v1->minvistime || ep->time > s_v1->maxvistime) {
                current_width = (s_v1->maxvistime - s_v1->minvistime);
                if (ep->time < ((current_width+1) / 2)) {
                    s_v1->minvistime = 0ll;
                    s_v1->maxvistime = current_width;
                } else {
                    s_v1->minvistime = ep->time - ((current_width+1)/2);
                    s_v1->maxvistime = ep->time + ((current_width+1)/2);
                }
                recompute_hscrollbar();
                full_redisplay = TRUE;
            }
            ep->flags |= EVENT_FLAG_SEARCHRSLT;
            full_redisplay = TRUE;

#ifdef NOTDEF
            if (!full_redisplay){
                if (!s_result_up) {
                    s_result_up = TRUE;
                    time_per_pixel = dtime_per_pixel(s_v1);
                    
                    y = pid_index*s_v1->strip_height + s_v1->event_offset;
                    x = s_v1->pid_ax_width + 
                        (int)(((double)(ep->time - s_v1->minvistime)) / 
                              time_per_pixel);
                    sprintf(tmpbuf, "SEARCH RESULT");
                    tbox(tmpbuf, x, y - s_v1->pop_offset, TBOX_DRAW_BOXED);
                    line(x, y-s_v1->pop_offset, x, y, LINE_DRAW_BLACK);
                } else {
                    full_redisplay = TRUE;
                }
            }
#endif

            if (full_redisplay)
                view1_display_when_idle();
            return(TRUE);
        }
    }
    sprintf (tmpbuf, "Search for event %ld failed...\n", s_srchcode);
    message_line(tmpbuf);
    s_srchfail_up = TRUE;
    return(TRUE);
}

/****************************************************************************
* event_search_callback
****************************************************************************/

boolean event_search_callback (char *s)
{
    /* No events yet?  Act like the search worked, to avoid a loop */
    if (g_nevents == 0)
        return(TRUE);

    s_srchcode = atol(s);
    
    if (s_srchcode == 0)
        return(FALSE);

    return(event_search_internal());
}

/****************************************************************************
* event_search
****************************************************************************/

static void event_search (void)
{
    modal_dialog ("Event Search: Please Enter Event Code",
                  "Invalid: Please Reenter Event Code", NULL,
                  event_search_callback);
}

/****************************************************************************
* init_track_colors
****************************************************************************/
static void init_track_colors(void)
{
    int         i;
    unsigned    hash;
    char       *label_char;
    unsigned    RGB[3];
    gboolean    dont_care[g_npids];

    /*
     * If we've already allocated the colors once, then in theory we should
     * just be able to re-order the GCs already created to match the new track
     * order; the track -> color mapping doesn't currently change at runtime.
     * However, it's easier just to allocate everything from fresh. As a nod in
     * the direction of politeness towards our poor abused X server, we at
     * least mop up the previously allocated GCs first, although in practice
     * even omitting this didn't seem to cause a problem. 
     */
    if (s_color != NULL ) {
        gdk_colormap_free_colors(gtk_widget_get_colormap(da), 
                                 s_color, g_npids);
        clib_memset(s_color, 0, sizeof(GdkColor) * g_npids);
    } else {
        /*
         * First time through: allocate the array to hold the GCs.
         */
        s_color = g_malloc(sizeof(GdkColor) * (g_npids+1));
    }

    /*
     * Go through and assign a color for each track.
     */
    /* Setup entry 0 in the colormap as pure red (for selection) */
    s_color[0] = fg_red;

    for (i = 1; i < g_npids; i++) {
        /*
         * We compute the color from a hash of the thread name. That way we get
         * a distribution of different colors, and the same thread has the same
         * color across multiple data sets. Unfortunately, even though the
         * process name and thread id are invariant across data sets, the
         * process id isn't, so we want to exclude that from the hash. Since
         * the pid appears in parentheses after the process name and tid, we
         * can just stop at the '(' character.
         *
         * We could create a substring and use the CLIB Jenkins hash, but given
         * we're hashing ascii data, a suitable Bernstein hash is pretty much
         * just as good, and it's easiest just to compute it inline.
         */
        label_char = get_track_label(g_pids[i].pid_value);
        hash = 0;
        while (*label_char != '\0' && *label_char != '(') {
            hash = hash * 33 + *label_char++;
        }
        hash += hash >> 5;    /* even out the lower order bits a touch */

        /*
         * OK, now we have our hash. We get the color by using the first three
         * bytes of the hash for the RGB values (expanded from 8 to 16 bits),
         * and then use the fourth byte to choose one of R, G, B and mask this
         * one down. This ensures the color can't be too close to white and
         * therefore hard to see.
         *
         * We also drop the top bit of the green, since bright green on its own
         * is hard to see against white. Generally we err on the side of
         * keeping it dark, rather than using the full spectrum of colors. This
         * does result in something of a preponderance of muddy colors and a
         * bit of a lack of cheery bright ones, but at least you can read
         * everything. It would be nice to do better.
         */
        RGB[0] = (hash & 0xff000000) >> 16;
        RGB[1] = (hash & 0x007f0000) >> 8;
        RGB[2] = (hash & 0x0000ff00);
        RGB[hash % 3] &= 0x1fff;

        {
            GdkColor color = {0, RGB[0], RGB[1], RGB[2]};
            s_color[i] = color;
            g_pids[i].color_index = i;
        }
    }

    /*
     * Actually allocate the colors in one bulk operation. We ignore the return
     * values.
     */
    gdk_colormap_alloc_colors(gtk_widget_get_colormap(da), 
                              s_color, g_npids+1, FALSE, TRUE, dont_care);
}


/****************************************************************************
* chase_event_etc
* Reorder the pid_index fields so the viewer "chases" the last selected
* event.
****************************************************************************/

static void chase_event_etc(enum chase_mode mode)
{
    pid_sort_t *psp, *new_pidvec;
    pid_data_t *pp;
    event_t *ep;
    int pids_mapped;
    ulong code_to_chase;
    ulong datum_to_chase;
    ulong pid_to_chase;
    int i;
    int winner;

    if (!s_last_selected_event) {
        infobox("No selected event", 
                "\nPlease select an event and try again...\n");
        return;
    }

    /* Clear all index assignments */
    psp = g_pids;
    for (i = 0; i < g_npids; i++) {
        pp = psp->pid;
        pp->pid_index = 0xFFFFFFFF;
        psp++;
    }

    ep = s_last_selected_event;
    code_to_chase = ep->code;
    datum_to_chase = ep->datum;
    pid_to_chase = ep->pid->pid_value;
    pids_mapped = 0;
    new_pidvec = g_malloc0(sizeof(pid_sort_t)*g_npids);

    while (1) {
        if (srch_chase_dir == SRCH_CHASE_FORWARD) {
            if (ep >= g_events + g_nevents)
                break;
        } else {
            if (ep < g_events)
                break;
        }

        winner = 0;
        switch(mode) {
        case CHASE_EVENT:
            if (ep->code == code_to_chase) {
                winner = 1;
            }
            break;

        case CHASE_DATUM:
            if (ep->datum == datum_to_chase) {
                winner = 1;
            }
            break;

        case CHASE_TRACK:
            if (ep->pid->pid_value == pid_to_chase) {
                winner = 1;
            }
            break;

        default:
            infobox("BUG", "unknown mode in chase_event_etc\n");
            break;
        }

        if (winner) {
            if (ep->pid->pid_index == 0xFFFFFFFF) {
                ep->pid->pid_index = pids_mapped;
                new_pidvec[pids_mapped].pid = ep->pid;
                new_pidvec[pids_mapped].pid_value = ep->pid->pid_value;
                new_pidvec[pids_mapped].color_index = 0;
                pids_mapped++;
                if (pids_mapped == g_npids)
                    break;
            }
        }
        if (srch_chase_dir == SRCH_CHASE_FORWARD)
            ep++;
        else
            ep--;
    }

    /* Pass 2, first-to-last, to collect stragglers */
    ep = g_events;

    while (ep < g_events + g_nevents) {
        if (ep->pid->pid_index == 0xFFFFFFFF) {
            ep->pid->pid_index = pids_mapped;
            new_pidvec[pids_mapped].pid = ep->pid;
            new_pidvec[pids_mapped].pid_value = ep->pid->pid_value;
            new_pidvec[pids_mapped].color_index = 0;
            pids_mapped++;
            if (pids_mapped == g_npids)
                break;
        }
        ep++;
    }

    if (pids_mapped != g_npids) {
        infobox("BUG", "\nDidn't map all pids in chase_event_etc\n");
    }

    g_free (g_pids);
    g_pids = new_pidvec;
    
    /*
     * The new g_pids vector contains the "chase" sort, so we revert
     * the pid_index mapping to an identity map 
     */
    psp = g_pids;

    for (i = 0; i < g_npids; i++) {
        pp = psp->pid;
        pp->pid_index = i;
        psp++;
    }

    /* AutoScroll the PID axis so we show the first "chased" event */
    s_v1->first_pid_index = 0;
    GTK_ADJUSTMENT(s_view1_vsadj)->value = 0.00;
    gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
    init_track_colors();
    view1_display_when_idle();
}

/****************************************************************************
* unchase_event_etc
* Copy g_original_pids to g_pids, revert index mapping
****************************************************************************/
static void unchase_event_etc(void)
{
    int i;
    pid_sort_t *psp;
    pid_data_t *pp;

    memcpy (g_pids, g_original_pids, sizeof(pid_sort_t)*g_npids); 

    /* Fix the pid structure index mappings */
    psp = g_pids;

    for (i = 0; i < g_npids; i++) {
        pp = psp->pid;
        pp->pid_index = i;
        psp++;
    }

    /* Scroll PID axis to the top */
    s_v1->first_pid_index = 0;
    GTK_ADJUSTMENT(s_view1_vsadj)->value = 0.00;
    gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
    init_track_colors();
    view1_display_when_idle();
}

/****************************************************************************
* print_ps_header
* To fit a reasonable-sized landscape mode plot onto letter-size paper,
* scale everything by .75.
****************************************************************************/

static void print_ps_header (v1_geometry_t *vp, char *filename)
{
    time_t now;

    now = time(0);

    fprintf(s_printfp, "%%%%!PS-Adobe-3.0 EPSF-3.0\n");
    fprintf(s_printfp, "%%%%Creator: G2 Event Viewer\n");
    fprintf(s_printfp, "%%%%Title: %s\n", filename);
    fprintf(s_printfp, "%%%%CreationDate: %s", ctime(&now));
    fprintf(s_printfp, "%%%%DocumentData: Clean7Bit\n");
    fprintf(s_printfp, "%%%%Origin: 0 0\n");
    fprintf(s_printfp, "%%%%BoundingBox: 0 0 %d %d\n", vp->total_height, 
           vp->total_width);
    fprintf(s_printfp, "%%%%LanguageLevel: 2\n");
    fprintf(s_printfp, "%%%%Pages: 1\n");
    fprintf(s_printfp, "%%%%Page: 1 1\n");
    fprintf(s_printfp, "%%%%EOF\n");
    fprintf(s_printfp, "/Times-Roman findfont\n");
    fprintf(s_printfp, "12 scalefont\n");
    fprintf(s_printfp, "setfont\n");
    fprintf(s_printfp, ".75 .75 scale\n");
}

/****************************************************************************
* xrt
* Xcoordinate rotate and translate.  We need to emit postscript that
* has a reasonable aspect ratio for printing.  To do that, we rotate the
* intended picture by 90 degrees, using the standard 2D rotation 
* formula:
* 
*     Xr = x*cos(theta) - y*sin(theta);
*     Yr = x*sin(theta) + y*cos(theta);
*
* If we let theta = 90, this reduces to
*     Xr = -y
*     Yr =  x
*
* Translate back to the origin in X by adding Ymax, yielding
*     Xrt = Ymax - y
****************************************************************************/

static inline int xrt(int x, int y)
{
    return (s_v1->total_height - y);
}

static inline int yrt(int x, int y)
{
    return(x);
}

/****************************************************************************
* print_screen_callback
****************************************************************************/

static boolean print_screen_callback(char *filename)
{
    s_printfp = fopen (filename, "wt");

    if (s_printfp == NULL)
        return(FALSE);

    /*
     * This variable allows us to magically turn the view1 display
     * code into a print-driver, with a minimum of fuss. The idea is to
     * magically change TBOX_DRAW_XXX into TBOX_PRINT_XXX by adding
     * the required value, aka s_print_offset.
     * Make sure to fix g2.h if you mess here, or vice versa.
     */
    s_print_offset = TBOX_PRINT_PLAIN - TBOX_DRAW_PLAIN;

    print_ps_header(s_v1, filename);

    display_pid_axis(s_v1);
    display_event_data(s_v1);
    display_time_axis(s_v1);

    fclose (s_printfp);
    s_printfp = 0;
    s_print_offset = 0;

    /* For tactile feedback */
    view1_display_when_idle();
    return(TRUE);
}

int event_time_cmp (const void *a, const void *b)
{
    const event_t *e1 = a;
    const event_t *e2 = b;

    if (e1->time < e2->time)
        return -1;
    else if (e1->time > e2->time)
        return 1;
    return 0;
}

/****************************************************************************
* slew_tracks
****************************************************************************/
static void slew_tracks (v1_geometry_t *vp, enum view1_button_click which)
{
    event_t *ep;
    pid_sort_t *pp;
    int pid_index;
    ulonglong delta;
    
    delta = (ulonglong) (vp->last_time_interval);

    /* Make sure we don't push events to the left of the big bang */
    if (which == SLEW_LEFT_BUTTON) {
        for (ep = g_events; ep < (g_events + g_nevents); ep++) {
            pid_index = ep->pid->pid_index;
            pp = (g_pids + pid_index);
            
            if (pp->selected) {
                if (ep->time < delta) {
                    infobox("Slew Range Error", 
                            "\nCan't slew selected data left that far..."
                            "\nEvents would preceed the Big Bang (t=0)...");
                    goto out;
                }
            }
        }
    }

    for (ep = g_events; ep < (g_events + g_nevents); ep++) {
        pid_index = ep->pid->pid_index;
        pp = (g_pids + pid_index);

        if (pp->selected) {
            if (which == SLEW_LEFT_BUTTON)
                ep->time -= delta;
            else
                ep->time += delta;
        }
    }

    /* Re-sort the events, to avoid screwing up the event display */
    qsort (g_events, g_nevents, sizeof(event_t), event_time_cmp);

    /* De-select tracks */
    deselect_tracks();

out:
    view1_display_when_idle();
}

/****************************************************************************
* view1_button_click_callback 
****************************************************************************/

static void view1_button_click_callback(GtkButton *item, gpointer data)
{
    enum view1_button_click click = (enum view1_button_click) data;
    event_t *ep;
    ulonglong event_incdec;
    ulonglong current_width;
    ulonglong zoom_delta;

    current_width = s_v1->maxvistime - s_v1->minvistime;
    event_incdec = (current_width) / 3;

    if (event_incdec == 0LL)
        event_incdec = 1;

    zoom_delta = (s_v1->maxvistime - s_v1->minvistime) / 6;

    switch(click) {
    case TOP_BUTTON:
        /* First PID to top of window */
        s_v1->first_pid_index = 0;
        GTK_ADJUSTMENT(s_view1_vsadj)->value = 0.00;
        gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
        break;

    case BOTTOM_BUTTON:
        s_v1->first_pid_index = g_npids - s_v1->npids;
        if (s_v1->first_pid_index < 0)
            s_v1->first_pid_index = 0;
        GTK_ADJUSTMENT(s_view1_vsadj)->value = (gdouble)s_v1->first_pid_index;
        gtk_adjustment_value_changed(GTK_ADJUSTMENT(s_view1_vsadj));
        break;

    case SNAP_BUTTON:
        add_snapshot();
        break;

    case NEXT_BUTTON:
        next_snapshot();
        break;

    case DEL_BUTTON:
        del_snapshot();
        break;

    case CHASE_EVENT_BUTTON:
        chase_event_etc(CHASE_EVENT);
        break;

    case CHASE_DATUM_BUTTON:
        chase_event_etc(CHASE_DATUM);
        break;

    case CHASE_TRACK_BUTTON:
        chase_event_etc(CHASE_TRACK);
        break;

    case UNCHASE_BUTTON:
        unchase_event_etc();
        break;

    case START_BUTTON:
    start_button:
        s_v1->minvistime = 0LL;
        s_v1->maxvistime = current_width;
        recompute_hscrollbar();
        break;

    case ZOOMIN_BUTTON:
        s_v1->minvistime += zoom_delta;
        s_v1->maxvistime -= zoom_delta;
        recompute_hscrollbar();
        break;

    case SEARCH_AGAIN_BUTTON:
        if (s_srchcode) {
            event_search_internal();
            break;
        }
        /* NOTE FALLTHROUGH */

    case SEARCH_BUTTON:
        event_search();
        break;

    case ZOOMOUT_BUTTON:
        if (zoom_delta == 0LL)
            zoom_delta = 1;

        if (s_v1->minvistime >= zoom_delta) {
            s_v1->minvistime -= zoom_delta;
            s_v1->maxvistime += zoom_delta;
        } else {
            s_v1->minvistime = 0;
            s_v1->maxvistime += zoom_delta*2;
        }
        
        if ((s_v1->maxvistime - s_v1->minvistime) * 8 > 
            g_events[g_nevents-1].time * 9) {
            s_v1->minvistime = 0;
            s_v1->maxvistime = g_events[g_nevents-1].time * 9 / 8;
            /* Single event? Make window 1s wide... */
            if (g_nevents == 1)
                s_v1->maxvistime = 1000000;                

        }
        recompute_hscrollbar();
        break;

    case END_BUTTON:
        ep = (g_events + g_nevents - 1);
        s_v1->maxvistime = ep->time + event_incdec/3;
        s_v1->minvistime = s_v1->maxvistime - current_width;
        if (s_v1->minvistime > s_v1->maxvistime)
            goto start_button;
        recompute_hscrollbar();
        break;

    case MORE_TRACES_BUTTON:
	/* Reduce the strip height to fit more traces on screen */
	s_v1->strip_height -= 1;

	if (s_v1->strip_height < 1) {
	    s_v1->strip_height = 1;
	}

	/* Recalculate the number of strips on the screen */
	s_v1->npids = (s_v1->total_height - s_v1->time_ax_height) / 
	    s_v1->strip_height;
	recompute_vscrollbar();
	break;

    case LESS_TRACES_BUTTON:
	/* Increase the strip height to fit fewer on the screen */
	s_v1->strip_height += 1;
	if (s_v1->strip_height > 80) {
	    s_v1->strip_height = 80;
	}

	/* Recalculate the number of strips on the screen */
	s_v1->npids = (s_v1->total_height - s_v1->time_ax_height) / 
	    s_v1->strip_height;
	recompute_vscrollbar();
	break;

    case FORWARD_BUTTON:
        srch_chase_dir = SRCH_CHASE_FORWARD;
        gtk_widget_hide (s_view1_forward_button);
        gtk_widget_show (s_view1_backward_button);
        break;

    case BACKWARD_BUTTON:
        srch_chase_dir = SRCH_CHASE_BACKWARD;
        gtk_widget_show (s_view1_forward_button);
        gtk_widget_hide (s_view1_backward_button);
        break;

    case SUMMARY_BUTTON:
        summary_mode = TRUE;
        gtk_widget_hide (s_view1_summary_button);
        gtk_widget_show (s_view1_nosummary_button);
        break;

    case NOSUMMARY_BUTTON:
        summary_mode = FALSE;
        gtk_widget_show (s_view1_summary_button);
        gtk_widget_hide (s_view1_nosummary_button);
        break;

    case SLEW_LEFT_BUTTON:
    case SLEW_RIGHT_BUTTON:
        if (s_v1->last_time_interval < 10e-9) {
            infobox("slew", "\nNo time interval set...\n");        
            break;
        }
        slew_tracks (s_v1, click);
        break;
    }

    view1_display_when_idle();
}

/****************************************************************************
* view1_print_callback
****************************************************************************/

void view1_print_callback (GtkToggleButton *notused, gpointer nu2)
{
    modal_dialog("Print Screen (PostScript format) to file:",
                 "Invalid file: Print Screen to file:",
                 "g2.ps", print_screen_callback);
}

/****************************************************************************
* view1_hscroll
****************************************************************************/

static void view1_hscroll (GtkAdjustment *adj, GtkWidget *notused)
{
    ulonglong current_width;

    current_width = (s_v1->maxvistime - s_v1->minvistime);

    s_v1->minvistime = (ulonglong)(adj->value);
    s_v1->maxvistime = s_v1->minvistime + current_width;
    
    view1_display_when_idle();

#ifdef NOTDEF
    g_print ("adj->lower = %.2f\n", adj->lower);
    g_print ("adj->upper = %.2f\n", adj->upper);
    g_print ("adj->value = %.2f\n", adj->value);
    g_print ("adj->step_increment = %.2f\n", adj->step_increment);
    g_print ("adj->page_increment = %.2f\n", adj->page_increment);
    g_print ("adj->page_size = %.2f\n", adj->page_size);
#endif
}

/****************************************************************************
* view1_vscroll
****************************************************************************/

static void view1_vscroll (GtkAdjustment *adj, GtkWidget *notused)
{
    s_v1->first_pid_index = (int)adj->value;
    view1_display_when_idle();
}

void set_pid_ax_width(int width)
{
    s_v1->pid_ax_width = width;
    view1_display_when_idle();
}

/****************************************************************************
* view1_init
****************************************************************************/

void view1_init(void)
{

    c_view1_draw_width = atol(getprop_default("drawbox_width", "700"));
    c_view1_draw_height = atol(getprop_default("drawbox_height", "400"));

    s_v1->pid_ax_width = 80;
    s_v1->time_ax_height = 80;
    s_v1->time_ax_spacing = 100;
    s_v1->strip_height = 25;
    s_v1->pop_offset = 20;
    s_v1->pid_ax_offset = 34;
    s_v1->event_offset = 40;
    s_v1->total_height = c_view1_draw_height;
    s_v1->total_width = c_view1_draw_width;
    s_v1->first_pid_index = 0;

    s_v1->npids = (s_v1->total_height - s_v1->time_ax_height) / 
        s_v1->strip_height;

    s_v1->minvistime = 0;
    s_v1->maxvistime = 200;

    s_view1_vbox = gtk_vbox_new(FALSE, 5);

    s_view1_hbox = gtk_hbox_new(FALSE, 5);

    da = gtk_drawing_area_new();
    gtk_drawing_area_size(GTK_DRAWING_AREA(da), c_view1_draw_width, 
                          c_view1_draw_height);
    
#ifdef NOTDEF
    gtk_signal_connect (GTK_OBJECT (da), "motion_notify_event",
                        (GtkSignalFunc) motion_notify_event, NULL);
#endif

    gtk_signal_connect (GTK_OBJECT (da), "expose_event",
                        (GtkSignalFunc) expose_event, NULL);

    gtk_signal_connect (GTK_OBJECT(da),"configure_event",
                        (GtkSignalFunc) configure_event, NULL);

    gtk_signal_connect (GTK_OBJECT (da), "button_press_event",
                        (GtkSignalFunc) button_press_event, NULL);
    
    gtk_signal_connect (GTK_OBJECT (da), "button_release_event",
                        (GtkSignalFunc) button_press_event, NULL);
    
    gtk_signal_connect (GTK_OBJECT (da), "motion_notify_event",
                        (GtkSignalFunc) button_press_event, NULL);
    
    gtk_widget_set_events (da, GDK_BUTTON_PRESS_MASK 
                           | GDK_BUTTON_RELEASE_MASK | GDK_EXPOSURE_MASK 
                           | GDK_BUTTON_MOTION_MASK);


    gtk_box_pack_start(GTK_BOX(s_view1_hbox), da, TRUE, TRUE, 0);

    g_font = gdk_font_load ("8x13");
    if (g_font == NULL) {
        g_error("Couldn't load 8x13 font...\n");
    }
    gdk_font_ref(g_font);

    /* PID axis menu */
    s_view1_vmenubox = gtk_vbox_new(FALSE, 5);

    s_view1_vsadj = gtk_adjustment_new(0.0 /* initial value */, 
                                       0.0 /* minimum value */,
                                       2000.0 /* maximum value */,
                                       0.1 /* step increment */, 
                                       10.0/* page increment */, 
                                       10.0/* page size */);

    s_view1_vscroll = gtk_vscrollbar_new (GTK_ADJUSTMENT(s_view1_vsadj));

    gtk_signal_connect (GTK_OBJECT (s_view1_vsadj), "value-changed",
                        GTK_SIGNAL_FUNC (view1_vscroll), 
                        (gpointer)s_view1_vscroll);

    s_view1_topbutton = gtk_button_new_with_label("Top");
    s_view1_bottombutton = gtk_button_new_with_label("Bottom");

    gtk_signal_connect (GTK_OBJECT(s_view1_topbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) TOP_BUTTON);
    
    gtk_signal_connect (GTK_OBJECT(s_view1_bottombutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) BOTTOM_BUTTON);

    /* More Traces button and Less Traces button */
    s_view1_more_traces_button = gtk_button_new_with_label("More Traces");
    s_view1_less_traces_button = gtk_button_new_with_label("Less Traces");
    gtk_signal_connect (GTK_OBJECT(s_view1_more_traces_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) MORE_TRACES_BUTTON);
    gtk_signal_connect (GTK_OBJECT(s_view1_less_traces_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) LESS_TRACES_BUTTON);
    
#ifdef NOTDEF
    /* Trick to bottom-justify the menu: */
    s_view1_pad1 = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start (GTK_BOX(s_view1_vmenubox), s_view1_pad1,
                        TRUE, FALSE, 0);

#endif
    
    gtk_box_pack_start (GTK_BOX(s_view1_vmenubox), s_view1_topbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_vmenubox), s_view1_vscroll,
                        TRUE, TRUE, 0);
    
    gtk_box_pack_start (GTK_BOX(s_view1_vmenubox), s_view1_bottombutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_vmenubox), s_view1_more_traces_button,
                        FALSE, FALSE, 0);
    
    gtk_box_pack_start (GTK_BOX(s_view1_vmenubox), s_view1_less_traces_button,
                        FALSE, FALSE, 0);
    
    gtk_box_pack_start (GTK_BOX(s_view1_hbox), s_view1_vmenubox,
                        FALSE, FALSE, 0);

    /* Time axis menu */

    s_view1_hmenubox = gtk_hbox_new(FALSE, 5);
    
    s_view1_startbutton = gtk_button_new_with_label("Start");

    s_view1_zoominbutton = gtk_button_new_with_label("ZoomIn");

    s_view1_searchbutton = gtk_button_new_with_label("Search");

    s_view1_srchagainbutton = gtk_button_new_with_label("Search Again");

    s_view1_zoomoutbutton = gtk_button_new_with_label("ZoomOut");

    s_view1_endbutton = gtk_button_new_with_label("End");

    gtk_signal_connect (GTK_OBJECT(s_view1_startbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) START_BUTTON);
    
    gtk_signal_connect (GTK_OBJECT(s_view1_zoominbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) ZOOMIN_BUTTON);
    
    gtk_signal_connect (GTK_OBJECT(s_view1_searchbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) SEARCH_BUTTON);
    
    gtk_signal_connect (GTK_OBJECT(s_view1_srchagainbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) SEARCH_AGAIN_BUTTON);
    
    gtk_signal_connect (GTK_OBJECT(s_view1_zoomoutbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) ZOOMOUT_BUTTON);
    
    gtk_signal_connect (GTK_OBJECT(s_view1_endbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) END_BUTTON);
    
    s_view1_hsadj = gtk_adjustment_new(0.0 /* initial value */, 
                                       0.0 /* minimum value */,
                                       2000.0 /* maximum value */,
                                       0.1 /* step increment */, 
                                       10.0/* page increment */, 
                                       10.0/* page size */);

    s_view1_hscroll = gtk_hscrollbar_new (GTK_ADJUSTMENT(s_view1_hsadj));

    gtk_signal_connect (GTK_OBJECT (s_view1_hsadj), "value-changed",
                        GTK_SIGNAL_FUNC (view1_hscroll), 
                        (gpointer)s_view1_hscroll);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_startbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_hscroll,
                        TRUE, TRUE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_endbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_zoominbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_searchbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_srchagainbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox), s_view1_zoomoutbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_vbox), s_view1_hbox, 
                        TRUE, TRUE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_vbox), s_view1_hmenubox,
                        FALSE, FALSE, 0);


    s_view1_hmenubox2 = gtk_hbox_new(FALSE, 5);

    s_view1_snapbutton = gtk_button_new_with_label("Snap");

    s_view1_nextbutton = gtk_button_new_with_label("Next");

    s_view1_delbutton = gtk_button_new_with_label("Del");

    s_view1_chase_event_button = gtk_button_new_with_label("ChaseEvent");

    s_view1_chase_datum_button = gtk_button_new_with_label("ChaseDatum");

    s_view1_chase_track_button = gtk_button_new_with_label("ChaseTrack");

    s_view1_unchasebutton = gtk_button_new_with_label("NoChase");

    s_view1_forward_button = gtk_button_new_with_label("->SrchChase(is<-)");
    s_view1_backward_button = gtk_button_new_with_label("<-SrchChase(is->)");

    s_view1_summary_button = gtk_button_new_with_label("Summary");
    s_view1_nosummary_button = gtk_button_new_with_label("NoSummary");

    s_view1_time_slew_left_button = gtk_button_new_with_label("<-TimeSlew");
    s_view1_time_slew_right_button = gtk_button_new_with_label("TimeSlew->");

    gtk_signal_connect (GTK_OBJECT(s_view1_snapbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) SNAP_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_nextbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) NEXT_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_delbutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) DEL_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_chase_event_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) CHASE_EVENT_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_chase_datum_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) CHASE_DATUM_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_chase_track_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) CHASE_TRACK_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_unchasebutton), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) UNCHASE_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_forward_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) FORWARD_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_backward_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) BACKWARD_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_summary_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) SUMMARY_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_nosummary_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) NOSUMMARY_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_time_slew_left_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) SLEW_LEFT_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_view1_time_slew_right_button), "clicked",
                        GTK_SIGNAL_FUNC(view1_button_click_callback), 
                        (gpointer) SLEW_RIGHT_BUTTON);

    gtk_box_pack_start (GTK_BOX(s_view1_vbox), s_view1_hmenubox2,
                        FALSE, FALSE, 0);
    
    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_snapbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_nextbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_delbutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_chase_event_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_chase_datum_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_chase_track_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_unchasebutton,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_forward_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_backward_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_summary_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), s_view1_nosummary_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), 
                        s_view1_time_slew_left_button,
                        FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(s_view1_hmenubox2), 
                        s_view1_time_slew_right_button,
                        FALSE, FALSE, 0);

    s_view1_label = gtk_label_new(NULL);

    gtk_box_pack_start (GTK_BOX(s_view1_vbox), s_view1_label,
			FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX(g_mainhbox), s_view1_vbox,
                        TRUE, TRUE, 0);

    gtk_widget_show_all (s_view1_vbox);
    GTK_WIDGET_SET_FLAGS(da, GTK_CAN_FOCUS);
    gtk_widget_grab_focus(da);

    gtk_widget_hide (s_view1_forward_button);
    gtk_widget_hide (summary_mode ? s_view1_summary_button
                                  : s_view1_nosummary_button);

    zi_source = gdk_bitmap_create_from_data (NULL, (char *)zi_bits, zi_width, 
                                             zi_height);
    zi_mask = gdk_bitmap_create_from_data (NULL, (char *)zi_bkgd, zi_width,
                                           zi_height);

    zi_cursor = (GdkCursor *) gdk_cursor_new_from_pixmap (zi_source, 
                                                          zi_mask, &fg_black,
                                                          &bg_white, zi_x_hot,
                                                          zi_y_hot);
    gdk_pixmap_unref (zi_source);
    gdk_pixmap_unref (zi_mask);

    norm_cursor = (GdkCursor *) gdk_cursor_new (GDK_TOP_LEFT_ARROW);
}

/****************************************************************************
* line_print
****************************************************************************/

void line_print (int x1, int y1, int x2, int y2)
{
    fprintf(s_printfp, "newpath\n");
    fprintf(s_printfp, "%d %d moveto\n", xrt(x1, s_v1->total_height - y1), 
            yrt(x1, s_v1->total_height - y1));

    fprintf(s_printfp, "%d %d lineto\n", xrt (x2, s_v1->total_height - y2),
            yrt (x2, s_v1->total_height - y2));
    fprintf(s_printfp, "1 setlinewidth\n");
    fprintf(s_printfp, "stroke\n");
}

/****************************************************************************
* tbox_print
****************************************************************************/
GdkRectangle *tbox_print (char *s, int x, int y, enum view1_tbox_fn function,
                          GdkRectangle *rp)
{
    if (function == TBOX_PRINT_BOXED) {
        rp->width -= 4;
    }

    if ((function == TBOX_PRINT_BOXED) ||
	(function == TBOX_PRINT_EVENT)) {

        fprintf(s_printfp, "newpath\n");
        fprintf(s_printfp, "0 setlinewidth\n");
        fprintf(s_printfp, "%d %d moveto\n", 
                xrt(rp->x, s_v1->total_height - rp->y),
                yrt(rp->x, s_v1->total_height - rp->y));
        
        fprintf(s_printfp, "%d %d lineto\n", 
                xrt (rp->x+rp->width, s_v1->total_height - rp->y),
                yrt (rp->x+rp->width, s_v1->total_height - rp->y));

        fprintf(s_printfp, "%d %d lineto\n", 
                xrt(rp->x+rp->width, s_v1->total_height - (rp->y+rp->height)),
                yrt(rp->x+rp->width, s_v1->total_height - (rp->y+rp->height)));

        fprintf(s_printfp, "%d %d lineto\n", 
                xrt(rp->x, s_v1->total_height - (rp->y+rp->height)),
                yrt(rp->x, s_v1->total_height - (rp->y+rp->height)));

        fprintf(s_printfp, "%d %d lineto\n", 
                xrt(rp->x, s_v1->total_height - rp->y),
                yrt(rp->x, s_v1->total_height - rp->y));

        fprintf(s_printfp, "stroke\n");
    }

    if ((function == TBOX_PRINT_BOXED) ||
	(function == TBOX_PRINT_PLAIN)) {

        fprintf(s_printfp, "newpath\n");
        fprintf(s_printfp, "%d %d moveto\n", 
                xrt(x, s_v1->total_height - (y-2)),
                yrt(x, s_v1->total_height - (y-2)));
        fprintf(s_printfp, "gsave\n");
        fprintf(s_printfp, "90 rotate\n");
        fprintf(s_printfp, "(%s) show\n", s);
        fprintf(s_printfp, "grestore\n");
    }

    return(rp);
}    

/****************************************************************************
* tbox - draws an optionally boxed string whose lower lefthand 
* corner is at (x, y).  As usual, Y is backwards.
****************************************************************************/

GdkRectangle *tbox (char *s, int x, int y, enum view1_tbox_fn function)
{
    static GdkRectangle update_rect;
    gint lbearing, rbearing, width, ascent, descent;

    gdk_string_extents (g_font, s,
                        &lbearing, &rbearing,
                        &width, &ascent, &descent);

    /*
     * If we have enough room to display full size events, then just
     * use the BOXED function instead of the EVENT function.
     */
    if (s_v1->strip_height > 9) {
	switch (function) {
	case TBOX_DRAW_EVENT:    function = TBOX_DRAW_BOXED;    break;
	case TBOX_GETRECT_EVENT: function = TBOX_GETRECT_BOXED; break;
	case TBOX_PRINT_EVENT:   function = TBOX_PRINT_BOXED;   break;
	default:
            break;
	    /* Nothing */
	}
    }
    
    switch (function) {
    case TBOX_DRAW_BOXED:
        gdk_draw_rectangle (pm, da->style->white_gc, TRUE,
                            x, y - (ascent+descent+3), width + 2, 
                            ascent + descent + 3);
        
        gdk_draw_rectangle (pm, da->style->black_gc, FALSE,
                            x, y - (ascent+descent+3), width + 2, 
                            ascent + descent + 3);
        
        gdk_draw_string (pm, g_font, da->style->black_gc,
                         x + 1, y - 1, (const gchar *)s);
        /* NOTE FALLTHROUGH */
    case TBOX_GETRECT_BOXED:
        update_rect.x = x;
        update_rect.y = y -(ascent+descent+3);
        update_rect.width = width + 3;
        update_rect.height = ascent + descent + 4;
        if (function == TBOX_DRAW_BOXED)
            gtk_widget_draw (da, &update_rect);
        break;

    case TBOX_DRAW_EVENT:
	/* We have a small event to draw...no text */
        gdk_draw_rectangle (pm, da->style->black_gc, FALSE,
                            x, y - 1, 3, 3);
        /* NOTE FALLTHROUGH */
    case TBOX_GETRECT_EVENT:
        update_rect.x = x;
        update_rect.y = y - 1;
        update_rect.width = 4;
        update_rect.height = 4;
        if (function == TBOX_DRAW_EVENT)
            gtk_widget_draw (da, &update_rect);
	break;
		
        
    case TBOX_DRAW_PLAIN:
        
        gdk_draw_string (pm, g_font, da->style->black_gc,
                         x + 1, y - 1, (const gchar *)s);
        /* NOTE FALLTHROUGH */
    case TBOX_GETRECT_PLAIN:
        update_rect.x = x;
        update_rect.y = y -(ascent+descent+1);
        update_rect.width = width;
        update_rect.height = ascent + descent;
        if (function == TBOX_DRAW_PLAIN)
            gtk_widget_draw (da, &update_rect);
        break;

    case TBOX_PRINT_BOXED:
        update_rect.x = x;
        update_rect.y = y -(ascent+descent+3);
        update_rect.width = width + 3;
        update_rect.height = ascent + descent + 4;
        /* note fallthrough */
    case TBOX_PRINT_PLAIN:
        return(tbox_print(s, x, y, function, &update_rect));

    case TBOX_PRINT_EVENT:
	/* We have a small event box to print...no text */
        update_rect.x = x;
        update_rect.y = y - 1;
        update_rect.width = 4;
        update_rect.height = 4;
        return(tbox_print(s, x, y, function, &update_rect));
    }
    return(&update_rect);
}

/****************************************************************************
* line
*
* For lines there is a primitive batching facility, that doesn't update
* the drawing area until the batch is complete. This is handy for drawing
* the pid axis and for summary mode.
*
* line_batch_mode contains the state for this:
*
*   BATCH_OFF:      no batching, update for every line
*   BATCH_NEW:      just entered a batch, so initialize the area to update from
*                   scratch
*   BATCH_EXISTING: have drawn at least one line in batch mode, so the update
*                   area should only be expanded from now on to include the
*                   union of the "rectangular hull" of all lines
****************************************************************************/

static enum { BATCH_OFF, BATCH_NEW, BATCH_EXISTING } line_batch_mode;
static int line_batch_count;
static int line_minx, line_miny, line_maxx, line_maxy;

void line_batch_start (void)
{
    line_batch_mode = BATCH_NEW;
    line_batch_count = 0;
}

void line_batch_end (void)
{
    GdkRectangle update_rect;
    if (line_batch_count > 0) {
        update_rect.x = line_minx;
        update_rect.y = line_miny;
        update_rect.width = (line_maxx - line_minx) + 1;
        update_rect.height = (line_maxy - line_miny) + 1;
        gtk_widget_draw (da, &update_rect);
    }
    line_batch_mode = BATCH_OFF;
}

void line (int x1, int y1, int x2, int y2, enum view1_line_fn function)
{
    GdkRectangle update_rect;
    GdkGC *gc = NULL;

    switch(function) {
    case LINE_DRAW_BLACK:
        gc = da->style->black_gc;
        break;

    case LINE_DRAW_WHITE:
        gc = da->style->white_gc;
        break;

    case LINE_PRINT:
        line_print (x1, y1, x2, y2);
        return;
    }

    gdk_draw_line (pm, gc, x1, y1, x2, y2);

    switch (line_batch_mode) {
        case BATCH_OFF:
            update_rect.x = x1;
            update_rect.y = y1;
            update_rect.width = (x2-x1) + 1;
            update_rect.height = (y2-y1) + 1;
            gtk_widget_draw (da, &update_rect);
            break;

        case BATCH_NEW:
            line_minx = x1;
            line_maxx = x2;
            line_miny = y1;
            line_maxy = y2;
            line_batch_mode = BATCH_EXISTING;
            line_batch_count = 1;
            break;

        case BATCH_EXISTING:
            if (line_minx > x1)
                line_minx = x1;
            if (line_miny > y1)
                line_miny = y1;
            if (line_maxx < x2)
                line_maxx = x2;
            if (line_maxy < y2)
                line_maxy = y2;
            line_batch_count++;
            break;
    }
}


/****************************************************************************
* display_pid_axis
****************************************************************************/

static void display_pid_axis(v1_geometry_t *vp)
{
    int y, i, label_tick;
    int last_printed_y = -vp->strip_height;
    pid_sort_t *pp;
    int pid_index;
    char *label_fmt;
    char tmpbuf [128];    

    /* No pids yet? Outta here */
    if (g_pids == NULL)
        return;

    line_batch_start();

    for (i = 0; i < vp->npids; i++) {
        pid_index = vp->first_pid_index + i;
        if (pid_index >= g_npids)
            break;

        pp = (g_pids + pid_index);

        set_color(pid_index);

        label_fmt = get_track_label(pp->pid_value);
        snprintf(tmpbuf, sizeof(tmpbuf)-1, label_fmt, pp->pid_value);

        y = i*vp->strip_height + vp->pid_ax_offset;

	/*
	 * Have we incremented enough space to have another label not
	 * overlap the previous label?
	 */
	if (y - last_printed_y > 9) {
	    /* Draw label */
	    tbox(tmpbuf, 0, y +4, TBOX_DRAW_PLAIN+s_print_offset);

	    last_printed_y = y;

	    /*
	     * And let the line stick out a bit more to indicate this label
	     * relates to the following line.
	     */
	    label_tick = 4;
	}
	else {
	    label_tick = 0;
	}

        /* Draw axis line, but only if the lines aren't too close together */
	if (vp->strip_height > 4) {
	    line(vp->pid_ax_width - label_tick, y+4*s_print_offset,
		 vp->total_width, y+4*s_print_offset,
		 LINE_DRAW_BLACK+s_print_offset);
	}
    }

    set_color(COLOR_DEFAULT);
    line_batch_end();
}

/****************************************************************************
* view1_read_events_callback
* New event data just showed up, reset a few things.
****************************************************************************/

void view1_read_events_callback(void)
{
    int max_vis_index;

    s_v1->first_pid_index = 0;

    max_vis_index = 300;
    if (max_vis_index > g_nevents)
        max_vis_index = g_nevents-1;
    
    s_v1->minvistime = 0LL;
    s_v1->maxvistime = (g_events[g_nevents - 1].time * 9)/ 8;
    /* Single event? Make the initial display 1s wide */
    if (g_nevents == 1)
        s_v1->maxvistime = 1000000;
    s_srchindex = 0;
    s_srchcode = 0;
    s_last_selected_event = 0;

    init_track_colors();

    recompute_hscrollbar();
    recompute_vscrollbar();
}

/****************************************************************************
* display_event_data
****************************************************************************/

static void display_event_data(v1_geometry_t *vp)
{
    int start_index;
    int pid_index;
    int x, y;
    event_t *ep;
    event_def_t *edp;
    double time_per_pixel;
    char tmpbuf[1024];
    GdkRectangle *print_rect;
    int *last_x_used;

    /* Happens if one loads the event def header first, for example. */
    if (g_nevents == 0)
        return;

    time_per_pixel = dtime_per_pixel(vp);

    start_index = find_event_index (vp->minvistime);

    /* Scrolled too far right? */
    if (start_index >= g_nevents)
        return;

    ep = (g_events + start_index);

    if (s_print_offset || summary_mode) {
        last_x_used = (int *)g_malloc0(vp->npids * sizeof(int));
    } else {
        last_x_used = NULL;
    }

    line_batch_start();

    while (ep < (g_events + g_nevents) &&
           (ep->time < vp->maxvistime)) {
        pid_index = ep->pid->pid_index;
        set_color(pid_index);
    
        /* First filter: pid out of range */
        if ((pid_index < vp->first_pid_index) ||
            (pid_index >= vp->first_pid_index + vp->npids)) {
            ep++;
            continue;
        }

        /* Second filter: event hidden */
        edp = find_event_definition (ep->code);
        if (!edp->selected) {
            ep++;
            continue;
        }
        
        /* Display it... */

        pid_index -= vp->first_pid_index;
        
        y = pid_index*vp->strip_height + vp->event_offset;
        
        x = vp->pid_ax_width + 
            (int)(((double)(ep->time - vp->minvistime)) / time_per_pixel);

        if (last_x_used != NULL && x < last_x_used[pid_index]) {
            ep++;
            continue;
        }

        if (ep->flags & (EVENT_FLAG_SELECT | EVENT_FLAG_SEARCHRSLT)) {
            if (ep->flags & EVENT_FLAG_SELECT) {
                format_popbox_string(tmpbuf, sizeof(tmpbuf), ep, edp);
#ifdef NOTDEF
                sprintf(tmpbuf, edp->name);
                sprintf(tmpbuf+strlen(tmpbuf), ": ");
                sprintf(tmpbuf+strlen(tmpbuf), edp->format, ep->datum);
#endif
            } else {
                sprintf(tmpbuf, "SEARCH RESULT");
            }
            print_rect = tbox(tmpbuf, x, y - vp->pop_offset, 
                              TBOX_DRAW_BOXED+s_print_offset);
            line(x, y-vp->pop_offset, x, y, LINE_DRAW_BLACK+s_print_offset);
            if (last_x_used != NULL)
                last_x_used[pid_index] = x + print_rect->width;
        } 
        if (summary_mode) {
            int delta = vp->strip_height / 3;
            if (delta < 1)
                delta = 1;
            y = pid_index*vp->strip_height + vp->pid_ax_offset;
            line(x, y - delta, x, y + delta, LINE_DRAW_BLACK);
            last_x_used[pid_index] = x + 1;
        } else {
            sprintf(tmpbuf, "%ld", ep->code);
            print_rect = tbox(tmpbuf, x, y, TBOX_DRAW_EVENT+s_print_offset);
            if (last_x_used != NULL)
                last_x_used[pid_index] = x + print_rect->width;
        }

        ep++;
    }
    if (last_x_used)
        g_free(last_x_used);
    line_batch_end();
    set_color(COLOR_DEFAULT);
}

/****************************************************************************
* display_clear
****************************************************************************/

static void display_clear(void)
{
    GdkRectangle update_rect;

    gdk_draw_rectangle (pm, da->style->white_gc, TRUE,
                        0, 0, da->allocation.width,
                        da->allocation.height);

    update_rect.x = 0;
    update_rect.y = 0;
    update_rect.width = da->allocation.width;
    update_rect.height = da->allocation.height;

    gtk_widget_draw (da, &update_rect);
}

/****************************************************************************
* display_time_axis
****************************************************************************/

static void display_time_axis(v1_geometry_t *vp)
{
    int x, y, i;
    int xoffset, nticks;
    char tmpbuf [128];
    double unit_divisor;
    double time;
    char *units;
    double time_per_pixel;

    y = vp->npids * vp->strip_height + vp->pid_ax_offset;

    x = vp->pid_ax_width;

    nticks = (vp->total_width - vp->pid_ax_width) / vp->time_ax_spacing;

    time_per_pixel = dtime_per_pixel(vp);

    units = "ns";
    unit_divisor = 1.00;
        
    if ((vp->maxvistime / unit_divisor) > 1000) {
        units = "us";
        unit_divisor = 1000.00;
    }

    if ((vp->maxvistime / unit_divisor) > 1000) {
        units = "ms";
        unit_divisor = 1000.00*1000.00;
    }
    if ((vp->maxvistime / unit_divisor) > 1000) {
        units = "s";
        unit_divisor = 1000.00*1000.00*1000.00;
    }

    /* Draw line */
    line(x, y, vp->total_width, y, LINE_DRAW_BLACK+s_print_offset);

    xoffset = 0;
    
    for (i = 0; i < nticks; i++) {
        /* Tick mark */
        line(x+xoffset, y-3, x+xoffset, y+3, LINE_DRAW_BLACK+s_print_offset);

        time = (double)(x + xoffset - vp->pid_ax_width);
        time *= time_per_pixel;
        time += (double)(vp->minvistime);
        time /= unit_divisor;

        sprintf (tmpbuf, "%.2f%s", time, units);

        tbox(tmpbuf, x+xoffset, y+15, TBOX_DRAW_PLAIN+s_print_offset);
        
        xoffset += vp->time_ax_spacing;
    }
}

/****************************************************************************
* clear_scoreboard
* Forget about any temporary displays, they're gone now...
****************************************************************************/

static void clear_scoreboard(void)
{
    s_result_up = FALSE;
}

/****************************************************************************
* view1_display
****************************************************************************/

void view1_display(void)
{
    display_clear();
    display_pid_axis(s_v1);
    display_event_data(s_v1);
    display_time_axis(s_v1);
    clear_scoreboard();
}

static gint idle_tag;

/****************************************************************************
* view1_display_eventually
****************************************************************************/

static void view1_display_eventually(void)
{
    gtk_idle_remove(idle_tag);
    idle_tag = 0;
    view1_display();
}


/****************************************************************************
* view1_display_when_idle
****************************************************************************/

void view1_display_when_idle(void)
{
    if (idle_tag == 0) {
        idle_tag = gtk_idle_add((GtkFunction) view1_display_eventually, 0);
    }
}

/****************************************************************************
* view1_about
****************************************************************************/

void view1_about (char *tmpbuf)
{
    int nsnaps;
    snapshot_t *snaps;

    sprintf(tmpbuf+strlen(tmpbuf), "Minvistime %lld\nMaxvistime %lld\n",
            s_v1->minvistime, s_v1->maxvistime);
    sprintf(tmpbuf+strlen(tmpbuf), "Strip Height %d\n", 
            s_v1->strip_height);

    for (nsnaps = 0, snaps = s_snapshots; snaps; snaps = snaps->next) {
        nsnaps++;
    }
    sprintf(tmpbuf+strlen(tmpbuf), "%d snapshots in the ring\n", nsnaps);
}
