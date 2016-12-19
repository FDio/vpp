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
#include <strings.h>
#include <ctype.h>
#include <string.h>
#include <gtk/gtk.h>
#include "g2.h"

/*
 * globals
 */
event_def_t g_eventdefs[NEVENTS];

/*
 * locals
 */
static GtkWidget *s_pointselbox;
static FILE *s_hfp;
static FILE *s_elog_hfp;
static int s_basenum;
static GtkWidget *s_event_buttons[NEVENTS];
static int s_min_shown_pointsel;
static int s_max_shown_pointsel;
static GtkWidget *s_allbutton;
static GtkWidget *s_nonebutton;
static GtkWidget *s_pointselbuttons;
static GtkWidget *s_ps_vscroll;
static GtkObject *s_ps_vsadj;
static int g_neventdefs;

enum button_click {
    ALL_BUTTON=1,
    NONE_BUTTON,
};

/*
 * config params
 */
int c_maxpointsel;

/****************************************************************************
* recompute_vscrollbar
****************************************************************************/

static void recompute_ps_vscrollbar (void)
{
    GtkAdjustment *adj;
    ulong limit;

    adj = GTK_ADJUSTMENT(s_ps_vsadj);

#ifdef NOTDEF
    /* This seems like the right calculation, but seems not to work */
    if (g_neventdefs > c_maxpointsel)
        limit = g_neventdefs - c_maxpointsel;
    else
        limit = g_neventdefs;
#else
    limit = g_neventdefs-1;
#endif

    adj->lower = (gfloat)0.00;
    adj->upper = (gfloat)limit;
    adj->value = (gfloat)0.00;
    adj->step_increment = (gfloat)1.00;
    adj->page_increment = (gfloat)(c_maxpointsel / 3);
    adj->page_size = (gfloat)c_maxpointsel;
    gtk_adjustment_changed(adj);
    gtk_adjustment_value_changed(adj);
    gtk_widget_show(s_ps_vscroll);
}

/****************************************************************************
* point_select_callback
****************************************************************************/

static void point_select_callback(GtkToggleButton *item, gpointer data)
{
    int i = (int) (unsigned long long) data;

    g_eventdefs[i].selected = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(s_event_buttons[i]));
    view1_display_when_idle();
}

/****************************************************************************
* up_button
****************************************************************************/

static void up_button(void)
{
    int i;
    int increment = c_maxpointsel/4;

    if (s_min_shown_pointsel == 0)
        return;

    s_min_shown_pointsel -= increment;

    if (s_min_shown_pointsel < 0)
        s_min_shown_pointsel = 0;

    s_max_shown_pointsel = s_min_shown_pointsel + c_maxpointsel;

    for (i = 0; i < g_neventdefs; i++) {
        if (i >= s_min_shown_pointsel &&
            i <= s_max_shown_pointsel)
            gtk_widget_show(s_event_buttons[i]);
        else
            gtk_widget_hide(s_event_buttons[i]);
    }

}

#ifdef NOTDEF
/****************************************************************************
* down_button
****************************************************************************/

static void down_button(void)
{
    int i;
    int increment = c_maxpointsel/4;

    if (s_max_shown_pointsel == g_neventdefs)
        return;

    s_max_shown_pointsel += increment;

    if (s_max_shown_pointsel >= g_neventdefs)
        s_max_shown_pointsel = (g_neventdefs-1);

    s_min_shown_pointsel = s_max_shown_pointsel - c_maxpointsel;

    if (s_min_shown_pointsel < 0)
        s_min_shown_pointsel = 0;

    for (i = 0; i < g_neventdefs; i++) {
        if (i >= s_min_shown_pointsel &&
            i <= s_max_shown_pointsel)
            gtk_widget_show(s_event_buttons[i]);
        else
            gtk_widget_hide(s_event_buttons[i]);
    }

}
#endif

/****************************************************************************
* button_click_callback
****************************************************************************/

static void button_click_callback(GtkButton *item, gpointer data)
{
    int i;
    enum button_click click = (enum button_click)data;

    switch (click) {
    case ALL_BUTTON:
        for (i = 0; i < g_neventdefs; i++) {
            gtk_toggle_button_set_active (
                GTK_TOGGLE_BUTTON(s_event_buttons[i]), TRUE);
            g_eventdefs[i].selected = TRUE;
        }
        break;

    case NONE_BUTTON:
        for (i = 0; i < g_neventdefs; i++) {
            gtk_toggle_button_set_active (
                GTK_TOGGLE_BUTTON(s_event_buttons[i]), FALSE);
            g_eventdefs[i].selected = FALSE;
        }
        break;
    }
}

/****************************************************************************
* scroll_callback
****************************************************************************/

static void scroll_callback (GtkAdjustment *adj, GtkWidget *notused)
{
    int i;

    s_min_shown_pointsel = (int)adj->value;
    s_max_shown_pointsel = s_min_shown_pointsel + c_maxpointsel;

    for (i = 0; i < g_neventdefs; i++) {
        if (i >= s_min_shown_pointsel &&
            i <= s_max_shown_pointsel)
            gtk_widget_show(s_event_buttons[i]);
        else
            gtk_widget_hide(s_event_buttons[i]);
    }
}

/****************************************************************************
* point_selector_init
****************************************************************************/

void point_selector_init(void)
{

    c_maxpointsel = atol(getprop_default("event_selector_lines", "20"));

    s_pointselbox = gtk_vbox_new(FALSE,5);

    s_pointselbuttons = gtk_hbox_new(FALSE,5);

    s_allbutton = gtk_button_new_with_label("ALL");
    gtk_widget_show(s_allbutton);
    s_nonebutton = gtk_button_new_with_label("NONE");
    gtk_widget_show(s_nonebutton);

    gtk_signal_connect (GTK_OBJECT(s_allbutton), "clicked",
                        GTK_SIGNAL_FUNC(button_click_callback), 
                        (gpointer) ALL_BUTTON);

    gtk_signal_connect (GTK_OBJECT(s_nonebutton), "clicked",
                        GTK_SIGNAL_FUNC(button_click_callback), 
                        (gpointer) NONE_BUTTON);

    gtk_box_pack_start(GTK_BOX(s_pointselbuttons), s_allbutton, FALSE, 
                       FALSE, 0);
    gtk_box_pack_start(GTK_BOX(s_pointselbuttons), s_nonebutton, FALSE, 
                       FALSE, 0);
    
    gtk_widget_show(s_pointselbuttons);
    gtk_widget_ref(s_pointselbuttons); 

    gtk_box_pack_start(GTK_BOX(s_pointselbox), s_pointselbuttons, FALSE, 
                       FALSE, 0);

    gtk_box_pack_end (GTK_BOX(g_mainhbox), s_pointselbox, 
                       FALSE, FALSE, 0);

    s_ps_vsadj = gtk_adjustment_new(0.0 /* initial value */, 
                                    0.0 /* minimum value */,
                                    2000.0 /* maximum value */,
                                    0.1 /* step increment */, 
                                    10.0/* page increment */, 
                                    10.0/* page size */);
    
    s_ps_vscroll = gtk_vscrollbar_new (GTK_ADJUSTMENT(s_ps_vsadj));
    gtk_signal_connect (GTK_OBJECT (s_ps_vsadj), "value-changed",
                        GTK_SIGNAL_FUNC (scroll_callback), 
                        (gpointer)s_ps_vscroll);
    gtk_box_pack_end(GTK_BOX(g_mainhbox), s_ps_vscroll, FALSE, FALSE, 0);
}

/****************************************************************************
* sxerox
****************************************************************************/

char *sxerox (char *s)
{
    char *rv;

    /* Note: g_malloc does or dies... */
    rv = (char *)g_malloc(strlen(s)+1);
    strcpy (rv, s);
    return (rv);
}

/****************************************************************************
* reset_point_selector
****************************************************************************/

static void reset_point_selector(void)
{
    int i;

    gtk_widget_hide(s_pointselbox);
    gtk_widget_hide(s_pointselbuttons);
    gtk_widget_hide(s_ps_vscroll);
    gtk_container_remove(GTK_CONTAINER(s_pointselbox), 
                         s_pointselbuttons);
    
    for (i = 0; i < g_neventdefs; i++) {
        if (s_event_buttons[i]) {
            gtk_container_remove(GTK_CONTAINER(s_pointselbox), 
                                 s_event_buttons[i]);
            s_event_buttons[i] = 0;
        }
    }
}

/****************************************************************************
* create_point_selector
****************************************************************************/

static void create_point_selector(void)
{
    int i;
    char tmpbuf [1024];
    event_def_t *ep;
    GtkWidget *wp;

    for (i = 0; i < g_neventdefs; i++) {
        ep = &g_eventdefs[i];
        sprintf(tmpbuf, "[%lu] %s", ep->event, 
                ep->name ? ep->name : "(none)");
        /* Hack to reduce width of point selectors */
        if (strlen(tmpbuf) > 50) {
            tmpbuf[50] = 0;
        }

        wp = gtk_check_button_new_with_label (tmpbuf);
        s_event_buttons[i] = wp;
        gtk_signal_connect (GTK_OBJECT(wp), "toggled",
                            GTK_SIGNAL_FUNC(point_select_callback), 
                            (gpointer) (unsigned long long) i);
        gtk_toggle_button_set_active (
            GTK_TOGGLE_BUTTON(wp), TRUE);
        gtk_box_pack_start(GTK_BOX(s_pointselbox), wp, FALSE, FALSE, 0);
    }

    /* set up scroll parameters by faking an up-button */
    s_min_shown_pointsel = 1;
    up_button();

    gtk_box_pack_start(GTK_BOX(s_pointselbox), s_pointselbuttons, FALSE, 
                       FALSE, 0);
    gtk_widget_show(s_pointselbuttons);
    gtk_widget_show(s_pointselbox);
    gtk_widget_show(s_ps_vscroll);
}

/****************************************************************************
* remove_all_events
****************************************************************************/

static void remove_all_events(void)
{
    event_def_t *ep;
    int i;

    for (i = 0; i < g_neventdefs; i++) {
        ep = &g_eventdefs[i];
        if (!ep->is_clib) {
            if (ep->name)
                g_free(ep->name);
            if(ep->format)
                g_free(ep->format);
        }
    }
    g_neventdefs = 0;
}

/****************************************************************************
* add_event
****************************************************************************/

static void add_event(ulong event, char *name, char *format)
{
    int i;
    event_def_t *ep;

    if (g_neventdefs >= NEVENTS) {
        g_error("Too many event definitions, increase NEVENTS!");
        /*NOTREACHED*/
    }
        
    /* Simple dup check, probably not needed very often */
    for (i = 0; i < g_neventdefs; i++) {
        if (g_eventdefs[i].event == event) {
            g_warning("Duplicate def event %lu: first definition retained\n",
                      event);
            return;
        }
    }

    ep = &g_eventdefs[g_neventdefs++];

    ep->event = event;
    ep->name = sxerox(name);
    ep->format = sxerox(format);
    ep->selected = TRUE;
}

/****************************************************************************
* add_event_from_cpel_file
****************************************************************************/

void add_event_from_cpel_file(ulong event, char *event_format, 
                              char *datum_format)
{
    event_def_t *ep;

    if (g_neventdefs >= NEVENTS) {
        g_error("Too many event definitions, increase NEVENTS!");
        /*NOTREACHED*/
    }

    ep = &g_eventdefs[g_neventdefs++];

    ep->event = event;
    /*
     * Duplicate the strings for backward compatibility. Otherwise,
     * the g_free above will barf because the name/format strings are
     * actually in mmap'ed memory 
     */
    ep->name = sxerox(event_format);
    ep->format = sxerox(datum_format);
    ep->selected = TRUE;
}

/****************************************************************************
* add_event_from_clib_file
****************************************************************************/

void add_event_from_clib_file(unsigned int event, char *name, 
                              unsigned int vec_index)
{
    event_def_t *ep;

    if (g_neventdefs >= NEVENTS) {
        g_error("Too many event definitions, increase NEVENTS!");
        /*NOTREACHED*/
    }

    ep = &g_eventdefs[g_neventdefs++];

    ep->event = event;

    ep->name = sxerox(name);
    ep->format = (void *)(unsigned long long) vec_index;
    ep->selected = TRUE;
    ep->is_clib = TRUE;
}

/****************************************************************************
* read_header_file - eats header file lines of the form
*
*     #define EVENT_FOO  123	/ * name: %d * /
*
****************************************************************************/

static void read_header_file (void)
{
    char tmpbuf [1024];
    char *name, *format;
    char *cp;
    unsigned long event;
    int ev_num_flag;

    while (fgets (tmpbuf, sizeof (tmpbuf), s_hfp))
    {
        cp = tmpbuf;
        ev_num_flag = 0;

        if (strncmp (cp, "#define", 7))
            continue;

        /* skip #define */
        while (*cp && !(isspace ((int)*cp)))
            cp++;

        if (*cp == 0)
            continue;

        /* skip ws after #define */
        while (*cp && isspace ((int)*cp))
            cp++;
            
        if (*cp == 0)
            continue;

        /* skip symbolic name */
        while (*cp && !(isspace ((int)*cp)))
            cp++;

        if (*cp == 0)
            continue;

        /* skip ws after symbolic name */
        while (*cp && isspace ((int)*cp))
            cp++;
            
        if (*cp == 0)
            continue;

        event = 0;

        if (!strncmp(cp, "EV_NUM", 6)) {
            cp += 6;
            ev_num_flag = 1;

            while (*cp && *cp != '(')
                cp++;
            
            if (*cp == 0)
                continue;

            cp++; 

            while (*cp && isspace ((int)*cp))
                cp++;
            
        } 

        /* eat event code. */
        while (*cp && isdigit ((int)*cp))
        {
            event = event * 10 + (*cp - '0');
            cp++;
        }

        if (*cp == 0)
            continue;

        if (ev_num_flag) {
            while (*cp && *cp != ')')
                cp++;
            if (*cp == 0)
                continue;
            cp++;
            event += s_basenum;
        }

        /* skip ws after event code */
        while (*cp && isspace ((int)*cp))
            cp++;
            
        if (*cp != '/')
            continue;

        cp++;

        if (*cp != '*')
            continue;

        cp++;

        /* skip ws after comment start */
        while (*cp && isspace ((int)*cp))
            cp++;

        if (*cp == 0)
            continue;

        name = cp;

        /* accumulate name */
        while (*cp && *cp != ':' && *cp != '*')
            cp++;

        if (*cp == 0)
            continue;

        *cp++ = 0;
        
        /* skip ws after name: */
        while (*cp && isspace ((int)*cp))
            cp++;
        
        if (*cp == 0 || *cp == '/')
        {
            format = " ";
            goto write_it;
        }

        format = cp;
        
        /* accumulate format string */
        while (*cp && !isspace ((int)*cp))
            cp++;

        *cp = 0;

    write_it:

        add_event (event, name, format);
    }
}

/****************************************************************************
* read_header_files - eats header file lines of the form
*
*     #define FILE1_BASE  100	/ * pointdefs: ../vpn/vpn_points.h * /
*
****************************************************************************/

static boolean read_header_files (void)
{
    char *cp, *name;
    char tmpbuf [1024];
    int basenum;
    boolean rv=FALSE;

    while (fgets (tmpbuf, sizeof (tmpbuf), s_elog_hfp))
    {
        cp = tmpbuf;

        if (strncmp (cp, "#define", 7))
            continue;

        cp += 7;

        /* skip ws after #define */
        while (*cp && isspace ((int)*cp))
            cp++;

        if (*cp == 0)
            continue;

        /* skip EV_COMPxxx_START */
        while (*cp && !isspace((int)*cp))
            cp++;

        if (*cp == 0)
            continue;

        /* skip ws after EV_COMPxxx_START */
        while (*cp && isspace ((int)*cp))
            cp++;
        
        if (*cp == 0)
            continue;
        
        basenum = atol (cp);
        
        /* skip #define */
        while (*cp && (*cp != '/'))
            cp++;

        if (*cp == 0)
            continue;

        cp++;
        if (*cp != '*')
            continue;

        cp++;

        /* skip ws after comment start */
        while (*cp && isspace ((int)*cp))
            cp++;

        if (*cp == 0)
            continue;

        if (strncmp (cp, "pointdefs:", 10))
            continue;

        cp += 10;

        /* skip ws after comment start */
        while (*cp && isspace ((int)*cp))
            cp++;

        name = cp;

        while (*cp && !isspace ((int)*cp))
            cp++;
       
        *cp = 0;

        s_hfp = fopen (name, "rt");

        if (s_hfp == NULL) {
            g_warning ("Couldn't open header file %s\n", name);
            continue;
        }
        rv = TRUE;

        s_basenum = basenum;

        read_header_file();

        fclose (s_hfp);
    }
    return(rv);
}

/****************************************************************************
* event_def_cmp
****************************************************************************/

int event_def_cmp(const void *a1, const void *a2)
{
    event_def_t *e1 = (event_def_t *)a1;
    event_def_t *e2 = (event_def_t *)a2;

    if (e1->event < e2->event)
        return(-1);
    else if (e1->event == e2->event)
        return(0);
    else
        return(1);
}

/****************************************************************************
* sort_event_definitions
****************************************************************************/

void sort_event_definitions(void)
{
    qsort(&g_eventdefs[0], g_neventdefs, sizeof(event_def_t), event_def_cmp);
}

static boolean remove_needed=TRUE;

void finalize_events(void)
{
    sort_event_definitions();
    create_point_selector();
    recompute_ps_vscrollbar();
    view1_display_when_idle();
    remove_needed = TRUE;
}

void initialize_events(void)
{
    if (remove_needed) {
        reset_point_selector();
        remove_all_events();
        remove_needed = FALSE;
    }
}

/****************************************************************************
* read_event_definitions
****************************************************************************/

boolean read_event_definitions (char *filename)
{
    char tmpbuf [128];

    initialize_events();

    s_elog_hfp = fopen (filename, "rt");
    if (s_elog_hfp == NULL) {
        sprintf (tmpbuf, "Couldn't open %s\n", filename);
        infobox ("Open Failed", tmpbuf);
        return(FALSE);
    }
    /* Presume "elog.h".  Note fallthrough... */
    if (read_header_files()) {
        sort_event_definitions();
        create_point_selector();
        recompute_ps_vscrollbar();
        fclose(s_elog_hfp);
        view1_display_when_idle();
        remove_needed = TRUE;
        return(TRUE);
    }
    fclose(s_elog_hfp);

    s_hfp = fopen (filename, "rt");
    if (s_hfp == NULL) {
        sprintf (tmpbuf, "Couldn't open %s\n", filename);
        infobox ("Read Event Definition Failure", tmpbuf);
        return(FALSE);
    }

    read_header_file();

    /* Happens if the user feeds us the wrong file, for example */
    if (g_neventdefs == 0) {
        sprintf (tmpbuf, "No event definitions found in %s\n", filename);
        infobox ("No Event Definitions?", tmpbuf);
        return(FALSE);
    }
    finalize_events();
    return(TRUE);
}

static event_def_t dummy_event;
static char dummy_string[32];

/****************************************************************************
* find_event_definition
* Binary search for first event whose time is >= t
****************************************************************************/

event_def_t *find_event_definition (ulong code)
{
    int index, bottom, top;
    event_def_t *edp;

    if (g_neventdefs == 0)
        goto use_dummy;

    bottom = g_neventdefs-1;
    top = 0;

    while (1) {
	index = (bottom + top) / 2;

        edp = (g_eventdefs + index);
        
        if (edp->event == code)
            return(edp);

        if (top >= bottom) {
        use_dummy:
            edp = &dummy_event;
            edp->selected = TRUE;
            edp->event = code;
            edp->format = "0x%x";
            sprintf (dummy_string, "E%lu", code);
            edp->name = &dummy_string[0];
            return(edp);
        }

        if (edp->event < code)
            top = index + 1;
        else 
            bottom = index - 1;
    }
}

/****************************************************************************
* pointsel_next_snapshot
* Set dialog buttons from snapshot
****************************************************************************/

void pointsel_next_snapshot(void)
{
    int i;
    
    for (i = 0; i < g_neventdefs; i++) {
        gtk_toggle_button_set_active (
            GTK_TOGGLE_BUTTON(s_event_buttons[i]), 
            g_eventdefs[i].selected);
    }
}

/****************************************************************************
* pointsel_about
****************************************************************************/

void pointsel_about (char *tmpbuf)
{
    sprintf (tmpbuf+strlen(tmpbuf), "%d event definitions\n", 
             g_neventdefs);
}
