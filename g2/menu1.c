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
#include <gtk/gtk.h>
#define GTK_ENABLE_BROKEN // DGMS
#include <gtk/gtktext.h>
#include <stdlib.h>
#include "g2.h"
#include <string.h>

/*
 * locals
 */
static GtkWidget *s_mainmenubar;
static GtkWidget *s_filemenu;
static GtkWidget *s_readdefs;
static GtkWidget *s_readevents;
static GtkWidget *s_readeventsclock;
static GtkWidget *s_readcpel;
static GtkWidget *s_readclib;
static GtkWidget *s_print;
static GtkWidget *s_quit;

static GtkWidget *s_mainfilemenu;
static GtkWidget *s_help_general;
static GtkWidget *s_help_about;
static GtkWidget *s_mainhelpmenu;
static GtkWidget *s_helpmenu;

static GtkWidget *s_filesel;
static GtkWidget *s_eventsel;

typedef struct md_ {
    GtkWidget *entry;
    GtkWidget *label;
    GtkWidget *dialog;
    boolean (*callback)(char *);
    char *retry_text;
} md_t;

char *general_help = "\n"
"G2 is a performance event visualization tool.\n"
"\n"
"To view CPEL-format event data:\n"
"g2 --cpel <filename>\n"
"or use the File Menu->Read CPEL file option.\n"
"\n"
"To view vppinfra-format (.../open-repo/vppinfra/vppinfra/elog.h) event data:\n"
"g2 --clib <filename>\n"
"or use the File Menu->Read clib file option.\n"
"\n"
"To toggle event detail boxes, left-mouse-click on an event.\n"
"\n"
"To zoom to an area, depress the left mouse button. Move the\n"
"mouse. Release the mouse.\n"
"\n"
"To use the time ruler, depress the right mouse button.  Move the\n"
"mouse. Release when done.\n"
"\n"
"To push a track to the bottom, <ctrl><left-mouse>\n"
"\n"
"To pull a track to the top, <shift><left-mouse>\n"
"\n"
"To selectively color/uncolor a track, <ctrl><shift><left-mouse>\n"
"\n"
"To make the mouse scrollwheel faster, press <shift>\n"
"\n"
"Hotkeys, supposedly Quake-like:\n"
"      w - zoom-in\n"
"      s - zoom-out\n"
"      a - pan-left\n"
"      d - pan-right\n"
"      r - pan-up\n"
"      f - pan-down\n"
"      t - less traces\n"
"      g - more traces\n"
"\n"
"      e - toggle summary-mode\n"
"      c - toggle color-mode\n"
"\n"
"      x - take snapshot\n"
"      z - go to next snapshot\n"
"      p - put snapshots to snapshots.g2 \n"
"      l - load snapshots from snapshots.g2\n"
"\n"
"<ctrl>q - quit\n"
"Send comments / bug reports to the \"fd.io\" mailing list.\n";

/****************************************************************************
* debug_dialog_callback
****************************************************************************/

boolean debug_dialog_callback (char *s)
{
    g_print("Dialog result: %s", s);
    return (TRUE);
}

/****************************************************************************
* get_dialog_value
****************************************************************************/

static void get_dialog_value (GtkWidget *dialog, gpointer user_data)
{
    md_t *md = (md_t *)user_data;
    char * cb_arg;
    
    cb_arg = (char *) gtk_entry_get_text(GTK_ENTRY(md->entry));

    if ((*md->callback)(cb_arg)) {
	gtk_grab_remove(md->dialog);
	gtk_widget_destroy(md->dialog);
    } else {
	gtk_label_set_text (GTK_LABEL(md->label), md->retry_text);
    }
}

/****************************************************************************
* modal_dialog
****************************************************************************/

void modal_dialog (char *label_text, char *retry_text, char *default_value, 
                   boolean (*cb)(char *))
{
    GtkWidget *dialog, *label, *ok_button, *entry;
    static md_t dlg;
    md_t *md = &dlg;

    dialog = gtk_dialog_new();
    label = gtk_label_new(label_text);

    entry = gtk_entry_new();
    if (default_value)
        gtk_entry_set_text(GTK_ENTRY(entry), default_value);

    ok_button = gtk_button_new_with_label("OK");

    md->entry = entry;
    md->label = label;
    md->retry_text = retry_text;
    md->dialog = dialog;
    if (cb)
	md->callback = cb;
    else
	md->callback = debug_dialog_callback;

    gtk_signal_connect (GTK_OBJECT (ok_button), "clicked", 
                        GTK_SIGNAL_FUNC(get_dialog_value), (gpointer) md);

    gtk_signal_connect (GTK_OBJECT (entry), "activate", 
                        GTK_SIGNAL_FUNC(get_dialog_value), (gpointer) md);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->action_area),
		      entry);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->action_area),
		      ok_button);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), label);
    gtk_widget_show_all(dialog);
    gtk_widget_grab_focus(entry);
    gtk_grab_add(dialog);
}

/****************************************************************************
* get_eventdef_name
****************************************************************************/

static void get_eventdef_name (GtkFileSelection *sel, gpointer user_data)
{
    char *filename = (char *) gtk_file_selection_get_filename (
        GTK_FILE_SELECTION(s_filesel));
    read_event_definitions(filename);
    set_window_title(filename);
}

/****************************************************************************
* read_eventdef_callback
****************************************************************************/

static void read_eventdef_callback(GtkToggleButton *item, gpointer data)
{
    
    s_filesel = gtk_file_selection_new("Read Event Definitions From...");
    
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(s_filesel), 
				    "../h/elog.h");

    gtk_signal_connect (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->ok_button),
                        "clicked", 
                        GTK_SIGNAL_FUNC(get_eventdef_name), NULL);
                            
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->ok_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_filesel);
    
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->cancel_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_filesel);
    gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(s_filesel));
    gtk_widget_show (s_filesel);
}

/****************************************************************************
* get_events_name
****************************************************************************/

static void get_events_name (GtkFileSelection *sel, gpointer user_data)
{
    char *filename = (char *) gtk_file_selection_get_filename (
        GTK_FILE_SELECTION(s_eventsel));
    read_events(filename);
    view1_display_when_idle();
}


/****************************************************************************
* get_ticks_per_ns
****************************************************************************/

static boolean get_ticks_per_ns (char *value)
{
    double rv;

    rv = atof (value);

    if (rv == 0.0 || rv > 100000)
	return(FALSE);

    ticks_per_ns = rv;
    ticks_per_ns_set = TRUE;

    gtk_widget_show(s_eventsel);
    return(TRUE);
}

/****************************************************************************
* read_events_callback
****************************************************************************/

static void read_events_callback(GtkToggleButton *item, gpointer data)
{
    char tmpbuf [32];

    s_eventsel = gtk_file_selection_new("Read Events From...");
    
    gtk_signal_connect (GTK_OBJECT (
        GTK_FILE_SELECTION(s_eventsel)->ok_button),
                        "clicked", 
                        GTK_SIGNAL_FUNC(get_events_name), NULL);
                            
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_eventsel)->ok_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_eventsel);
    
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_eventsel)->cancel_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_eventsel);
    gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(s_eventsel));

    if (ticks_per_ns_set)
	gtk_widget_show (s_eventsel);
    else {
	sprintf(tmpbuf, "%.3f", ticks_per_ns);
	modal_dialog ("Please enter clock ticks per nanosecond",
		      "Invalid: Please enter clock ticks per nanosecond",
		      tmpbuf, get_ticks_per_ns);
    }
}

/****************************************************************************
* read_eventclock_callback
****************************************************************************/

static void read_eventsclock_callback(GtkToggleButton *item, gpointer data)
{
    ticks_per_ns_set = FALSE;
    read_events_callback(item, data);
}

/****************************************************************************
* infobox_size_request
****************************************************************************/

void infobox_size_request (GtkWidget *widget, GtkRequisition *req,
                           gpointer user_data)
{
    char *text = (char *)user_data;
    char *cp;
    int widest_line_in_chars;
    int w;
    int nlines;
    
    /*
     * You'd think that the string extent function would work here.
     * You'd be wrong. 
     */
    nlines = w = widest_line_in_chars = 0;
    for (cp = text; *cp; cp++) {
        if (*cp == '\n') {
            if (w > widest_line_in_chars) {
                widest_line_in_chars = w;
            }
            w = 0;
            nlines++;
        }
        w++;
    }

    nlines++;

    req->width = (widest_line_in_chars * 8) + 20;
    req->height = (nlines * 13) + 10;
}

/****************************************************************************
* infobox
****************************************************************************/

void infobox(char *label_text, char *text)
{
    GtkWidget *dialog, *label, *ok_button, *entry;
    GtkWidget *box;

    dialog = gtk_dialog_new();
    label = gtk_label_new(label_text);

    entry = gtk_text_new(NULL, NULL);

    gtk_signal_connect (GTK_OBJECT (entry), "size-request", 
                        GTK_SIGNAL_FUNC(infobox_size_request), 
                        (gpointer) text);

    gtk_text_insert(GTK_TEXT(entry), g_font, &fg_black, &bg_white,
                    text, -1);

    gtk_text_set_editable(GTK_TEXT(entry), FALSE);

    ok_button = gtk_button_new_with_label("OK");

    gtk_signal_connect_object (GTK_OBJECT (ok_button), "clicked", 
                               GTK_SIGNAL_FUNC(gtk_widget_destroy), 
                               (gpointer) GTK_OBJECT(dialog));

    box = gtk_vbox_new(FALSE, 5);


    gtk_box_pack_start(GTK_BOX(box), entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), ok_button, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->action_area),
		      box);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), label);
    gtk_widget_show_all(dialog);
}

/****************************************************************************
* help_general_callback
****************************************************************************/

static void help_general_callback(GtkToggleButton *item, gpointer data)
{
    infobox("General Help", general_help);
}

/****************************************************************************
* help_about_callback
****************************************************************************/

static void help_about_callback(GtkToggleButton *item, gpointer data)
{
    char tmpbuf [1024];
    sprintf (tmpbuf, "G2 -- Graphical Event Viewer\n\n");
    view1_about(tmpbuf);
    pointsel_about(tmpbuf);
    events_about(tmpbuf);
    sprintf (tmpbuf+strlen(tmpbuf), "\n%s\n", version_string);
    sprintf (tmpbuf+strlen(tmpbuf), "%s\n", minor_v_string);
    infobox("About", tmpbuf);
}


/****************************************************************************
* get_cpel_name
****************************************************************************/

static void get_cpel_name (GtkFileSelection *sel, gpointer user_data)
{
    char *filename = (char *)gtk_file_selection_get_filename (
        GTK_FILE_SELECTION(s_filesel));
    read_cpel_file(filename);
    set_window_title(filename);
}

/****************************************************************************
* get_clib_name
****************************************************************************/

static void get_clib_name (GtkFileSelection *sel, gpointer user_data)
{
    char *filename = (char *) gtk_file_selection_get_filename (
        GTK_FILE_SELECTION(s_filesel));
    read_clib_file(filename);
    set_window_title(filename);
}

/****************************************************************************
* read_cpel_callback
****************************************************************************/

static void read_cpel_callback(GtkToggleButton *item, gpointer data)
{
    
    s_filesel = gtk_file_selection_new("Read CPEL data from...");
    
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(s_filesel), 
				    "cpel.out");

    gtk_signal_connect (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->ok_button),
                        "clicked", 
                        GTK_SIGNAL_FUNC(get_cpel_name), NULL);
                            
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->ok_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_filesel);
    
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->cancel_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_filesel);
    gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(s_filesel));
    gtk_widget_show (s_filesel);
}

/****************************************************************************
* read_clib_callback
****************************************************************************/

static void read_clib_callback(GtkToggleButton *item, gpointer data)
{
    
    s_filesel = gtk_file_selection_new("Read clib data From...");
    
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(s_filesel), 
				    "clib.out");

    gtk_signal_connect (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->ok_button),
                        "clicked", 
                        GTK_SIGNAL_FUNC(get_clib_name), NULL);
                            
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->ok_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_filesel);
    
    gtk_signal_connect_object (GTK_OBJECT (
        GTK_FILE_SELECTION(s_filesel)->cancel_button),
                               "clicked", 
                               GTK_SIGNAL_FUNC (gtk_widget_destroy),
                               (gpointer) s_filesel);
    gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(s_filesel));
    gtk_widget_show (s_filesel);
}

/****************************************************************************
* menu1_init
****************************************************************************/

void menu1_init(void)
{

    s_filemenu = gtk_menu_new();

    s_readcpel = gtk_menu_item_new_with_label 
	("Read CPEL file");
    gtk_menu_append(GTK_MENU(s_filemenu), s_readcpel);
    gtk_signal_connect(GTK_OBJECT(s_readcpel), "activate", 
                       GTK_SIGNAL_FUNC(read_cpel_callback), 0);

    s_readclib = gtk_menu_item_new_with_label 
	("Read CLIB file");
    gtk_menu_append(GTK_MENU(s_filemenu), s_readclib);
    gtk_signal_connect(GTK_OBJECT(s_readclib), "activate", 
                       GTK_SIGNAL_FUNC(read_clib_callback), 0);
    
    s_readdefs = gtk_menu_item_new_with_label ("Read Event Definitions");
    gtk_menu_append(GTK_MENU(s_filemenu), s_readdefs);
    gtk_signal_connect(GTK_OBJECT(s_readdefs), "activate", 
                       GTK_SIGNAL_FUNC(read_eventdef_callback), 0);
    
    s_readevents = gtk_menu_item_new_with_label ("Read Event Log");
    gtk_menu_append(GTK_MENU(s_filemenu), s_readevents);
    gtk_signal_connect(GTK_OBJECT(s_readevents), "activate", 
                       GTK_SIGNAL_FUNC(read_events_callback), 0);
    
    s_readeventsclock = gtk_menu_item_new_with_label 
	("Read Event Log with Different Clock Rate");
    gtk_menu_append(GTK_MENU(s_filemenu), s_readeventsclock);
    gtk_signal_connect(GTK_OBJECT(s_readeventsclock), "activate", 
                       GTK_SIGNAL_FUNC(read_eventsclock_callback), 0);

    s_print = gtk_menu_item_new_with_label ("Print");
    gtk_menu_append(GTK_MENU(s_filemenu), s_print);
    gtk_signal_connect(GTK_OBJECT(s_print), "activate", 
                       GTK_SIGNAL_FUNC(view1_print_callback), 0);
    
    s_quit = gtk_menu_item_new_with_label ("Exit");
    gtk_menu_append(GTK_MENU(s_filemenu), s_quit);
    gtk_signal_connect(GTK_OBJECT(s_quit), "activate", 
                       GTK_SIGNAL_FUNC(gtk_main_quit), 0);

    s_mainfilemenu = gtk_menu_item_new_with_label("File");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(s_mainfilemenu), s_filemenu);

    s_helpmenu = gtk_menu_new();

    s_help_general = gtk_menu_item_new_with_label ("General");
    gtk_menu_append(GTK_MENU(s_helpmenu), s_help_general);
    gtk_signal_connect(GTK_OBJECT(s_help_general), "activate", 
                       GTK_SIGNAL_FUNC(help_general_callback), 0);

    s_help_about = gtk_menu_item_new_with_label ("About");
    gtk_menu_append(GTK_MENU(s_helpmenu), s_help_about);
    gtk_signal_connect(GTK_OBJECT(s_help_about), "activate", 
                       GTK_SIGNAL_FUNC(help_about_callback), 0);

    s_mainhelpmenu = gtk_menu_item_new_with_label("Help");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(s_mainhelpmenu), s_helpmenu);

    s_mainmenubar = gtk_menu_bar_new();
    gtk_menu_bar_append(GTK_MENU_BAR(s_mainmenubar), s_mainfilemenu);
    gtk_menu_bar_append(GTK_MENU_BAR(s_mainmenubar), s_mainhelpmenu);
    gtk_widget_show_all(s_mainmenubar);

    gtk_box_pack_start(GTK_BOX(g_mainvbox), s_mainmenubar, FALSE, FALSE, 0);
}
