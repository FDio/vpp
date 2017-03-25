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

#include "g2.h"
#include "props.h"
#include <pwd.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <vppinfra/mem.h>

/*
 * globals
 */

GtkWidget *g_mainwindow;        /* The main window */

/* Graphical object heirarchy
 *
 * [main window]
 *   [main vbox]
 *     [main (e.g. file) menubar]
 *     [view hbox] 
 *     [view bottom menu]
 */

GtkWidget *g_mainvbox;
GtkWidget *g_mainhbox;

gint delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    /* Allow window to be destroyed */
    return(FALSE);
}

void destroy(GtkWidget *widget, gpointer data)
{
    gtk_main_quit();
}

int main (int argc, char **argv)
{
    char tmpbuf [128];
    struct passwd *pw;
    char *event_file = 0;
    char *cpel_file = 0;
    char *clib_file =0;
    char *title = "none";
    int curarg=1;
    char *homedir;
    
    clib_mem_init (0, ((uword)3<<30));

    gtk_init(&argc, &argv);

    homedir = getenv ("HOME");
    tmpbuf[0] = 0;

    if (homedir) {
        sprintf(tmpbuf, "%s/.g2", homedir);
    } else {
        pw = getpwuid(geteuid());
        if (pw) {
            sprintf(tmpbuf, "%s/.g2", pw->pw_dir);
        }
    }
    if (tmpbuf[0])
        readprops(tmpbuf);

    g_mainwindow = gtk_window_new (GTK_WINDOW_TOPLEVEL);

    gtk_signal_connect (GTK_OBJECT(g_mainwindow), "delete_event",
                        GTK_SIGNAL_FUNC (delete_event), NULL);

    gtk_signal_connect (GTK_OBJECT(g_mainwindow), "destroy",
                        GTK_SIGNAL_FUNC (destroy), NULL);

    gtk_container_set_border_width(GTK_CONTAINER(g_mainwindow), 5);

    g_mainvbox = gtk_vbox_new(FALSE, 0);
    g_mainhbox = gtk_hbox_new(FALSE, 0);

    /* 
     * init routines
     */

    menu1_init();
    point_selector_init();
    view1_init();
    event_init();

    /* 
     * Now that we're ready to rock 'n roll, see if we've been asked to
     * press a few buttons...
     */
    
    while (curarg < argc) {
        if (!strncmp(argv[curarg], "--cpel-input", 4)) {
            curarg++;
            if (curarg < argc) {
                cpel_file = argv[curarg];
                curarg++;
                break;
            }
            g_error("Missing filename after --cpel-input");
        }
        if (!strncmp(argv[curarg], "--clib-input", 4)) {
            curarg++;
            if (curarg < argc) {
                clib_file = argv[curarg];
                curarg++;
                break;
            }
            g_error("Missing filename after --cpel-input");
        }

        if (!strncmp(argv[curarg], "--pointdefs", 3)) {
            curarg++;
            if (curarg < argc) {
                read_event_definitions(argv[curarg]);
                curarg++;
                continue;
            }
            g_error ("Missing filename after --pointdefs\n");
        }
        if (!strncmp(argv[curarg], "--event-log", 3)) {
            curarg++;
            if (curarg < argc) {
                event_file = argv[curarg];
                curarg++;
                continue;
            }
            g_error ("Missing filename after --event-log\n");
        }

        if (!strncmp(argv[curarg], "--ticks-per-us", 3)) {
            curarg++;
            if (curarg < argc) {
                ticks_per_ns = 0.0;
                ticks_per_ns = atof(argv[curarg]);
                if (ticks_per_ns == 0.0) {
                    g_error("ticks-per-ns (%s) didn't convert properly\n",
                            argv[curarg]);
                }
                ticks_per_ns_set = TRUE;
                curarg++;
                continue;
            }
            g_error ("Missing filename after --event-log\n");
        }

        fprintf(stderr, 
                "g2 [--pointdefs <filename>] [--event-log <filename>]\n");
        fprintf(stderr, "   [--ticks-per-us <value>]\n");
        fprintf(stderr, 
                "   [--cpel-input <filename>] [--clib-input <filename]>\n");
        fprintf(stderr, 
                "%s\n%s\n", version_string, minor_v_string);
        exit(0);
    }

    if (clib_file) {
        read_clib_file (clib_file);
        title = clib_file;
    } else if (cpel_file) {
        read_cpel_file(cpel_file);
        title = cpel_file;
    } else if (event_file) {
        read_events(event_file);
        title = event_file;
    }

    set_window_title(title);

    gtk_signal_connect (GTK_OBJECT (g_mainwindow), "key_press_event",
                        (GtkSignalFunc) view1_handle_key_press_event, NULL);
    gtk_container_add(GTK_CONTAINER(g_mainvbox), g_mainhbox);
    gtk_widget_show(g_mainhbox);
    gtk_container_add(GTK_CONTAINER(g_mainwindow), g_mainvbox);
    gtk_widget_show(g_mainvbox);
    gtk_widget_show(g_mainwindow);

    gtk_main();
    return(0);
}
