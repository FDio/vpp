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
#include <ctype.h>
#include <malloc.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static char *sxerox (char *s);

#define NBUCKETS 97

typedef struct prop_ {
    struct prop_ *next;
    char *name;
    char *value;
} prop_t;

static prop_t *buckets [NBUCKETS];
static int hash_shifts[4] = {24, 16, 8, 0};

/*
 * getprop 
 */

char *getprop (char *name)
{
    unsigned char *cp;
    unsigned long hash=0;
    prop_t *bp;
    int i=0;

    for (cp = (unsigned char *) name; *cp; cp++)
        hash ^= (*cp)<<(hash_shifts[(i++)&0x3]);

    bp = buckets [hash%NBUCKETS];

    while (bp && strcmp(bp->name, name)) {
        bp = bp->next;
    }

    if (bp == NULL)
        return (0);
    else
        return (bp->value);
}

/*
 * getprop_default
 */

char *getprop_default (char *name, char *def)
{
    char *rv;
    rv = getprop (name);
    if (rv)
        return (rv);
    else
        return (def);
}

/*
 * addprop
 */

void addprop (char *name, char *value)
{
    unsigned char *cp;
    unsigned long hash=0;
    prop_t **bpp;
    prop_t *bp;
    int i=0;

    bp = (prop_t *)malloc (sizeof (prop_t));

    bp->next = 0;
    bp->name = sxerox (name);
    bp->value = sxerox (value);

    for (cp = (unsigned char *)name; *cp; cp++)
        hash ^= (*cp)<<(hash_shifts[(i++)&0x3]);

    bpp = &buckets [hash%NBUCKETS];

    if (*bpp == NULL)
        *bpp = bp;
    else {
        bp->next = *bpp;
        *bpp = bp;
    }
}

/*
 * sxerox 
 */

static char *sxerox (char *s)
{
    char *rv = (char *) malloc (strlen (s) + 1);
    strcpy (rv, s);
    return rv;
}

/*
 * readprops 
 */

#define START 0
#define READNAME  1
#define READVALUE 2
#define C_COMMENT 3
#define CPP_COMMENT 4

int readprops (char *filename)
{
    FILE *ifp;
    unsigned char c;
    int state=START;
    int linenum=1;
    char namebuf [128];
    char valbuf [512];
    int i;

    ifp = fopen (filename, "r");

    if (ifp == NULL)
        return (-1);

    while (1) {

    readchar:
        c = getc (ifp);

    again:
        switch (state) {
        case START:
            if (feof (ifp)) {
                fclose (ifp);
                return (0);
            }

            if (c == ' ' || c == '\t')
                goto readchar;

            if (c == '\n') {
                linenum++;
                goto readchar;
            }
            if (isalpha (c) || (c == '_')) {
                state = READNAME;
                goto again;
            }
            if (c == '/') {
                c = getc (ifp);
                if (c == '/') {
                    state = CPP_COMMENT;
                    goto readchar;
                } else if (c == '*') {
                    state = C_COMMENT;
                    goto readchar;
                } else {
                    fprintf (stderr, "unknown token '/' line %d\n",
                             linenum);
                    exit(1);
                }
            }
            fprintf (stderr, "unknown token '%c' line %d\n",
                     c, linenum);
            exit (1);
            break;
            
        case CPP_COMMENT:
            while (1) {
                c = getc (ifp);
                if (feof (ifp))
                    return (0);
                if (c == '\n') {
                    linenum++;
                    state = START;
                    goto readchar;
                }
            }
            break;

        case C_COMMENT:
            while (1) {
                c = getc (ifp);
                if (feof (ifp)) {
                    fprintf (stderr, "unterminated comment, line %d\n",
                             linenum);
                    exit (1);
                }
                if (c == '*') {
                staragain:
                    c = getc (ifp);
                    if (c == '/') {
                        state = START;
                        goto readchar;
                    }
                    if (c == '*')
                        goto staragain;
                }
            }
            break;
                    
        case READNAME:
            i = 0;
            namebuf[i++] = c;
            while (1) {
                c = getc (ifp);
                if (feof (ifp)) {
                    fprintf (stderr, "EOF while reading a name, line %d\n",
                             linenum);
                    exit (1);
                }
                if ((!isalnum (c)) && (c != '_')) {
                    namebuf [i] = 0;
                    state = READVALUE;
                    goto again;
                }
                namebuf [i++] = c;
            }
            break;

        case READVALUE:
            i = 0;
            while ((c == ' ') || (c == '\t') || (c == '=')) {
                c = getc (ifp);
                if (feof (ifp)) {
                    fprintf (stderr, "EOF while reading a value, line %d\n",
                             linenum);
                    exit (1);
                }
            }
            goto firsttime;
            while (1) {
                c = getc (ifp);

            firsttime:
                if (c == '\\') {
                    c = getc (ifp);
                    if (feof (ifp)) {
                        fprintf (stderr, "EOF after '\\', line %d\n",
                                 linenum);
                        exit (1);
                    }
                    valbuf[i++] = c;
                    continue;
                }
                if (c == '\n') {
                    linenum++;
                    while (valbuf [i-1] == ' ' || valbuf[i-1] == '\t')
                        i--;
                    valbuf[i] = 0;
                    addprop (namebuf, valbuf);
                    state = START;
                    goto readchar;
                }
                valbuf[i++] = c;
            }

        }
    }
}
