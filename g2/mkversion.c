/* 
 *------------------------------------------------------------------
 * Copyright (c) 1997-2016 Cisco and/or its affiliates.
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
#include <time.h>
#include <string.h>

int main (int argc, char **argv)
{
    time_t now;
    FILE *ofp;
    char *dateval;
    char *username;
    char *userstr;
    char *datestr;
    int i;
    char propname[32];
    char *propvalue;
    char timestr[64];
    char *cp;

    if (argc < 4) {
        printf ("usage: mkversion ostype version outputfile\n");
        exit (1);
    }

    ofp = fopen (argv[3], "w");
    if (ofp == NULL) {
        printf ("Couldn't create %s\n", argv[3]);
        exit (1);
    }

    now = time (0);
    
    fprintf (ofp, "/*\n");
    fprintf (ofp, " * G2 Version Stamp, %s",
             ctime (&now));
    fprintf (ofp, " * Automatically generated, hand edits are pointless.\n");
    fprintf (ofp, " */\n\n");

    fprintf (ofp, 
            "const char *version_string = \"G2 (%s) major version %s\";\n",
             argv[1], argv[2]);
    
    username = (char *) cuserid (0);

    strcpy(timestr, ctime(&now));
    
    cp = timestr;

    while (*cp) {
        cp++;
    }
    if (*--cp == '\n')
        *cp = 0;

    fprintf (ofp,
             "const char *minor_v_string = \"Built by %s at %s\";\n",
             username, timestr);
    
    exit (0);
}

    
