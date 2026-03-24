/* SPDX-License-Identifier: BSD-Attribution-HPND-disclaimer */
/*
 * options.c - handles option processing for PPP.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define RCSID "$Id: options.c,v 1.102 2008/06/15 06:53:06 paulus Exp $"

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#ifdef PLUGIN
#include <dlfcn.h>
#endif

#ifdef PPP_FILTER
#include <pcap.h>
/*
 * There have been 3 or 4 different names for this in libpcap CVS, but
 * this seems to be what they have settled on...
 * For older versions of libpcap, use DLT_PPP - but that means
 * we lose the inbound and outbound qualifiers.
 */
#ifndef DLT_PPP_PPPD
#ifdef DLT_PPP_WITHDIRECTION
#define DLT_PPP_PPPD DLT_PPP_WITHDIRECTION
#else
#define DLT_PPP_PPPD DLT_PPP
#endif
#endif
#endif /* PPP_FILTER */

#include "pppd.h"
#include "pathnames.h"

#if defined(ultrix) || defined(NeXT)
char *strdup __P ((char *) );
#endif

// ZDY: remove not used complaints.
// static const char rcsid[] = RCSID;

struct option_value
{
  struct option_value *next;
  const char *source;
  char value[1];
};

/*
 * Option variables and default values.
 */
// ZDY: enable debug for test.
int debug = 1;		      /* Debug flag */
bool nodetach = 0;	      /* Don't detach from controlling tty */
bool updetach = 0;	      /* Detach once link is up */
bool master_detach;	      /* Detach when we're (only) multilink master */
char user[MAXNAMELEN];	      /* Username for PAP */
char passwd[MAXSECRETLEN];    /* Password for PAP */
bool persist = 0;	      /* Reopen link after it goes down */
char our_name[MAXNAMELEN];    /* Our name for authentication purposes */
bool demand = 0;	      /* do dial-on-demand */
char *ipparam = NULL;	      /* Extra parameter for ip up/down scripts */
int idle_time_limit = 0;      /* Disconnect if idle for this many seconds */
int holdoff = 30;	      /* # seconds to pause before reconnecting */
bool holdoff_specified;	      /* true if a holdoff value has been given */
int connect_delay = 1000;     /* wait this many ms after connect script */
int req_unit = -1;	      /* requested interface unit */
bool multilink = 0;	      /* Enable multilink operation */
char *bundle_name = NULL;     /* bundle name for multilink */
bool dump_options;	      /* print out option values */
bool dryrun;		      /* print out option values and exit */
char *domain;		      /* domain name set by domain option */
int child_wait = 5;	      /* # seconds to wait for children at exit */
struct userenv *userenv_list; /* user environment variables */

extern option_t auth_options[];
extern struct stat devstat;

#ifdef PPP_FILTER
struct bpf_program pass_filter;	  /* Filter program for packets to pass */
struct bpf_program active_filter; /* Filter program for link-active pkts */
#endif

char *current_option;		     /* the name of the option being parsed */
int privileged_option;		     /* set iff the current option came from root */
char *option_source;		     /* string saying where the option came from */
int option_priority = OPRIO_CFGFILE; /* priority of the current options */

/*
 * Read a word from a file.
 * Words are delimited by white-space or by quotes (" or ').
 * Quotes, white-space and \ may be escaped with \.
 * \<newline> is ignored.
 */
int
getword (f, word, newlinep, filename)
FILE *f;
char *word;
int *newlinep;
char *filename;
{
  // ZDY: will be removed later.
  f = f;
  word = word;
  newlinep = newlinep;
  filename = filename;
  return 0;
}
