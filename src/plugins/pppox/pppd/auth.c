/* SPDX-License-Identifier: Mackerras-3-Clause-acknowledgment AND BSD-Attribution-HPND-disclaimer */
/*
 * auth.c - PPP authentication and phase control.
 *
 * Copyright (c) 1993-2002 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Derived from main.c, which is:
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

#define RCSID "$Id: auth.c,v 1.117 2008/07/01 12:27:56 paulus Exp $"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <utmp.h>
#include <fcntl.h>
#if defined(_PATH_LASTLOG) && defined(__linux__)
#include <lastlog.h>
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAS_SHADOW
#include <shadow.h>
#ifndef PW_PPP
#define PW_PPP PW_LOGIN
#endif
#endif
#include <time.h>

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ccp.h"
#include "ecp.h"
#include "ipcp.h"
#include "upap.h"
#include "chap-new.h"
#include "eap.h"
#include "pathnames.h"

// static const char rcsid[] = RCSID;

#define ISWILD(word) (word[0] == '*' && word[1] == 0)

/* The name by which the peer authenticated itself to us. */
char peer_authname[MAXNAMELEN];

/* Records which authentication operations haven't completed yet. */
static int auth_pending[NUM_PPP];

/* Records which authentication operations have been completed. */
int auth_done[NUM_PPP];

/* Remote telephone number, if available */
char remote_number[MAXNAMELEN];

/* Number of network protocols which we have opened. */
static int num_np_open[NUM_PPP];

/* Number of network protocols which have come up. */
static int num_np_up[NUM_PPP];

/* Set if we got the contents of passwd[] from the pap-secrets file. */
static int passwd_from_file;

/* Hook for a plugin to say whether we can possibly authenticate any peer */
int (*pap_check_hook) __P ((void) ) = NULL;

/* Hook for a plugin to check the PAP user and password */
int (*pap_auth_hook) __P ((char *user, char *passwd, char **msgp, struct wordlist **paddrs,
			   struct wordlist **popts)) = NULL;

/* Hook for a plugin to know about the PAP user logout */
void (*pap_logout_hook) __P ((void) ) = NULL;

/* Hook for a plugin to get the PAP password for authenticating us */
int (*pap_passwd_hook) __P ((char *user, char *passwd)) = NULL;

/* Hook for a plugin to say if we can possibly authenticate a peer using CHAP */
int (*chap_check_hook) __P ((void) ) = NULL;

/* Hook for a plugin to get the CHAP password for authenticating us */
int (*chap_passwd_hook) __P ((char *user, char *passwd)) = NULL;

/* Hook for a plugin to say whether it is OK if the peer
   refuses to authenticate. */
int (*null_auth_hook) __P ((struct wordlist * *paddrs, struct wordlist **popts)) = NULL;

int (*allowed_address_hook) __P ((u_int32_t addr)) = NULL;

#ifdef HAVE_MULTILINK
/* Hook for plugin to hear when an interface joins a multilink bundle */
void (*multilink_join_hook) __P ((void) ) = NULL;
#endif

/* A notifier for when the peer has authenticated itself,
   and we are proceeding to the network phase. */
struct notifier *auth_up_notifier = NULL;

/* A notifier for when the link goes down. */
struct notifier *link_down_notifier = NULL;

/*
 * Option variables.
 */
bool uselogin = 0;    /* Use /etc/passwd for checking PAP */
bool refuse_pap = 0;  /* Don't wanna auth. ourselves with PAP */
bool refuse_chap = 0; /* Don't wanna auth. ourselves with CHAP */
bool refuse_eap = 0;  /* Don't wanna auth. ourselves with EAP */
#ifdef CHAPMS
bool refuse_mschap = 0;	   /* Don't wanna auth. ourselves with MS-CHAP */
bool refuse_mschap_v2 = 0; /* Don't wanna auth. ourselves with MS-CHAPv2 */
#else
bool refuse_mschap = 1;	   /* Don't wanna auth. ourselves with MS-CHAP */
bool refuse_mschap_v2 = 1; /* Don't wanna auth. ourselves with MS-CHAPv2 */
#endif
bool usehostname = 0;	      /* Use hostname for our_name */
bool allow_any_ip = 0;	      /* Allow peer to use any IP address */
bool explicit_remote = 0;     /* User specified explicit remote name */
bool explicit_user = 0;	      /* Set if "user" option supplied */
bool explicit_passwd = 0;     /* Set if "password" option supplied */
char remote_name[MAXNAMELEN]; /* Peer's name for authentication */

extern char *crypt __P ((const char *, const char *) );

/* Prototypes for procedures local to this file. */

static void network_phase __P ((int) );

// ZDY: add an auth context to store unit to support multiple instances.
typedef struct auth_context
{
  int unit; /* Interface unit number */
} auth_context;

static auth_context auth_contexts[NUM_PPP];

void
init_auth_context (int unit)
{
  auth_contexts[unit].unit = unit;
}

/*
 * An Open on LCP has requested a change from Dead to Establish phase.
 */
void link_required (unit) int unit;
{
}

/*
 * Bring the link up to the point of being able to do ppp.
 */
void start_link (unit) int unit;
{
  // ZDY: we make lower up firstly, so we can directly shift
  // to establish.
  status = EXIT_NEGOTIATION_FAILED;
  new_phase (unit, PHASE_ESTABLISH);
  lcp_lowerup (unit);
  return;
}

/*
 * LCP has terminated the link; go to the Dead phase and take the
 * physical layer down.
 */
void link_terminated (unit) int unit;
{
  if (phase[unit] == PHASE_DEAD || phase[unit] == PHASE_MASTER)
    return;
  new_phase (unit, PHASE_DISCONNECT);

  if (!doing_multilink)
    {
      notice ("[%d], Connection terminated.", unit);
    }
  else
    notice ("[%d], Link terminated.", unit);

  if (!hungup)
    lcp_lowerdown (unit);

  if (the_channel->cleanup)
    (*the_channel->cleanup) (unit);

  new_phase (unit, PHASE_DEAD);
}

/*
 * LCP has gone down; it will either die or try to re-establish.
 */
void link_down (unit) int unit;
{
  if (!doing_multilink)
    {
      upper_layers_down (unit);
      if (phase[unit] != PHASE_DEAD && phase[unit] != PHASE_MASTER)
	new_phase (unit, PHASE_ESTABLISH);
    }
  /* XXX if doing_multilink, should do something to stop
     network-layer traffic on the link */
}

void
upper_layers_down (int unit)
{
  int i;
  struct protent *protp;

  for (i = 0; (protp = protocols[i]) != NULL; ++i)
    {
      if (!protp->enabled_flag)
	continue;
      if (protp->protocol != PPP_LCP && protp->lowerdown != NULL)
	(*protp->lowerdown) (unit);
      if (protp->protocol < 0xC000 && protp->close != NULL)
	(*protp->close) (unit, "LCP down");
    }
  num_np_open[unit] = 0;
  num_np_up[unit] = 0;
}

/*
 * The link is established.
 * Proceed to the Dead, Authenticate or Network phase as appropriate.
 */
void link_established (unit) int unit;
{
  int auth;
  lcp_options *go = &lcp_gotoptions[unit];
  lcp_options *ho = &lcp_hisoptions[unit];
  int i;
  struct protent *protp;

  /*
   * Tell higher-level protocols that LCP is up.
   */
  if (!doing_multilink)
    {
      for (i = 0; (protp = protocols[i]) != NULL; ++i)
	if (protp->protocol != PPP_LCP && protp->enabled_flag && protp->lowerup != NULL)
	  (*protp->lowerup) (unit);
    }

  new_phase (unit, PHASE_AUTHENTICATE);
  auth = 0;
  if (go->neg_eap)
    {
      eap_authpeer (unit, our_name);
      auth |= EAP_PEER;
    }
  else if (go->neg_chap)
    {
      chap_auth_peer (unit, our_name, CHAP_DIGEST (go->chap_mdtype));
      auth |= CHAP_PEER;
    }
  else if (go->neg_upap)
    {
      upap_authpeer (unit);
      auth |= PAP_PEER;
    }
  if (ho->neg_eap)
    {
      eap_authwithpeer (unit, user);
      auth |= EAP_WITHPEER;
    }
  else if (ho->neg_chap)
    {
      chap_auth_with_peer (unit, user, CHAP_DIGEST (ho->chap_mdtype));
      auth |= CHAP_WITHPEER;
    }
  else if (ho->neg_upap)
    {
      // ZDY: password will be set by new-ly introduced API.
      upap_authwithpeer (unit);
      auth |= PAP_WITHPEER;
    }
  auth_pending[unit] = auth;
  auth_done[unit] = 0;

  if (!auth)
    network_phase (unit);
}

/*
 * Proceed to the network phase.
 */
static void network_phase (unit) int unit;
{
  lcp_options *go = &lcp_gotoptions[unit];

  /* Log calling number. */
  if (*remote_number)
    notice ("[%d], peer from calling number %q authorized", unit, remote_number);

  /*
   * If the peer had to authenticate, run the auth-up script now.
   */
  if (go->neg_chap || go->neg_upap || go->neg_eap)
    {
      notify (auth_up_notifier, 0);
    }

#ifdef CBCP_SUPPORT
  /*
   * If we negotiated callback, do it now.
   */
  if (go->neg_cbcp)
    {
      new_phase (unit, PHASE_CALLBACK);
      (*cbcp_protent.open) (unit);
      return;
    }
#endif

  start_networks (unit);
}

void start_networks (unit) int unit;
{
  int i;
  struct protent *protp;
  int ecp_required, mppe_required;

  new_phase (unit, PHASE_NETWORK);

#ifdef HAVE_MULTILINK
  if (multilink)
    {
      if (mp_join_bundle ())
	{
	  if (multilink_join_hook)
	    (*multilink_join_hook) ();
	  if (updetach && !nodetach)
	    detach ();
	  return;
	}
    }
#endif /* HAVE_MULTILINK */

#ifdef PPP_FILTER
  if (!demand)
    set_filters (&pass_filter, &active_filter);
#endif
  /* Start CCP and ECP */
  for (i = 0; (protp = protocols[i]) != NULL; ++i)
    if ((protp->protocol == PPP_ECP || protp->protocol == PPP_CCP) && protp->enabled_flag &&
	protp->open != NULL)
      (*protp->open) (0);

  /*
   * Bring up other network protocols iff encryption is not required.
   */
  ecp_required = ecp_gotoptions[unit].required;
  mppe_required = ccp_gotoptions[unit].mppe;
  if (!ecp_required && !mppe_required)
    continue_networks (unit);
}

void continue_networks (unit) int unit;
{
  int i;
  struct protent *protp;

  /*
   * Start the "real" network protocols.
   */
  for (i = 0; (protp = protocols[i]) != NULL; ++i)
    if (protp->protocol < 0xC000 && protp->protocol != PPP_CCP && protp->protocol != PPP_ECP &&
	protp->enabled_flag && protp->open != NULL)
      {
	(*protp->open) (unit);
	++num_np_open[unit];
      }

  if (num_np_open[unit] == 0)
    /* nothing to do */
    lcp_close (unit, "No network protocols running");
}

/*
 * The peer has failed to authenticate himself using `protocol'.
 */
void auth_peer_fail (unit, protocol) int unit, protocol;
{
  /*
   * Authentication failure: take the link down
   */
  status = EXIT_PEER_AUTH_FAILED;
  lcp_close (unit, "Authentication failed");
}

/*
 * The peer has been successfully authenticated using `protocol'.
 */
void auth_peer_success (unit, protocol, prot_flavor, name, namelen) int unit, protocol, prot_flavor;
char *name;
int namelen;
{
  int bit;

  switch (protocol)
    {
    case PPP_CHAP:
      bit = CHAP_PEER;
      switch (prot_flavor)
	{
	case CHAP_MD5:
	  bit |= CHAP_MD5_PEER;
	  break;
#ifdef CHAPMS
	case CHAP_MICROSOFT:
	  bit |= CHAP_MS_PEER;
	  break;
	case CHAP_MICROSOFT_V2:
	  bit |= CHAP_MS2_PEER;
	  break;
#endif
	}
      break;
    case PPP_PAP:
      bit = PAP_PEER;
      break;
    case PPP_EAP:
      bit = EAP_PEER;
      break;
    default:
      xwarn ("auth_peer_success: unknown protocol %x", protocol);
      return;
    }

  /*
   * Save the authenticated name of the peer for later.
   */
  if (namelen > sizeof (peer_authname) - 1)
    namelen = sizeof (peer_authname) - 1;
  BCOPY (name, peer_authname, namelen);
  peer_authname[namelen] = 0;
  script_setenv ("PEERNAME", peer_authname, 0);

  /* Save the authentication method for later. */
  auth_done[unit] |= bit;

  /*
   * If there is no more authentication still to be done,
   * proceed to the network (or callback) phase.
   */
  if ((auth_pending[unit] &= ~bit) == 0)
    network_phase (unit);
}

/*
 * We have failed to authenticate ourselves to the peer using `protocol'.
 */
void auth_withpeer_fail (unit, protocol) int unit, protocol;
{
  if (passwd_from_file)
    BZERO (passwd, MAXSECRETLEN);
  /*
   * We've failed to authenticate ourselves to our peer.
   * Some servers keep sending CHAP challenges, but there
   * is no point in persisting without any way to get updated
   * authentication secrets.
   */
  status = EXIT_AUTH_TOPEER_FAILED;
  lcp_close (unit, "Failed to authenticate ourselves to peer");
}

/*
 * We have successfully authenticated ourselves with the peer using `protocol'.
 */
void auth_withpeer_success (unit, protocol, prot_flavor) int unit, protocol, prot_flavor;
{
  int bit;
  const char *prot = "";

  switch (protocol)
    {
    case PPP_CHAP:
      bit = CHAP_WITHPEER;
      prot = "CHAP";
      switch (prot_flavor)
	{
	case CHAP_MD5:
	  bit |= CHAP_MD5_WITHPEER;
	  break;
#ifdef CHAPMS
	case CHAP_MICROSOFT:
	  bit |= CHAP_MS_WITHPEER;
	  break;
	case CHAP_MICROSOFT_V2:
	  bit |= CHAP_MS2_WITHPEER;
	  break;
#endif
	}
      break;
    case PPP_PAP:
      if (passwd_from_file)
	BZERO (passwd, MAXSECRETLEN);
      bit = PAP_WITHPEER;
      prot = "PAP";
      break;
    case PPP_EAP:
      bit = EAP_WITHPEER;
      prot = "EAP";
      break;
    default:
      xwarn ("[%d], auth_withpeer_success: unknown protocol %x", unit, protocol);
      bit = 0;
    }

  notice ("[%d], %s authentication succeeded", unit, prot);

  /* Save the authentication method for later. */
  auth_done[unit] |= bit;

  /*
   * If there is no more authentication still being done,
   * proceed to the network (or callback) phase.
   */
  if ((auth_pending[unit] &= ~bit) == 0)
    network_phase (unit);
}

/*
 * np_up - a network protocol has come up.
 */
void np_up (unit, proto) int unit, proto;
{
  if (num_np_up[unit] == 0)
    {
      /*
       * At this point we consider that the link has come up successfully.
       */
      status = EXIT_OK;
      unsuccess = 0;
      new_phase (unit, PHASE_RUNNING);

      /*
       * Detach now, if the updetach option was given.
       */
      if (updetach && !nodetach)
	detach ();
    }
  ++num_np_up[unit];
}

/*
 * np_down - a network protocol has gone down.
 */
void np_down (unit, proto) int unit, proto;
{
  if (--num_np_up[unit] == 0)
    {
      new_phase (unit, PHASE_NETWORK);
    }
}

/*
 * np_finished - a network protocol has finished using the link.
 */
void np_finished (unit, proto) int unit, proto;
{
  if (--num_np_open[unit] <= 0)
    {
      /* no further use for the link: shut up shop. */
      lcp_close (unit, "No network protocols running");
    }
}

/*
 * auth_reset - called when LCP is starting negotiations to recheck
 * authentication options, i.e. whether we have appropriate secrets
 * to use for authenticating ourselves and/or the peer.
 */
void auth_reset (unit) int unit;
{
  // lcp_options *go = &lcp_gotoptions[unit];
  lcp_options *ao = &lcp_allowoptions[unit];
  // int hadchap;

  // hadchap = -1;
  //  ZDY: explicitly set to allow upap & chap.
  ao->neg_upap = 1;
  ao->neg_chap = 1;
  ao->chap_mdtype = MDTYPE_MD5;
}

// ZDY: add _ to client and server to allow access client & server
// array in chap-new.c
/*
 * get_secret - open the CHAP secret file and return the secret
 * for authenticating the given client on the given server.
 * (We could be either client or server).
 */
int
get_secret (unit, client, server, secret, secret_len, am_server)
int unit;
char *client;
char *server;
char *secret;
int *secret_len;
int am_server;
{
  // FILE *f;
  // int ret, len;
  int len;
  // char *filename;
  // struct wordlist *addrs, *opts;
  char secbuf[MAXWORDLEN];

  if (!am_server && passwd[0] != 0)
    {
      strlcpy (secbuf, passwd, sizeof (secbuf));
    }
  else if (!am_server && chap_passwd_hook)
    {
      if ((*chap_passwd_hook) (client, secbuf) < 0)
	{
	  xerror ("[%d], Unable to obtain CHAP password for %s on %s from plugin", unit, client,
		  server);
	  return 0;
	}
    }
  else
    {
      // ZDY: we do not leverage file storage, only support client one-way auth which
      // mean we auth with AC.
      if (!am_server)
	{
	  len = chap_client[unit].us_passwdlen;
	  if (len >= sizeof (secbuf))
	    len = sizeof (secbuf) - 1;
	  memcpy (secbuf, chap_client[unit].us_passwd, len);
	  secbuf[len] = 0;
	}
      else
	{
	  xerror ("[%d], We do not support auth AC currently", unit);
	  return 0;
	}
    }

  len = strlen (secbuf);
  if (len > MAXSECRETLEN)
    {
      xerror ("[%d], Secret for %s on %s is too long", unit, client, server);
      len = MAXSECRETLEN;
    }
  BCOPY (secbuf, secret, len);
  BZERO (secbuf, sizeof (secbuf));
  *secret_len = len;

  return 1;
}
