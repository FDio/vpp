/*
 * sys-vpp.c - adapt pppd on vpp platform.
 *
 * Copyright (c) 2017 RaydoNetworks.
 *
 */
#include "stdlib.h"
#include "pppd.h"
#include "fsm.h"
#include "ipcp.h"
#include "upap.h"
#include "chap-new.h"
#include "lcp.h"
#include "ipv6cp.h"

// NOTE: too keep relative independency, code here are used only to keep pppd compiled.
// code that iteractivate with vpp should be moved to pppox.c
extern void channel_cleanup (int unit);
extern void pppox_set_interface_mtu (int unit, int mtu);

struct channel vpp_channel = { .options = 0,
			       .process_extra_options = 0,
			       .check_options = 0,
			       .connect = 0,
			       .disconnect = 0,
			       .establish_ppp = 0,
			       .disestablish_ppp = 0,
			       .send_config = 0,
			       .recv_config = 0,
			       .close = NULL,
			       .cleanup = channel_cleanup };

struct channel *the_channel = &vpp_channel;
/*
 * PPP Data Link Layer "protocol" table.
 * One entry per supported protocol.
 * The last entry must be NULL.
 */
// We only support limited protocol.
struct protent *protocols[] = { &lcp_protent,	 &pap_protent,	&ipcp_protent,
				&ipv6cp_protent, &chap_protent, NULL };

// Those global variables are defined to resolve symbols, they
// should be lookup and set carefully.
int hungup = 0;
char hostname[] = "oss-pppd-for-vpp";
// TODO: use vpp buffer instead.
u_char outpacket_buf[PPP_MRU + PPP_HDRLEN]; /* buffer for outgoing packet */
int phase[NUM_PPP];			    /* Current state of link - see values below */
int redirect_stderr;			    /* Connector's stderr should go to file */
int privileged;				    /* We were run by real-uid root */
int need_holdoff;			    /* Need holdoff period after link terminates */
char **script_env;			    /* Environment variables for scripts */
int detached;				    /* Have detached from controlling tty */
GIDSET_TYPE groups[NGROUPS_MAX];	    /* groups the user is in */
int ngroups;				    /* How many groups valid in groups */
struct pppd_stats link_stats;		    /* byte/packet counts etc. for link */
int link_stats_valid;			    /* set if link_stats is valid */
unsigned link_connect_time;		    /* time the link was up for */
char *no_ppp_msg;			    /* message to print if ppp not in kernel */
volatile int status;			    /* exit status for pppd */
int unsuccess;				    /* # unsuccessful connection attempts */
int do_calblack;			    /* set if we want to do callback next */
int doing_callback;			    /* set if this is a callback */
int error_count;			    /* # of times error() has been called */
char ppp_devnam[MAXPATHLEN];
int ppp_session_number; /* Session number (eg PPPoE session) */
int fd_devnull;		/* fd open to /dev/null */
// ZDY: default listen time is zero means we will send conf request
// immediately.
int listen_time = 0; /* time to listen first (ms) */
bool doing_multilink;

/*
 * ppp_send_config - configure the transmit-side characteristics of
 * the ppp interface.  Returns -1, indicating an error, if the channel
 * send_config procedure called error() (or incremented error_count
 * itself), otherwise 0.
 */
int
ppp_send_config (unit, mtu, accm, pcomp, accomp)
int unit, mtu;
u_int32_t accm;
int pcomp, accomp;
{
  int errs;

  if (the_channel->send_config == NULL)
    return 0;
  errs = error_count;
  (*the_channel->send_config) (mtu, accm, pcomp, accomp);
  return (error_count != errs) ? -1 : 0;
}

/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.  Returns -1, indicating an error, if the channel
 * recv_config procedure called error() (or incremented error_count
 * itself), otherwise 0.
 */
int
ppp_recv_config (unit, mru, accm, pcomp, accomp)
int unit, mru;
u_int32_t accm;
int pcomp, accomp;
{
  int errs;

  if (the_channel->recv_config == NULL)
    return 0;
  errs = error_count;
  (*the_channel->recv_config) (mru, accm, pcomp, accomp);
  return (error_count != errs) ? -1 : 0;
}

void
new_phase (int unit, int p)
{
  phase[unit] = p;
  /*  if (new_phase_hook)
    (*new_phase_hook)(p);
    notify(phasechange, p);*/
}

void
netif_set_mtu (int unit, int mtu) /* Set PPP interface MTU */
{
  pppox_set_interface_mtu (unit, mtu);
}

int
netif_get_mtu (int unit) /* Get PPP interface MTU */
{
  unit = unit;
  return 0;
}

struct callout
{
  struct timeval c_time;	  /* time at which to call routine */
  void *c_arg;			  /* argument to routine */
  void (*c_func) __P ((void *) ); /* routine */
  struct callout *c_next;
};

static struct callout *callout = NULL; /* Callout list */
static struct timeval timenow;	       /* Current time */

/*
 * timeout - Schedule a timeout.
 */
void timeout (func, arg, secs, usecs) void (*func) __P ((void *) );
void *arg;
int secs, usecs;
{
  struct callout *newp, *p, **pp;

  /*
   * Allocate timeout.
   */
  if ((newp = (struct callout *) malloc (sizeof (struct callout))) == NULL)
    fatal ("Out of memory in timeout()!");
  newp->c_arg = arg;
  newp->c_func = func;
  gettimeofday (&timenow, NULL);
  newp->c_time.tv_sec = timenow.tv_sec + secs;
  newp->c_time.tv_usec = timenow.tv_usec + usecs;
  if (newp->c_time.tv_usec >= 1000000)
    {
      newp->c_time.tv_sec += newp->c_time.tv_usec / 1000000;
      newp->c_time.tv_usec %= 1000000;
    }

  /*
   * Find correct place and link it in.
   */
  for (pp = &callout; (p = *pp); pp = &p->c_next)
    if (newp->c_time.tv_sec < p->c_time.tv_sec ||
	(newp->c_time.tv_sec == p->c_time.tv_sec && newp->c_time.tv_usec < p->c_time.tv_usec))
      break;
  newp->c_next = p;
  *pp = newp;
}

/*
 * untimeout - Unschedule a timeout.
 */
void untimeout (func, arg) void (*func) __P ((void *) );
void *arg;
{
  struct callout **copp, *freep;

  /*
   * Find first matching timeout and remove it from the list.
   */
  for (copp = &callout; (freep = *copp); copp = &freep->c_next)
    if (freep->c_func == func && freep->c_arg == arg)
      {
	*copp = freep->c_next;
	free ((char *) freep);
	break;
      }
}

/*
 * calltimeout - Call any timeout routines which are now due.
 */
void
pppd_calltimeout ()
{
  struct callout *p;

  while (callout != NULL)
    {
      p = callout;

      if (gettimeofday (&timenow, NULL) < 0)
	fatal ("Failed to get time of day: %m");
      if (!(p->c_time.tv_sec < timenow.tv_sec ||
	    (p->c_time.tv_sec == timenow.tv_sec && p->c_time.tv_usec <= timenow.tv_usec)))
	break; /* no, it's not time yet */

      callout = p->c_next;
      (*p->c_func) (p->c_arg);

      free ((char *) p);
    }
}

// Not needed now, can be used to optimize tick mechanism.
#if 0
/*
 * timeleft - return the length of time until the next timeout is due.
 */
static struct timeval *
timeleft(tvp)
     struct timeval *tvp;
{
  if (callout == NULL)
    return NULL;

  gettimeofday(&timenow, NULL);
  tvp->tv_sec = callout->c_time.tv_sec - timenow.tv_sec;
  tvp->tv_usec = callout->c_time.tv_usec - timenow.tv_usec;
  if (tvp->tv_usec < 0) {
    tvp->tv_usec += 1000000;
    tvp->tv_sec -= 1;
  }
  if (tvp->tv_sec < 0)
    tvp->tv_sec = tvp->tv_usec = 0;

  return tvp;
}
#endif

/*
 * script_setenv - set an environment variable value to be used
 * for scripts that we run (e.g. ip-up, auth-up, etc.)
 */
void script_setenv (var, value, iskey) char *var, *value;
int iskey;
{
  // TODO: adpt ipcp up.
}

void
reset_link_stats (int u)
{
  // TODO: adapt to vpp pppox virtual interface.
}

/*
 * have_route_to - determine if the system has any route to
 * a given IP address.  `addr' is in network byte order.
 * Return value is 1 if yes, 0 if no, -1 if don't know.
 * For demand mode to work properly, we have to ignore routes
 * through our own interface.
 */
int
have_route_to (u_int32_t addr)
{
  int result = 0;
  // TODO: adapt to vpp.
  addr = addr;
  return result;
}

/********************************************************************
 *
 * Return user specified netmask, modified by any mask we might determine
 * for address `addr' (in network byte order).
 * Here we scan through the system's list of interfaces, looking for
 * any non-point-to-point interfaces which might appear to be on the same
 * network as `addr'.  If we find any, we OR in their netmask to the
 * user-specified netmask.
 */

u_int32_t
GetMask (u_int32_t addr)
{
  // TODO: whether to adapt.
  return addr;
}

/********************************************************************
 *
 * sifvjcomp - config tcp header compression
 */

int
sifvjcomp (int u, int vjcomp, int cidcomp, int maxcid)
{
  // TODO: support if needed later.
  return 1;
}

/********************************************************************
 *
 * sifup - Config the interface up and enable IP packets to pass.
 */

int
sifup (int u)
{
  u = u;
  return 1;
}

/********************************************************************
 *
 * sifdown - Disable the indicated protocol and config the interface
 *	     down if there are no remaining protocols.
 */

int
sifdown (int u)
{
  u = u;
  return 1;
}

/********************************************************************
 *
 * sifnpmode - Set the mode for handling packets for a given NP.
 */

int
sifnpmode (int u, int proto, enum NPmode mode)
{
  u = u;
  proto = proto;
  mode = mode;
  return 1;
}

/********************************************************************
 *
 * sifdefaultroute/cifdefaultroute are implemented in pppox.c, where
 * route changes are marshalled onto the VPP main thread.
 */

/********************************************************************
 *
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int
sifproxyarp (int unit, u_int32_t his_adr)
{
  unit = unit;
  his_adr = his_adr;
  return 1;
}

/*
 * notify - call a set of functions registered with add_notifier.
 */
void
notify (struct notifier *notif, int val)
{
  notif = notif;
  val = val;
}

/* List of protocol names, to make our messages a little more informative. */
struct protocol_list
{
  u_short proto;
  const char *name;
} protocol_list[] = {
  { 0x21, "IP" },
  { 0x23, "OSI Network Layer" },
  { 0x25, "Xerox NS IDP" },
  { 0x27, "DECnet Phase IV" },
  { 0x29, "Appletalk" },
  { 0x2b, "Novell IPX" },
  { 0x2d, "VJ compressed TCP/IP" },
  { 0x2f, "VJ uncompressed TCP/IP" },
  { 0x31, "Bridging PDU" },
  { 0x33, "Stream Protocol ST-II" },
  { 0x35, "Banyan Vines" },
  { 0x39, "AppleTalk EDDP" },
  { 0x3b, "AppleTalk SmartBuffered" },
  { 0x3d, "Multi-Link" },
  { 0x3f, "NETBIOS Framing" },
  { 0x41, "Cisco Systems" },
  { 0x43, "Ascom Timeplex" },
  { 0x45, "Fujitsu Link Backup and Load Balancing (LBLB)" },
  { 0x47, "DCA Remote Lan" },
  { 0x49, "Serial Data Transport Protocol (PPP-SDTP)" },
  { 0x4b, "SNA over 802.2" },
  { 0x4d, "SNA" },
  { 0x4f, "IP6 Header Compression" },
  { 0x51, "KNX Bridging Data" },
  { 0x53, "Encryption" },
  { 0x55, "Individual Link Encryption" },
  { 0x57, "IPv6" },
  { 0x59, "PPP Muxing" },
  { 0x5b, "Vendor-Specific Network Protocol" },
  { 0x61, "RTP IPHC Full Header" },
  { 0x63, "RTP IPHC Compressed TCP" },
  { 0x65, "RTP IPHC Compressed non-TCP" },
  { 0x67, "RTP IPHC Compressed UDP 8" },
  { 0x69, "RTP IPHC Compressed RTP 8" },
  { 0x6f, "Stampede Bridging" },
  { 0x73, "MP+" },
  { 0xc1, "NTCITS IPI" },
  { 0xfb, "single-link compression" },
  { 0xfd, "Compressed Datagram" },
  { 0x0201, "802.1d Hello Packets" },
  { 0x0203, "IBM Source Routing BPDU" },
  { 0x0205, "DEC LANBridge100 Spanning Tree" },
  { 0x0207, "Cisco Discovery Protocol" },
  { 0x0209, "Netcs Twin Routing" },
  { 0x020b, "STP - Scheduled Transfer Protocol" },
  { 0x020d, "EDP - Extreme Discovery Protocol" },
  { 0x0211, "Optical Supervisory Channel Protocol" },
  { 0x0213, "Optical Supervisory Channel Protocol" },
  { 0x0231, "Luxcom" },
  { 0x0233, "Sigma Network Systems" },
  { 0x0235, "Apple Client Server Protocol" },
  { 0x0281, "MPLS Unicast" },
  { 0x0283, "MPLS Multicast" },
  { 0x0285, "IEEE p1284.4 standard - data packets" },
  { 0x0287, "ETSI TETRA Network Protocol Type 1" },
  { 0x0289, "Multichannel Flow Treatment Protocol" },
  { 0x2063, "RTP IPHC Compressed TCP No Delta" },
  { 0x2065, "RTP IPHC Context State" },
  { 0x2067, "RTP IPHC Compressed UDP 16" },
  { 0x2069, "RTP IPHC Compressed RTP 16" },
  { 0x4001, "Cray Communications Control Protocol" },
  { 0x4003, "CDPD Mobile Network Registration Protocol" },
  { 0x4005, "Expand accelerator protocol" },
  { 0x4007, "ODSICP NCP" },
  { 0x4009, "DOCSIS DLL" },
  { 0x400B, "Cetacean Network Detection Protocol" },
  { 0x4021, "Stacker LZS" },
  { 0x4023, "RefTek Protocol" },
  { 0x4025, "Fibre Channel" },
  { 0x4027, "EMIT Protocols" },
  { 0x405b, "Vendor-Specific Protocol (VSP)" },
  { 0x8021, "Internet Protocol Control Protocol" },
  { 0x8023, "OSI Network Layer Control Protocol" },
  { 0x8025, "Xerox NS IDP Control Protocol" },
  { 0x8027, "DECnet Phase IV Control Protocol" },
  { 0x8029, "Appletalk Control Protocol" },
  { 0x802b, "Novell IPX Control Protocol" },
  { 0x8031, "Bridging NCP" },
  { 0x8033, "Stream Protocol Control Protocol" },
  { 0x8035, "Banyan Vines Control Protocol" },
  { 0x803d, "Multi-Link Control Protocol" },
  { 0x803f, "NETBIOS Framing Control Protocol" },
  { 0x8041, "Cisco Systems Control Protocol" },
  { 0x8043, "Ascom Timeplex" },
  { 0x8045, "Fujitsu LBLB Control Protocol" },
  { 0x8047, "DCA Remote Lan Network Control Protocol (RLNCP)" },
  { 0x8049, "Serial Data Control Protocol (PPP-SDCP)" },
  { 0x804b, "SNA over 802.2 Control Protocol" },
  { 0x804d, "SNA Control Protocol" },
  { 0x804f, "IP6 Header Compression Control Protocol" },
  { 0x8051, "KNX Bridging Control Protocol" },
  { 0x8053, "Encryption Control Protocol" },
  { 0x8055, "Individual Link Encryption Control Protocol" },
  { 0x8057, "IPv6 Control Protocol" },
  { 0x8059, "PPP Muxing Control Protocol" },
  { 0x805b, "Vendor-Specific Network Control Protocol (VSNCP)" },
  { 0x806f, "Stampede Bridging Control Protocol" },
  { 0x8073, "MP+ Control Protocol" },
  { 0x80c1, "NTCITS IPI Control Protocol" },
  { 0x80fb, "Single Link Compression Control Protocol" },
  { 0x80fd, "Compression Control Protocol" },
  { 0x8207, "Cisco Discovery Protocol Control" },
  { 0x8209, "Netcs Twin Routing" },
  { 0x820b, "STP - Control Protocol" },
  { 0x820d, "EDPCP - Extreme Discovery Protocol Ctrl Prtcl" },
  { 0x8235, "Apple Client Server Protocol Control" },
  { 0x8281, "MPLSCP" },
  { 0x8285, "IEEE p1284.4 standard - Protocol Control" },
  { 0x8287, "ETSI TETRA TNP1 Control Protocol" },
  { 0x8289, "Multichannel Flow Treatment Protocol" },
  { 0xc021, "Link Control Protocol" },
  { 0xc023, "Password Authentication Protocol" },
  { 0xc025, "Link Quality Report" },
  { 0xc027, "Shiva Password Authentication Protocol" },
  { 0xc029, "CallBack Control Protocol (CBCP)" },
  { 0xc02b, "BACP Bandwidth Allocation Control Protocol" },
  { 0xc02d, "BAP" },
  { 0xc05b, "Vendor-Specific Authentication Protocol (VSAP)" },
  { 0xc081, "Container Control Protocol" },
  { 0xc223, "Challenge Handshake Authentication Protocol" },
  { 0xc225, "RSA Authentication Protocol" },
  { 0xc227, "Extensible Authentication Protocol" },
  { 0xc229, "Mitsubishi Security Info Exch Ptcl (SIEP)" },
  { 0xc26f, "Stampede Bridging Authorization Protocol" },
  { 0xc281, "Proprietary Authentication Protocol" },
  { 0xc283, "Proprietary Authentication Protocol" },
  { 0xc481, "Proprietary Node ID Authentication Protocol" },
  { 0, NULL },
};

/*
 * protocol_name - find a name for a PPP protocol.
 */
const char *
protocol_name (proto)
int proto;
{
  struct protocol_list *lp;

  for (lp = protocol_list; lp->proto != 0; ++lp)
    if (proto == lp->proto)
      return lp->name;
  return NULL;
}
