/* PPP Stubs - Minimal stub implementations for pppox plugin */
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/ip/ip.h>

typedef unsigned short u_short;
typedef unsigned char u_char;

typedef struct option
{
  char *name;
  int type;
  void *val;
  char *description;
} option_t;

typedef int (*printer_func) (void *, char *, ...);
struct protent;

static void
lcp_init (int unit)
{
}
static void
lcp_input (int unit, u_char *pkt, int len)
{
}
static void
lcp_protrej (int unit)
{
}
static void
lcp_lowerup (int unit)
{
}
static void
lcp_lowerdown (int unit)
{
}
static void
lcp_open (int unit)
{
}
static void
lcp_close (int unit, char *reason)
{
}
static int
lcp_printpkt (u_char *pkt, int len, printer_func printer, void *arg)
{
  return 0;
}
static void
lcp_datainput (int unit, u_char *pkt, int len)
{
}
static void
lcp_check_options (void)
{
}
static int
lcp_demand_conf (int unit)
{
  return 0;
}

static void
ipcp_init (int unit)
{
}
static void
ipcp_input (int unit, u_char *pkt, int len)
{
}
static void
ipcp_protrej (int unit)
{
}
static void
ipcp_lowerup (int unit)
{
}
static void
ipcp_lowerdown (int unit)
{
}
static void
ipcp_open (int unit)
{
}
static void
ipcp_close (int unit, char *reason)
{
}
static int
ipcp_printpkt (u_char *pkt, int len, printer_func printer, void *arg)
{
  return 0;
}
static void
ipcp_datainput (int unit, u_char *pkt, int len)
{
}
static void
ipcp_check_options (void)
{
}
static int
ipcp_demand_conf (int unit)
{
  return 0;
}

static void
pap_init (int unit)
{
}
static void
pap_input (int unit, u_char *pkt, int len)
{
}
static void
pap_protrej (int unit)
{
}
static void
pap_lowerup (int unit)
{
}
static void
pap_lowerdown (int unit)
{
}
static void
pap_open (int unit)
{
}
static void
pap_close (int unit, char *reason)
{
}
static int
pap_printpkt (u_char *pkt, int len, printer_func printer, void *arg)
{
  return 0;
}
static void
pap_datainput (int unit, u_char *pkt, int len)
{
}
static void
pap_check_options (void)
{
}
static int
pap_demand_conf (int unit)
{
  return 0;
}

static void
chap_init (int unit)
{
}
static void
chap_input (int unit, u_char *pkt, int len)
{
}
static void
chap_protrej (int unit)
{
}
static void
chap_lowerup (int unit)
{
}
static void
chap_lowerdown (int unit)
{
}
static void
chap_open (int unit)
{
}
static void
chap_close (int unit, char *reason)
{
}
static int
chap_printpkt (u_char *pkt, int len, printer_func printer, void *arg)
{
  return 0;
}
static void
chap_datainput (int unit, u_char *pkt, int len)
{
}
static void
chap_check_options (void)
{
}
static int
chap_demand_conf (int unit)
{
  return 0;
}

struct protent
{
  u_short protocol;
  void (*init) (int unit);
  void (*input) (int unit, u_char *pkt, int len);
  void (*protrej) (int unit);
  void (*lowerup) (int unit);
  void (*lowerdown) (int unit);
  void (*open) (int unit);
  void (*close) (int unit, char *reason);
  int (*printpkt) (u_char *pkt, int len, printer_func printer, void *arg);
  void (*datainput) (int unit, u_char *pkt, int len);
  int enabled_flag;
  char *name;
  char *data_name;
  option_t *options;
  void (*check_options) (void);
  int (*demand_conf) (int unit);
};

struct protent lcp_protent = {
  0xc021,   lcp_init,  lcp_input,	  lcp_protrej,	  lcp_lowerup, lcp_lowerdown,
  lcp_open, lcp_close, lcp_printpkt,	  lcp_datainput,  1,	       "lcp",
  "LCP",    0,	       lcp_check_options, lcp_demand_conf
};

struct protent ipcp_protent = { 0x8021,
				ipcp_init,
				ipcp_input,
				ipcp_protrej,
				ipcp_lowerup,
				ipcp_lowerdown,
				ipcp_open,
				ipcp_close,
				ipcp_printpkt,
				ipcp_datainput,
				1,
				"ipcp",
				"IPCP",
				0,
				ipcp_check_options,
				ipcp_demand_conf };

struct protent pap_protent = {
  0xc023,   pap_init,  pap_input,	  pap_protrej,	  pap_lowerup, pap_lowerdown,
  pap_open, pap_close, pap_printpkt,	  pap_datainput,  1,	       "pap",
  "PAP",    0,	       pap_check_options, pap_demand_conf
};

struct protent chap_protent = { 0xc223,
				chap_init,
				chap_input,
				chap_protrej,
				chap_lowerup,
				chap_lowerdown,
				chap_open,
				chap_close,
				chap_printpkt,
				chap_datainput,
				1,
				"chap",
				"CHAP",
				0,
				chap_check_options,
				chap_demand_conf };

static void
ipv6cp_init (int unit)
{
}
static void
ipv6cp_input (int unit, u_char *pkt, int len)
{
}
static void
ipv6cp_protrej (int unit)
{
}
static void
ipv6cp_lowerup (int unit)
{
}
static void
ipv6cp_lowerdown (int unit)
{
}
static void
ipv6cp_open (int unit)
{
}
static void
ipv6cp_close (int unit, char *reason)
{
}
static int
ipv6cp_printpkt (u_char *pkt, int len, printer_func printer, void *arg)
{
  return 0;
}
static void
ipv6cp_datainput (int unit, u_char *pkt, int len)
{
}
static void
ipv6cp_check_options (void)
{
}
static int
ipv6cp_demand_conf (int unit)
{
  return 0;
}

struct protent ipv6cp_protent = { 0x8057,
				  ipv6cp_init,
				  ipv6cp_input,
				  ipv6cp_protrej,
				  ipv6cp_lowerup,
				  ipv6cp_lowerdown,
				  ipv6cp_open,
				  ipv6cp_close,
				  ipv6cp_printpkt,
				  ipv6cp_datainput,
				  1,
				  "ipv6cp",
				  "IPV6CP",
				  0,
				  ipv6cp_check_options,
				  ipv6cp_demand_conf };
