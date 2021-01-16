/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifdef __KERNEL__

#if __linux__
# include <linux/unistd.h>
# include <linux/signal.h>
#endif

#else /* ! __KERNEL__ */

#ifdef __APPLE__
#define _XOPEN_SOURCE
#endif

#define _GNU_SOURCE		/* to get REG_* in ucontext.h */
#include <ucontext.h>
#undef __USE_GNU

#include <unistd.h>
#include <signal.h>
#include <grp.h>

#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <math.h>

#include <vppinfra/time.h>
#if __linux__
#include <vppinfra/linux/syscall.h>

#ifdef AF_NETLINK
#include <linux/types.h>
#include <linux/netlink.h>
#endif
#endif

#endif /* ! __KERNEL__ */


#ifdef __KERNEL__
# include <linux/socket.h>
# include <linux/in.h>
# include <linux/ip.h>
# include <linux/tcp.h>
# include <linux/udp.h>
# include <linux/icmp.h>
# include <linux/if_ether.h>
# include <linux/if_arp.h>
#else
# include <net/if.h>            /* struct ifnet may live here */
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <netinet/if_ether.h>
#endif /* __KERNEL__ */

#include <vppinfra/bitops.h> /* foreach_set_bit */
#include <vppinfra/format.h>
#include <vppinfra/error.h>

/* Format unix network address family (e.g. AF_INET). */
u8 * format_address_family (u8 * s, va_list * va)
{
  uword family = va_arg (*va, uword);
  u8 * t = (u8 *) "UNKNOWN";
  switch (family)
    {
#define _(x) case PF_##x: t = (u8 *) #x; break
      _ (UNSPEC);
      _ (UNIX);			/* Unix domain sockets 		*/
      _ (INET);			/* Internet IP Protocol 	*/
#ifdef PF_AX25
      _ (AX25);			/* Amateur Radio AX.25 		*/
#endif
#ifdef PF_IPX
      _ (IPX);			/* Novell IPX 			*/
#endif
#ifdef PF_APPLETALK
      _ (APPLETALK);		/* AppleTalk DDP 		*/
#endif
#ifdef PF_NETROM
      _ (NETROM);		/* Amateur Radio NET/ROM 	*/
#endif
#ifdef PF_BRIDGE
      _ (BRIDGE);		/* Multiprotocol bridge 	*/
#endif
#ifdef PF_ATMPVC
      _ (ATMPVC);		/* ATM PVCs			*/
#endif
#ifdef PF_X25
      _ (X25);			/* Reserved for X.25 project 	*/
#endif
#ifdef PF_INET6
      _ (INET6);		/* IP version 6			*/
#endif
#ifdef PF_ROSE
      _ (ROSE);			/* Amateur Radio X.25 PLP	*/
#endif
#ifdef PF_DECnet
      _ (DECnet);		/* Reserved for DECnet project	*/
#endif
#ifdef PF_NETBEUI
      _ (NETBEUI);		/* Reserved for 802.2LLC project*/
#endif
#ifdef PF_SECURITY
      _ (SECURITY);		/* Security callback pseudo AF */
#endif
#ifdef PF_KEY
      _ (KEY);			/* PF_KEY key management API */
#endif
#ifdef PF_NETLINK
      _ (NETLINK);
#endif
#ifdef PF_PACKET
      _ (PACKET);		/* Packet family		*/
#endif
#ifdef PF_ASH
      _ (ASH);			/* Ash				*/
#endif
#ifdef PF_ECONET
      _ (ECONET);		/* Acorn Econet			*/
#endif
#ifdef PF_ATMSVC
      _ (ATMSVC);		/* ATM SVCs			*/
#endif
#ifdef PF_SNA
      _ (SNA);			/* Linux SNA Project */
#endif
#ifdef PF_IRDA
      _ (IRDA);			/* IRDA sockets			*/
#endif
#undef _
    }
  vec_add (s, t, strlen ((char *) t));
  return s;
}

u8 * format_network_protocol (u8 * s, va_list * args)
{
  uword family = va_arg (*args, uword);
  uword protocol = va_arg (*args, uword);

#ifndef __KERNEL__
  struct protoent * p = getprotobynumber (protocol);

  ASSERT (family == AF_INET);
  if (p)
    return format (s, "%s", p->p_name);
  else
    return format (s, "%d", protocol);
#else
  return format (s, "%d/%d", family, protocol);
#endif
}

u8 * format_network_port (u8 * s, va_list * args)
{
  uword proto = va_arg (*args, uword);
  uword port = va_arg (*args, uword);

#ifndef __KERNEL__
  struct servent * p = getservbyport (port, proto == IPPROTO_UDP ? "udp" : "tcp");

  if (p)
    return format (s, "%s", p->s_name);
  else
    return format (s, "%d", port);
#else
  return format (s, "%s/%d", proto == IPPROTO_UDP ? "udp" : "tcp", port);
#endif
}

/* Format generic network address: takes two arguments family and address.
   Assumes network byte order. */
u8 * format_network_address (u8 * s, va_list * args)
{
  uword family = va_arg (*args, uword);
  u8 * addr    = va_arg (*args, u8 *);

  switch (family)
    {
    case AF_INET:
      s = format (s, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
      break;

    case AF_UNSPEC:
      /* We use AF_UNSPEC for ethernet addresses. */
      s = format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
      break;

    default:
      clib_error ("unsupported address family %d", family);
    }

  return s;
}

u8 * format_sockaddr (u8 * s, va_list * args)
{
  void * v = va_arg (*args, void *);
  struct sockaddr * sa = v;
  static u32 local_counter;

  switch (sa->sa_family)
    {
    case AF_INET:
      {
	struct sockaddr_in * i = v;
	s = format (s, "%U:%U",
		    format_network_address, AF_INET, &i->sin_addr.s_addr,
		    format_network_port, IPPROTO_TCP, ntohs (i->sin_port));
      }
      break;

    case AF_LOCAL:
      {
        /* 
         * There isn't anything useful to print.
         * The unix cli world uses the output to make a node name,
         * so we need to return a unique name. 
         */
        s = format (s, "local:%u", local_counter++);
      }
      break;

#ifndef __KERNEL__
#ifdef AF_NETLINK
    case AF_NETLINK:
      {
	struct sockaddr_nl * n = v;
	s = format (s, "KERNEL-NETLINK");
	if (n->nl_groups)
	  s = format (s, " (groups 0x%x)", n->nl_groups);
	break;
      }
#endif
#endif

    default:
      s = format (s, "sockaddr family %d", sa->sa_family);
      break;
    }

  return s;
}

#ifndef __APPLE__
u8 * format_tcp4_packet (u8 * s, va_list * args)
{
  u8 * p = va_arg (*args, u8 *);
  struct iphdr * ip = (void *) p;
  struct tcphdr * tcp = (void *) (ip + 1);

  s = format (s, "tcp %U:%U -> %U:%U",
	      format_network_address, AF_INET,  &ip->saddr,
	      format_network_port, IPPROTO_TCP, ntohs (tcp->source),
	      format_network_address, AF_INET,  &ip->daddr,
	      format_network_port, IPPROTO_TCP, ntohs (tcp->dest));

  s = format (s, ", seq 0x%08x -> 0x%08x", tcp->seq, tcp->ack_seq);
#define _(f) if (tcp->f) s = format (s, ", " #f);
  _ (syn); _ (ack); _ (fin); _ (rst); _ (psh); _ (urg);
#undef _

  if (tcp->window)
    s = format (s, ", window 0x%04x", tcp->window);
  if (tcp->urg)
    s = format (s, ", urg 0x%04x", tcp->urg_ptr);

  return s;
}

u8 * format_udp4_packet (u8 * s, va_list * args)
{
  u8 * p = va_arg (*args, u8 *);
  struct iphdr * ip = (void *) p;
  struct udphdr * udp = (void *) (ip + 1);

  s = format (s, "udp %U:%U -> %U:%U",
	      format_network_address, AF_INET,  &ip->saddr,
	      format_network_port, IPPROTO_UDP, ntohs (udp->uh_sport),
	      format_network_address, AF_INET,  &ip->daddr,
	      format_network_port, IPPROTO_UDP, ntohs (udp->uh_dport));

  return s;
}

u8 * format_icmp4_type_and_code (u8 * s, va_list * args)
{
  uword icmp_type = va_arg (*args, uword);
  uword icmp_code = va_arg (*args, uword);

  switch (icmp_type)
    {
#define _(f,str) case ICMP_##f: s = format (s, str); break;
      _ (ECHOREPLY, "echo reply");
      _ (DEST_UNREACH, "unreachable");
      _ (SOURCE_QUENCH, "source quench");
      _ (REDIRECT, "redirect");
      _ (ECHO, "echo request");
      _ (TIME_EXCEEDED, "time exceeded");
      _ (PARAMETERPROB, "parameter problem");
      _ (TIMESTAMP, "timestamp request");
      _ (TIMESTAMPREPLY, "timestamp reply");
      _ (INFO_REQUEST, "information request");
      _ (INFO_REPLY, "information reply");
      _ (ADDRESS, "address mask request");
      _ (ADDRESSREPLY, "address mask reply");
#undef _
    default:
      s = format (s, "unknown type 0x%x", icmp_type);
    }

  if (icmp_type == ICMP_DEST_UNREACH)
    {
      switch (icmp_code)
	{
#define _(f,str) case ICMP_##f: s = format (s, " " # str); break;
	  _ (NET_UNREACH, "network");
	  _ (HOST_UNREACH, "host");
	  _ (PROT_UNREACH, "protocol");
	  _ (PORT_UNREACH, "port");
	  _ (FRAG_NEEDED, ": fragmentation needed/DF set");
	  _ (SR_FAILED, "source route failed");
	  _ (NET_UNKNOWN, "network unknown");
	  _ (HOST_UNKNOWN, "host unknown");
	  _ (HOST_ISOLATED, "host isolated");
	  _ (NET_ANO, "network: admin. prohibited");
	  _ (HOST_ANO, "host: admin. prohibited");
	  _ (NET_UNR_TOS, "network for type-of-service");
	  _ (HOST_UNR_TOS, "host for type-of-service");
	  _ (PKT_FILTERED, ": packet filtered");
	  _ (PREC_VIOLATION, "precedence violation");
	  _ (PREC_CUTOFF, "precedence cut off");
#undef _
	default:
	  s = format (s, "unknown code 0x%x", icmp_code);
	}
    }
  else if (icmp_type == ICMP_REDIRECT)
    {
      switch (icmp_code)
	{
#define _(f,str) case ICMP_##f: s = format (s, " " # str); break;
	  _ (REDIR_NET, "network");
	  _ (REDIR_HOST, "host");
	  _ (REDIR_NETTOS, "network for type-of-service");
	  _ (REDIR_HOSTTOS, "host for type-of-service");
#undef _
	default:
	  s = format (s, "unknown code 0x%x", icmp_code);
	}
    }
  else if (icmp_type == ICMP_TIME_EXCEEDED)
    {
      switch (icmp_code)
	{
#define _(f,str) case ICMP_##f: s = format (s, " " # str); break;
	  _ (EXC_TTL, "time-to-live zero in transit");
	  _ (EXC_FRAGTIME, "time-to-live zero during reassembly");
#undef _
	default:
	  s = format (s, "unknown code 0x%x", icmp_code);
	}
    }

  return s;
}

typedef struct {
  u8 type;
  u8 code;
  u16 checksum;
} icmp4_t;

u8 * format_icmp4_packet (u8 * s, va_list * args)
{
  u8 * p = va_arg (*args, u8 *);
  struct iphdr * ip = (void *) p;
  icmp4_t * icmp = (void *) (ip + 1);
  s = format (s, "icmp %U %U -> %U",
	      format_icmp4_type_and_code, icmp->type, icmp->code,
	      format_network_address, AF_INET,  &ip->saddr,
	      format_network_address, AF_INET,  &ip->daddr);

  return s;
}

u8 * format_ip4_tos_byte (u8 * s, va_list * args)
{
  uword tos = va_arg (*args, uword);

  if (tos & IPTOS_LOWDELAY)
    s = format (s, "minimize-delay, ");
  if (tos & IPTOS_MINCOST)
    s = format (s, "minimize-cost, ");
  if (tos & IPTOS_THROUGHPUT)
    s = format (s, "maximize-throughput, ");
  if (tos & IPTOS_RELIABILITY)
    s = format (s, "maximize-reliability, ");

  switch (IPTOS_PREC (tos))
    {
#define _(x,y) case IPTOS_PREC_##x: s = format (s, y); break
      _ (NETCONTROL, "network");
      _ (INTERNETCONTROL, "internet");
      _ (CRITIC_ECP, "critical");
      _ (FLASH, "flash");
      _ (FLASHOVERRIDE, "flash-override");
      _ (IMMEDIATE, "immediate");
      _ (PRIORITY, "priority");
      _ (ROUTINE, "routine");
#undef _
    }

  return s;
}

u8 * format_ip4_packet (u8 * s, va_list * args)
{
  u8 * p = va_arg (*args, u8 *);
  struct iphdr * ip = (void *) p;

  static format_function_t * f[256];

  if (! f[IPPROTO_TCP])
    {
      f[IPPROTO_TCP] = format_tcp4_packet;
      f[IPPROTO_UDP] = format_udp4_packet;
      f[IPPROTO_ICMP] = format_icmp4_packet;
    }

  if (f[ip->protocol])
    return format (s, "%U", f[ip->protocol], p);

  s = format (s, "%U: %U -> %U",
	      format_network_protocol, AF_INET, ip->protocol,
	      format_network_address, AF_INET,  &ip->saddr,
	      format_network_address, AF_INET,  &ip->daddr);

  return s;
}

#define foreach_unix_arphrd_type		\
  _ (NETROM, 0)					\
  _ (ETHER, 1)					\
  _ (EETHER, 2)					\
  _ (AX25, 3)					\
  _ (PRONET, 4)					\
  _ (CHAOS, 5)					\
  _ (IEEE802, 6)				\
  _ (ARCNET, 7)					\
  _ (APPLETLK, 8)				\
  _ (DLCI, 15)					\
  _ (ATM, 19)					\
  _ (METRICOM, 23)				\
  _ (IEEE1394, 24)				\
  _ (EUI64, 27)					\
  _ (INFINIBAND, 32)				\
  _ (SLIP, 256)					\
  _ (CSLIP, 257)				\
  _ (SLIP6, 258)				\
  _ (CSLIP6, 259)				\
  _ (RSRVD, 260)				\
  _ (ADAPT, 264)				\
  _ (ROSE, 270)					\
  _ (X25, 271)					\
  _ (HWX25, 272)				\
  _ (PPP, 512)					\
  _ (HDLC, 513)					\
  _ (LAPB, 516)					\
  _ (DDCMP, 517)				\
  _ (RAWHDLC, 518)				\
  _ (TUNNEL, 768)				\
  _ (TUNNEL6, 769)				\
  _ (FRAD, 770)					\
  _ (SKIP, 771)					\
  _ (LOOPBACK, 772)				\
  _ (LOCALTLK, 773)				\
  _ (FDDI, 774)					\
  _ (BIF, 775)					\
  _ (SIT, 776)					\
  _ (IPDDP, 777)				\
  _ (IPGRE, 778)				\
  _ (PIMREG, 779)				\
  _ (HIPPI, 780)				\
  _ (ASH, 781)					\
  _ (ECONET, 782)				\
  _ (IRDA, 783)					\
  _ (FCPP, 784)					\
  _ (FCAL, 785)					\
  _ (FCPL, 786)					\
  _ (FCFABRIC, 787)				\
  _ (IEEE802_TR, 800)				\
  _ (IEEE80211, 801)				\
  _ (IEEE80211_PRISM, 802)			\
  _ (IEEE80211_RADIOTAP, 803)			\
  _ (VOID, 0xFFFF)				\
  _ (NONE, 0xFFFE)

u8 * format_unix_arphrd (u8 * s, va_list * args)
{
#ifndef __COVERITY__ /* doesn't understand this at all... */
  u32 x = va_arg (*args, u32);
  char * t;
  switch (x)
    {
#define _(f,n) case ARPHRD_##f: t = #f; break;
      foreach_unix_arphrd_type
#undef _
    default:
      t = 0;
      break;
    }

  if (t)
    s = format (s, "%s", t);
  else
    s = format (s, "unknown 0x%x", x);
#endif
  return s;
}

#define foreach_unix_interface_flag		\
  _ (up)					\
  _ (broadcast)					\
  _ (debug)					\
  _ (loopback)					\
  _ (pointopoint)				\
  _ (notrailers)				\
  _ (running)					\
  _ (noarp)					\
  _ (promisc)					\
  _ (allmulti)					\
  _ (master)					\
  _ (slave)					\
  _ (multicast)					\
  _ (portsel)					\
  _ (automedia)					\
  _ (dynamic)					\
  _ (lower_up)					\
  _ (dormant)					\
  _ (echo)

static char * unix_interface_flag_names[] = {
#define _(f) #f,
  foreach_unix_interface_flag
#undef _
};

u8 * format_unix_interface_flags (u8 * s, va_list * args)
{
  u32 x = va_arg (*args, u32);
  u32 i;

  if (x == 0)
    s = format (s, "none");
  else foreach_set_bit (i, x, ({
    if (i < ARRAY_LEN (unix_interface_flag_names))
      s = format (s, "%s", unix_interface_flag_names[i]);
    else
      s = format (s, "unknown %d", i);
    if (x >> (i + 1))
      s = format (s, ", ");
  }));
  return s;
}

typedef struct {
  u16 ar_hrd;			/* format of hardware address	*/
  u16 ar_pro;			/* format of protocol address	*/
  u8  ar_hln;			/* length of hardware address	*/
  u8  ar_pln;			/* length of protocol address	*/
  u16 ar_op;			/* ARP opcode (command)		*/
  u8  ar_sha[6];		/* sender hardware address	*/
  u8  ar_spa[4];		/* sender IP address		*/
  u8  ar_tha[6];		/* target hardware address	*/
  u8  ar_tpa[4];		/* target IP address		*/
} arp_ether_ip4_t;

u8 * format_arp_packet (u8 * s, va_list * args)
{
  arp_ether_ip4_t * a = va_arg (*args, arp_ether_ip4_t *);
  char * op = "unknown";

  if (a->ar_pro != ETH_P_IP ||
      a->ar_hrd != ARPHRD_ETHER)
    return s;

  switch (a->ar_op)
    {
#define _(f) case ARPOP_##f: op = #f; break;
      _ (REQUEST);
      _ (REPLY);
      _ (RREQUEST);
      _ (RREPLY);
#undef _
    }

  s = format (s, "%s %U %U -> %U %U",
	      op,
	      format_network_address, AF_INET,   a->ar_spa,
	      format_network_address, AF_UNSPEC, a->ar_sha,
	      format_network_address, AF_INET,   a->ar_tpa,
	      format_network_address, AF_UNSPEC, a->ar_tha);
  return s;
}

u8 * format_ethernet_proto (u8 * s, va_list * args)
{
  uword type = va_arg (*args, uword);
  char * t = 0;

  switch (type)
    {
    case 0: t = "BPDU"; break;
#define _(f) case ETH_P_##f: t = #f; break;
      _ (LOOP);
      _ (PUP);
#ifdef ETH_P_PUPAT
      _ (PUPAT);
#endif
      _ (IP);
      _ (X25);
      _ (ARP);
      _ (BPQ);
#ifdef ETH_P_PUPAT
      _ (IEEEPUP);
      _ (IEEEPUPAT);
#endif
      _ (DEC);
      _ (DNA_DL);
      _ (DNA_RC);
      _ (DNA_RT);
      _ (LAT);
      _ (DIAG);
      _ (CUST);
      _ (SCA);
      _ (RARP);
      _ (ATALK);
      _ (AARP);
      _ (IPX);
      _ (IPV6);
#ifdef ETH_P_PPP_DISC
      _ (PPP_DISC);
      _ (PPP_SES);
#endif
#ifdef ETH_P_ATMMPOA
      _ (ATMMPOA);
      _ (ATMFATE);
#endif
      _ (802_3);
      _ (AX25);
      _ (ALL);
      _ (802_2);
      _ (SNAP);
      _ (DDCMP);
      _ (WAN_PPP);
      _ (PPP_MP);
      _ (LOCALTALK);
      _ (PPPTALK);
      _ (TR_802_2);
      _ (MOBITEX);
      _ (CONTROL);
      _ (IRDA);
#ifdef ETH_P_ECONET
      _ (ECONET);
#endif
#undef _
    }

  if (t)
    vec_add (s, t, strlen (t));
  else
    s = format (s, "ether-type 0x%x", type);
  return s;
}

u8 * format_ethernet_packet (u8 * s, va_list * args)
{
  struct ethhdr * h = va_arg (*args, struct ethhdr *);
  uword proto = h->h_proto;
  u8 * payload = (void *) (h + 1);
  u32 indent;

  /* Check for 802.2/802.3 encapsulation. */
  if (proto < ETH_DATA_LEN)
    {
      typedef struct {
	u8 dsap, ssap, control;
	u8 orig_code[3];
	u16 proto;
      } ethhdr_802_t;
      ethhdr_802_t * h1 = (void *) (h + 1);
      proto = h1->proto;
      payload = (void *) (h1 + 1);
    }

  indent = format_get_indent (s);

  s = format (s, "%U: %U -> %U",
	      format_ethernet_proto, proto,
	      format_network_address, AF_UNSPEC, h->h_source,
	      format_network_address, AF_UNSPEC, h->h_dest);

  switch (proto)
    {
    case ETH_P_ARP:
      s = format (s, "\n%U%U",
		  format_white_space, indent,
		  format_arp_packet, payload);
      break;
    }

  return s;
}

#ifndef __KERNEL__
u8 * format_hostname (u8 * s, va_list * args)
{
  char buffer[1024];
  char * b = buffer;
  if (gethostname (b, sizeof (buffer)) < 0)
    b = "noname";
  return format (s, "%s", b);
}
#endif

#ifndef __KERNEL__
u8 * format_timeval (u8 * s, va_list * args)
{
  char * fmt = va_arg (*args, char *);
  struct timeval * tv = va_arg (*args, struct timeval *);
  struct tm * tm;
  word msec;
  char * f, c;

  if (! fmt)
    fmt = "y/m/d H:M:S:F";

  if (! tv)
    {
      static struct timeval now;
      gettimeofday (&now, 0);
      tv = &now;
    }

  msec = flt_round_nearest (1e-3 * tv->tv_usec);
  if (msec >= 1000)
    { msec = 0; tv->tv_sec++; }

  {
    time_t t = tv->tv_sec;
    tm = localtime (&t);
  }

  for (f = fmt; *f; f++)
    {
      uword what;
      char * what_fmt = "%d";

      switch (c = *f)
	{
	default:
	  vec_add1 (s, c);
	  continue;

	case 'y':
	  what = 1900 + tm->tm_year;
	  what_fmt = "%4d";
	  break;
	case 'm':
	  what = tm->tm_mon + 1;
	  what_fmt = "%02d";
	  break;
	case 'd':
	  what = tm->tm_mday;
	  what_fmt = "%02d";
	  break;
	case 'H':
	  what = tm->tm_hour;
	  what_fmt = "%02d";
	  break;
	case 'M':
	  what = tm->tm_min;
	  what_fmt = "%02d";
	  break;
	case 'S':
	  what = tm->tm_sec;
	  what_fmt = "%02d";
	  break;
	case 'F':
	  what = msec;
	  what_fmt = "%03d";
	  break;
	}

      s = format (s, what_fmt, what);
    }

  return s;
}
#endif

u8 * format_time_float (u8 * s, va_list * args)
{
  u8 * fmt = va_arg (*args, u8 *);
  f64 t = va_arg (*args, f64);
  struct timeval tv;
  if (t <= 0)
    t = unix_time_now ();
  tv.tv_sec = t;
  tv.tv_usec = 1e6*(t - tv.tv_sec);
  return format (s, "%U", format_timeval, fmt, &tv);
}

u8 * format_signal (u8 * s, va_list * args)
{
  uword signum = va_arg (*args, uword);
  char * t = 0;
  switch (signum)
    {
#define _(x) case x: t = #x; break;
      _ (SIGHUP);
      _ (SIGINT);
      _ (SIGQUIT);
      _ (SIGILL);
      _ (SIGTRAP);
      _ (SIGABRT);
      _ (SIGBUS);
      _ (SIGFPE);
      _ (SIGKILL);
      _ (SIGUSR1);
      _ (SIGSEGV);
      _ (SIGUSR2);
      _ (SIGPIPE);
      _ (SIGALRM);
      _ (SIGTERM);
#ifdef SIGSTKFLT
      _ (SIGSTKFLT);
#endif
      _ (SIGCHLD);
      _ (SIGCONT);
      _ (SIGSTOP);
      _ (SIGTSTP);
      _ (SIGTTIN);
      _ (SIGTTOU);
      _ (SIGURG);
      _ (SIGXCPU);
      _ (SIGXFSZ);
      _ (SIGVTALRM);
      _ (SIGPROF);
      _ (SIGWINCH);
      _ (SIGIO);
      _ (SIGPWR);
#ifdef SIGSYS
      _ (SIGSYS);
#endif
#undef _
    default:
      return format (s, "unknown %d", signum);
    }

  vec_add (s, t, strlen (t));
  return s;
}

u8 * format_ucontext_pc (u8 * s, va_list * args)
{
  ucontext_t * uc __attribute__((unused));
  unsigned long * regs = 0;
  uword reg_no = 0;

  uc = va_arg (*args, ucontext_t *);

#if defined (powerpc)
  regs = &uc->uc_mcontext.uc_regs->gregs[0];
#elif defined (powerpc64)
  regs = &uc->uc_mcontext.uc_regs->gp_regs[0];
#elif defined (i386) || defined (__x86_64__)
  regs = (void *) &uc->uc_mcontext.gregs[0];
#endif

#if defined (powerpc) || defined (powerpc64)
  reg_no = PT_NIP;
#elif defined (i386)
  reg_no = REG_EIP;
#elif defined (__x86_64__)
  reg_no = REG_RIP;
#else
  reg_no = 0;
  regs = 0;
#endif

  if (! regs)
    return format (s, "unsupported");
  else
    return format (s, "%p", regs[reg_no]);
}

__clib_export uword
unformat_unix_gid (unformat_input_t * input, va_list * args)
{
  gid_t *gid = va_arg (*args, gid_t *);
  struct group *grp = 0;
  int r;
  u8 *s;

  if (unformat (input, "%d", &r))
    {
      grp = getgrgid (r);
    }
  else if (unformat (input, "%s", &s))
    {
      grp = getgrnam ((char *) s);
      vec_free (s);
    }
  if (grp)
    {
      *gid = grp->gr_gid;
      return 1;
    }
  return 0;
}

#endif /* __KERNEL__ */
