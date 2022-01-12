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
