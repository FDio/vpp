/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <memory.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <string.h>
#include <dlfcn.h>

#include "../packetdrill/gtests/net/packetdrill/packetdrill.h"

#define ETH_ALEN       6      /* MAC len  */
#define ETHERTYPE_IP   0x0800 /* IP protocol version 4 */
#define ETHERTYPE_IPV6 0x86dd /* IP protocol version 6 */
#define ETH_MAXPACKET  1500   /* MTU*/

uint8_t local_mac[ETH_ALEN];
uint8_t remote_mac[ETH_ALEN] = { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff };
int packet_fd;
const char *local_interface = "vppvethhost";

struct sockaddr_ll local_device;
struct ether_header ether;
static void *ldpreload_handle = NULL;

struct ldp_interface
{
  int (*socket) (int domain, int type, int protocol);
  int (*bind) (int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int (*listen) (int sockfd, int backlog);
  int (*accept) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  int (*connect) (int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  ssize_t (*read) (int fd, void *buf, size_t count);
  ssize_t (*readv) (int fd, const struct iovec *iov, int iovcnt);
  ssize_t (*recv) (int sockfd, void *buf, size_t len, int flags);
  ssize_t (*recvfrom) (int sockfd, void *buf, size_t len, int flags,
		       struct sockaddr *src_addr, socklen_t *addrlen);
  ssize_t (*recvmsg) (int sockfd, struct msghdr *msg, int flags);
  ssize_t (*write) (int fd, const void *buf, size_t count);
  ssize_t (*writev) (int fd, const struct iovec *iov, int iovcnt);
  ssize_t (*send) (int sockfd, const void *buf, size_t len, int flags);
  ssize_t (*sendto) (int sockfd, const void *buf, size_t len, int flags,
		     const struct sockaddr *dest_addr, socklen_t addrlen);
  ssize_t (*sendmsg) (int sockfd, const struct msghdr *msg, int flags);
  int (*fcntl) (int fd, int cmd, ...);
  int (*ioctl) (int fd, unsigned long request, ...);
  int (*close) (int fd);
  int (*shutdown) (int sockfd, int how);
  int (*getsockopt) (int sockfd, int level, int optname, void *optval,
		     socklen_t *optlen);
  int (*setsockopt) (int sockfd, int level, int optname, const void *optval,
		     socklen_t optlen);
  int (*poll) (struct pollfd *fds, nfds_t nfds, int timeout);
  int (*epoll_create) (int size);
  int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event);
  int (*epoll_wait) (int epfd, struct epoll_event *events, int maxevents,
		     int timeout);
  int (*pipe) (int pipefd[2]);
  int (*splice) (int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
		 size_t len, unsigned int flags);
};

struct ldp_interface lifc;

static uint64_t
now_usecs (void)
{
  struct timeval tv;

  gettimeofday (&tv, NULL);
  return ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
}
int
pd_usleep (void *userdata, useconds_t usec)
{
  return usleep (usec);
}

int
pd_gettimeofday (void *userdata, struct timeval *tv, struct timezone *tz)
{
  return gettimeofday (tv, tz);
}

void
pd_free (void *userdata)
{
  if (packet_fd > 0)
    {
      close (packet_fd);
    }
  return;
}

int
pd_socket (void *userdata, int domain, int type, int protocol)
{
  if (lifc.socket)
    return lifc.socket (domain, type, protocol);

  fprintf (stderr, "socket() is missing");
  return -1;
}

int
pd_bind (void *userdata, int sockfd, const struct sockaddr *addr,
	 socklen_t addrlen)
{
  if (lifc.bind)
    return lifc.bind (sockfd, addr, addrlen);

  fprintf (stderr, "bind() is missing");
  return -1;
}

int
pd_listen (void *userdata, int sockfd, int backlog)
{
  if (lifc.listen)
    return lifc.listen (sockfd, backlog);

  fprintf (stderr, "listen() is missing");
  return -1;
}

int
pd_accept (void *userdata, int sockfd, struct sockaddr *addr,
	   socklen_t *addrlen)
{
  if (lifc.accept)
    return lifc.accept (sockfd, addr, addrlen);

  fprintf (stderr, "accept() is missing");
  return -1;
}

int
pd_connect (void *userdata, int sockfd, const struct sockaddr *addr,
	    socklen_t addrlen)
{
  if (lifc.connect)
    return lifc.connect (sockfd, addr, addrlen);

  fprintf (stderr, "connect() is missing");
  return -1;
}
ssize_t
pd_read (void *userdata, int fd, void *buf, size_t count)
{
  if (lifc.read)
    return lifc.read (fd, buf, count);

  fprintf (stderr, "read() is missing");
  return -1;
}
ssize_t
pd_readv (void *userdata, int fd, const struct iovec *iov, int iovcnt)
{
  if (lifc.readv)
    return lifc.readv (fd, iov, iovcnt);

  fprintf (stderr, "readv() is missing");
  return -1;
}
ssize_t
pd_recv (void *userdata, int sockfd, void *buf, size_t len, int flags)
{
  if (lifc.recv)
    return lifc.recv (sockfd, buf, len, flags);

  fprintf (stderr, "recv() is missing");
  return -1;
}
ssize_t
pd_recvfrom (void *userdata, int sockfd, void *buf, size_t len, int flags,
	     struct sockaddr *src_addr, socklen_t *addrlen)
{
  if (lifc.recvfrom)
    return lifc.recvfrom (sockfd, buf, len, flags, src_addr, addrlen);

  fprintf (stderr, "recvfrom() is missing");
  return -1;
}
ssize_t
pd_recvmsg (void *userdata, int sockfd, struct msghdr *msg, int flags)
{
  if (lifc.recvmsg)
    return lifc.recvmsg (sockfd, msg, flags);

  fprintf (stderr, "recvmsg() is missing");
  return -1;
}
ssize_t
pd_write (void *userdata, int fd, const void *buf, size_t count)
{
  if (lifc.write)
    return lifc.write (fd, buf, count);

  fprintf (stderr, "write() is missing");
  return -1;
}
ssize_t
pd_writev (void *userdata, int fd, const struct iovec *iov, int iovcnt)
{
  if (lifc.writev)
    return lifc.writev (fd, iov, iovcnt);

  fprintf (stderr, "writev() is missing");
  return -1;
}
ssize_t
pd_send (void *userdata, int sockfd, const void *buf, size_t len, int flags)
{
  if (lifc.send)
    return lifc.send (sockfd, buf, len, flags);

  fprintf (stderr, "send() is missing");
  return -1;
}
ssize_t
pd_sendto (void *userdata, int sockfd, const void *buf, size_t len, int flags,
	   const struct sockaddr *dest_addr, socklen_t addrlen)
{
  if (lifc.sendto)
    return lifc.sendto (sockfd, buf, len, flags, dest_addr, addrlen);

  fprintf (stderr, "connect() is missing");
  return -1;
}
ssize_t
pd_sendmsg (void *userdata, int sockfd, const struct msghdr *msg, int flags)
{
  if (lifc.sendmsg)
    return lifc.sendmsg (sockfd, msg, flags);

  fprintf (stderr, "sendmsg() is missing");
  return -1;
}
int
pd_fcntl (void *userdata, int fd, int cmd, ...)
{
  void *arg;
  va_list ap;

  va_start (ap, cmd);
  arg = va_arg (ap, void *);
  va_end (ap);

  if (lifc.fcntl)
    return lifc.fcntl (fd, cmd, arg);
  fprintf (stderr, "fcntl() is missing");
  return -1;
}
int
pd_ioctl (void *userdata, int fd, unsigned long request, ...)
{
  void *arg;
  va_list ap;

  va_start (ap, request);
  arg = va_arg (ap, void *);
  va_end (ap);
  if (lifc.ioctl)
    return lifc.ioctl (fd, request, arg);
  fprintf (stderr, "ioctl() is missing");
  return -1;
}
int
pd_close (void *userdata, int fd)
{
  if (lifc.close)
    return lifc.close (fd);

  fprintf (stderr, "close() is missing");
  return -1;
}
int
pd_shutdown (void *userdata, int sockfd, int how)
{
  if (lifc.shutdown)
    return lifc.shutdown (sockfd, how);
  fprintf (stderr, "shutdown() is missing");
  return -1;
}
int
pd_getsockopt (void *userdata, int sockfd, int level, int optname,
	       void *optval, socklen_t *optlen)
{
  if (lifc.getsockopt)
    return lifc.getsockopt (sockfd, level, optname, optval, optlen);
  fprintf (stderr, "getsockopt() is missing");
  return -1;
}
int
pd_setsockopt (void *userdata, int sockfd, int level, int optname,
	       const void *optval, socklen_t optlen)
{
  if (lifc.setsockopt)
    return lifc.setsockopt (sockfd, level, optname, optval, optlen);
  fprintf (stderr, "setsockopt() is missing");
  return -1;
}
int
pd_poll (void *userdata, struct pollfd *fds, nfds_t nfds, int timeout)
{
  if (lifc.poll)
    return lifc.poll (fds, nfds, timeout);
  fprintf (stderr, "poll() is missing");
  return -1;
}

int
pd_epoll_create (void *userdata, int size)
{
  if (lifc.epoll_create)
    return lifc.epoll_create (size);
  fprintf (stderr, "epoll_create() is missing");
  return -1;
}
int
pd_epoll_ctl (void *userdata, int epfd, int op, int fd,
	      struct epoll_event *event)
{
  if (lifc.epoll_ctl)
    return lifc.epoll_ctl (epfd, op, fd, event);
  fprintf (stderr, "epoll_ctl() is missing");
  return -1;
}
int
pd_epoll_wait (void *userdata, int epfd, struct epoll_event *events,
	       int maxevents, int timeout)
{
  if (lifc.epoll_wait)
    return lifc.epoll_wait (epfd, events, maxevents, timeout);
  fprintf (stderr, "epoll_wait() is missing");
  return -1;
}
int
pd_pipe (void *userdata, int pipefd[2])
{
  if (lifc.pipe)
    return lifc.pipe (pipefd);
  fprintf (stderr, "pipe() is missing");
  return -1;
}
int
pd_splice (void *userdata, int fd_in, loff_t *off_in, int fd_out,
	   loff_t *off_out, size_t len, unsigned int flags)
{
  if (lifc.splice)
    return lifc.splice (fd_in, off_in, fd_out, off_out, len, flags);
  fprintf (stdout, "splice() is missiog");
  return -1;
}

int
pd_netdev_send (void *userdata, const void *buf, size_t count)
{
  uint8_t ether_frame[ETH_MAXPACKET];

  size_t frame_length = 0;
  if (count + sizeof (ether) > ETH_MAXPACKET)
    {
      fprintf (stderr, "ip packet size (%lu ) is too long", count);
      return -1;
    }

  memcpy (ether_frame, &ether, sizeof (ether));
  frame_length += sizeof (ether);

  memcpy (ether_frame + frame_length, buf, count);
  frame_length += count;

  if (sendto (packet_fd, ether_frame, frame_length, 0,
	      (struct sockaddr *) &local_device, sizeof (local_device)) <= 0)
    {
      perror ("sendto error");
      return -1;
    }

  return 0;
}

int
pd_netdev_recv (void *userdata, void *buf, size_t *count,
		long long *time_usecs)
{
  char ether_frame[ETH_MAXPACKET];
  /* Read the packet out of our kernel packet socket buffer. */
  int in_bytes =
    recvfrom (packet_fd, ether_frame, ETH_MAXPACKET, 0, NULL, NULL);

  if (in_bytes < sizeof (struct ether_header))
    {
      *count = 0;
      fprintf (stderr, "recvfrom error");
      return -1;
    }

  memcpy (buf, ether_frame + sizeof (struct ether_header),
	  in_bytes - sizeof (struct ether_header));
  *count = in_bytes - sizeof (struct ether_header);
  *time_usecs = now_usecs ();
  return 0;
}

void
ether_head_init ()
{

  memcpy (ether.ether_shost, local_mac, ETH_ALEN);
  memcpy (ether.ether_dhost, remote_mac, ETH_ALEN);
  ether.ether_type = htons (ETHERTYPE_IP);

  return;
}

int
packet_socket_init ()
{
  if ((packet_fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP))) < 0)
    {
      perror ("socket() error");
      return -1;
    }

  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  memcpy (ifr.ifr_name, local_interface, strlen (local_interface));
  if (ioctl (packet_fd, SIOCGIFHWADDR, &ifr) < 0)
    {
      perror ("ioctl() error");
      return -1;
    }

  memset (&local_device, 0, sizeof (local_device));
  local_device.sll_family = AF_PACKET;

  local_device.sll_ifindex = if_nametoindex (local_interface);
  ;
  if (local_device.sll_ifindex < 0)
    {
      perror ("if_nametoIndex() error");
      return -1;
    }

  memcpy (local_device.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  local_device.sll_halen = htons (ETH_ALEN);
  local_device.sll_protocol = htons (ETH_P_IP);

  if (bind (packet_fd, (struct sockaddr *) &local_device,
	    sizeof (local_device)) < 0)
    return -1;

  memcpy (local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  return 0;
}

void
ldpreload (struct ldp_interface *plifc)
{
  char *ldpreload_so = NULL;

  ldpreload_so = getenv ("LD_PRELOAD");
  if (!ldpreload_so)
    {
      fprintf (stderr, "LD_PRELOAD is not set");
      return;
    }

  ldpreload_handle = dlopen (ldpreload_so, RTLD_NOW | RTLD_LOCAL |
					     RTLD_NODELETE | RTLD_DEEPBIND);
  if (!ldpreload_handle)
    {
      fprintf (stderr, "%s is not found", ldpreload_so);
      return;
    }

  plifc->socket = (int (*) (int, int, int)) dlsym (ldpreload_handle, "socket");
  plifc->bind = (int (*) (int, const struct sockaddr *, socklen_t)) dlsym (
    ldpreload_handle, "bind");
  plifc->listen = (int (*) (int, int)) dlsym (ldpreload_handle, "listen");
  plifc->accept = (int (*) (int, struct sockaddr *, socklen_t *)) dlsym (
    ldpreload_handle, "accept");
  plifc->connect = (int (*) (int, const struct sockaddr *, socklen_t)) dlsym (
    ldpreload_handle, "connect");
  plifc->read =
    (ssize_t (*) (int, void *, size_t)) dlsym (ldpreload_handle, "read");
  plifc->readv = (ssize_t (*) (int, const struct iovec *, int)) dlsym (
    ldpreload_handle, "readv");
  plifc->recv =
    (ssize_t (*) (int, void *, size_t, int)) dlsym (ldpreload_handle, "recv");
  plifc->recvfrom =
    (ssize_t (*) (int, void *, size_t, int, struct sockaddr *,
		  socklen_t *)) dlsym (ldpreload_handle, "recvfrom");
  plifc->recvmsg = (ssize_t (*) (int, struct msghdr *, int)) dlsym (
    ldpreload_handle, "recvmsg");
  plifc->write = (ssize_t (*) (int, const void *, size_t)) dlsym (
    ldpreload_handle, "write");
  plifc->writev = (ssize_t (*) (int, const struct iovec *, int)) dlsym (
    ldpreload_handle, "writev");
  plifc->send = (ssize_t (*) (int, const void *, size_t, int)) dlsym (
    ldpreload_handle, "send");
  plifc->sendto =
    (ssize_t (*) (int, const void *, size_t, int, const struct sockaddr *,
		  socklen_t)) dlsym (ldpreload_handle, "sendto");
  plifc->sendmsg = (ssize_t (*) (int, const struct msghdr *, int)) dlsym (
    ldpreload_handle, "sendmsg");
  plifc->fcntl = (int (*) (int, int, ...)) dlsym (ldpreload_handle, "fcntl");
  plifc->ioctl =
    (int (*) (int, unsigned long, ...)) dlsym (ldpreload_handle, "ioctl");
  plifc->close = (int (*) (int)) dlsym (ldpreload_handle, "close");
  plifc->shutdown = (int (*) (int, int)) dlsym (ldpreload_handle, "shutdown");
  plifc->getsockopt = (int (*) (int, int, int, void *, socklen_t *)) dlsym (
    ldpreload_handle, "getsockopt");
  plifc->setsockopt =
    (int (*) (int, int, int, const void *, socklen_t)) dlsym (ldpreload_handle,
							      "setsockopt");
  plifc->poll =
    (int (*) (struct pollfd *, nfds_t, int)) dlsym (ldpreload_handle, "poll");
  plifc->epoll_create =
    (int (*) (int)) dlsym (ldpreload_handle, "epoll_create");
  plifc->epoll_ctl = (int (*) (int, int, int, struct epoll_event *)) dlsym (
    ldpreload_handle, "epoll_ctl");
  plifc->epoll_wait = (int (*) (int, struct epoll_event *, int, int)) dlsym (
    ldpreload_handle, "epoll_wait");
  plifc->pipe = (int (*) (int[2])) dlsym (ldpreload_handle, "pipe");
  plifc->splice = (int (*) (int, loff_t *, int, loff_t *, size_t,
			    unsigned int)) dlsym (ldpreload_handle, "splice");

  return;
}

void
packetdrill_interface_init (const char *flags,
			    struct packetdrill_interface *ifc)
{

  packet_socket_init ();
  ether_head_init ();
  ldpreload (&lifc);

  ifc->free = pd_free;
  ifc->socket = pd_socket;
  ifc->bind = pd_bind;
  ifc->listen = pd_listen;
  ifc->accept = pd_accept;
  ifc->connect = pd_connect;
  ifc->read = pd_read;
  ifc->readv = pd_readv;
  ifc->recv = pd_recv;
  ifc->recvfrom = pd_recvfrom;
  ifc->recvmsg = pd_recvmsg;
  ifc->write = pd_write;
  ifc->writev = pd_writev;
  ifc->send = pd_send;
  ifc->sendto = pd_sendto;
  ifc->sendmsg = pd_sendmsg;
  ifc->fcntl = pd_fcntl;
  ifc->ioctl = pd_ioctl;
  ifc->close = pd_close;
  ifc->shutdown = pd_shutdown;
  ifc->getsockopt = pd_getsockopt;
  ifc->setsockopt = pd_setsockopt;
  ifc->poll = pd_poll;
  ifc->netdev_send = pd_netdev_send;
  ifc->netdev_receive = pd_netdev_recv;
  ifc->usleep = pd_usleep;
  ifc->gettimeofday = pd_gettimeofday;
  ifc->epoll_create = pd_epoll_create;
  ifc->epoll_ctl = pd_epoll_ctl;
  ifc->epoll_wait = pd_epoll_wait;
  ifc->pipe = pd_pipe;
  ifc->splice = pd_splice;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
