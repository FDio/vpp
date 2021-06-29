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

#include "packetdrill.h"

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

static uint64_t
now_usecs (void)
{
  struct timeval tv;

  gettimeofday (&tv, NULL);
  return ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
}

void
pd_free (void *userdata)
{
  if (packet_fd > 0)
    close (packet_fd);
  return;
}

int
pd_socket (void *userdata, int domain, int type, int protocol)
{
  return socket (domain, type, protocol);
}

int
pd_bind (void *userdata, int sockfd, const struct sockaddr *addr,
	 socklen_t addrlen)
{
  return bind (sockfd, addr, addrlen);
}

int
pd_listen (void *userdata, int sockfd, int backlog)
{
  return listen (sockfd, backlog);
}

int
pd_accept (void *userdata, int sockfd, struct sockaddr *addr,
	   socklen_t *addrlen)
{
  return accept (sockfd, addr, addrlen);
}

int
pd_connect (void *userdata, int sockfd, const struct sockaddr *addr,
	    socklen_t addrlen)
{
  return connect (sockfd, addr, addrlen);
}
ssize_t
pd_read (void *userdata, int fd, void *buf, size_t count)
{
  return read (fd, buf, count);
}
ssize_t
pd_readv (void *userdata, int fd, const struct iovec *iov, int iovcnt)
{
  return readv (fd, iov, iovcnt);
}
ssize_t
pd_recv (void *userdata, int sockfd, void *buf, size_t len, int flags)
{
  return recv (sockfd, buf, len, flags);
}
ssize_t
pd_recvfrom (void *userdata, int sockfd, void *buf, size_t len, int flags,
	     struct sockaddr *src_addr, socklen_t *addrlen)
{
  return recvfrom (sockfd, buf, len, flags, src_addr, addrlen);
}
ssize_t
pd_recvmsg (void *userdata, int sockfd, struct msghdr *msg, int flags)
{
  return recvmsg (sockfd, msg, flags);
}
ssize_t
pd_write (void *userdata, int fd, const void *buf, size_t count)
{
  return write (fd, buf, count);
}
ssize_t
pd_writev (void *userdata, int fd, const struct iovec *iov, int iovcnt)
{
  return writev (fd, iov, iovcnt);
}
ssize_t
pd_send (void *userdata, int sockfd, const void *buf, size_t len, int flags)
{
  return send (sockfd, buf, len, flags);
}
ssize_t
pd_sendto (void *userdata, int sockfd, const void *buf, size_t len, int flags,
	   const struct sockaddr *dest_addr, socklen_t addrlen)
{
  return sendto (sockfd, buf, len, flags, dest_addr, addrlen);
}
ssize_t
pd_sendmsg (void *userdata, int sockfd, const struct msghdr *msg, int flags)
{
  return sendmsg (sockfd, msg, flags);
}
int
pd_fcntl (void *userdata, int fd, int cmd, ...)
{
  void *arg;
  va_list ap;

  va_start (ap, cmd);
  arg = va_arg (ap, void *);
  va_end (ap);

  return fcntl (fd, cmd, arg);
}
int
pd_ioctl (void *userdata, int fd, unsigned long request, ...)
{
  void *arg;
  va_list ap;

  va_start (ap, request);
  arg = va_arg (ap, void *);
  va_end (ap);

  return ioctl (fd, request, arg);
}
int
pd_close (void *userdata, int fd)
{
  return close (fd);
}
int
pd_shutdown (void *userdata, int sockfd, int how)
{
  return shutdown (sockfd, how);
}
int
pd_getsockopt (void *userdata, int sockfd, int level, int optname,
	       void *optval, socklen_t *optlen)
{
  return getsockopt (sockfd, level, optname, optval, optlen);
}
int
pd_setsockopt (void *userdata, int sockfd, int level, int optname,
	       const void *optval, socklen_t optlen)
{
  return setsockopt (sockfd, level, optname, optval, optlen);
}
int
pd_poll (void *userdata, struct pollfd *fds, nfds_t nfds, int timeout)
{
  return poll (fds, nfds, timeout);
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
/* Sniff the next packet leaving the TCP stack.
 * Put packet data in @buf.  @count is passed in as the buffer size.
 * The actual number of bytes received should be put in @count.
 * Set @count to 0 if received nothing.
 * Set @time_usecs to the receive timestamp.
 * Return 0 on success or -1 on error. */
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
int
pd_epoll_create (void *userdata, int size)
{
  return epoll_create (size);
}
int
pd_epoll_ctl (void *userdata, int epfd, int op, int fd,
	      struct epoll_event *event)
{
  return epoll_ctl (epfd, op, fd, event);
}
int
pd_epoll_wait (void *userdata, int epfd, struct epoll_event *events,
	       int maxevents, int timeout)
{
  return epoll_wait (epfd, events, maxevents, timeout);
}
int
pd_pipe (void *userdata, int pipefd[2])
{
  return pipe (pipefd);
}
int
pd_splice (void *userdata, int fd_in, loff_t *off_in, int fd_out,
	   loff_t *off_out, size_t len, unsigned int flags)
{
  fprintf (stdout, "not support splice");
  return -1;
}

void
packetdrill_interface_init (const char *flags,
			    struct packetdrill_interface *ifc)
{

  packet_socket_init ();
  ether_head_init ();

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
