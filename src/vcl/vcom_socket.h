/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef included_vcom_socket_h
#define included_vcom_socket_h

#include <string.h>

#include <vcl/vcom_glibc_socket.h>
#include <vppinfra/types.h>
#include <sys/socket.h>

#define INVALID_SESSION_ID (~0)
#define INVALID_FD (~0)

#define INVALID_VEP_IDX INVALID_SESSION_ID
#define INVALID_EPFD INVALID_FD

typedef enum
{
  SOCKET_TYPE_UNBOUND = 0,
  SOCKET_TYPE_KERNEL_BOUND,
  SOCKET_TYPE_VPPCOM_BOUND
} vcom_socket_type_t;

typedef enum
{
  EPOLL_TYPE_UNBOUND = 0,
  EPOLL_TYPE_KERNEL_BOUND,
  EPOLL_TYPE_VPPCOM_BOUND
} vcom_epoll_type_t;

typedef enum
{
  FD_TYPE_INVALID = 0,
  FD_TYPE_KERNEL,
  FD_TYPE_EPOLL,
  FD_TYPE_VCOM_SOCKET,
  /* add new types here */
  /* FD_TYPE_MAX should be the last entry */
  FD_TYPE_MAX
} vcom_fd_type_t;

typedef struct
{
  /* file descriptor -
   * fd 0, 1, 2 have special meaning and are reserved,
   * -1 denote invalid fd */
  i32 fd;

  /* session id - -1 denote invalid sid */
  i32 sid;

  /* socket type */
  vcom_socket_type_t type;

  /* vcom socket attributes here */

} vcom_socket_t;

typedef struct
{
  /* epoll file descriptor -
   * epfd 0, 1, 2 have special meaning and are reserved,
   * -1 denote invalid epfd */
  i32 epfd;

  /* vep idx - -1 denote invalid vep_idx */
  i32 vep_idx;

  /* epoll type */
  vcom_epoll_type_t type;

  /* flags - 0 or EPOLL_CLOEXEC */
  i32 flags;

  /* vcom epoll attributes here */

  /*
   * 00. count of file descriptors currently registered
   *     on this epoll instance.
   * 01. number of file descriptors in the epoll set.
   * 02. EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL
   *     update the count.
   * 03. cached for frequent access.
   * */
  i32 count;
  i32 vcl_cnt;
  i32 libc_cnt;

  /* close( ) called on this epoll instance */
  /* 0 - close ( ) not called, 1 - close( ) called. */
  u32 close;

} vcom_epoll_t;

typedef struct
{
  /* "container" of this item */
  i32 epfd;

  /* fd - file descriptor information this item refers to */
  i32 fd;
  /* next and prev fd in the "epoll set" of epfd */
  i32 next_fd;
  i32 prev_fd;

  /* vcom fd type */
  vcom_fd_type_t type;

  /* interested events and the source fd */
  struct epoll_event event;

  /* ready events and the source fd */
  struct epoll_event revent;

  /* epitem attributes here */

} vcom_epitem_t;

typedef union vcom_epitem_key
{
  struct
  {
    i32 fd;
    i32 epfd;
  };
  i64 key;
} __EPOLL_PACKED vcom_epitem_key_t;

static inline char *
vcom_socket_type_str (vcom_socket_type_t t)
{
  switch (t)
    {
    case SOCKET_TYPE_UNBOUND:
      return "SOCKET_TYPE_UNBOUND";

    case SOCKET_TYPE_KERNEL_BOUND:
      return "SOCKET_TYPE_KERNEL_BOUND";

    case SOCKET_TYPE_VPPCOM_BOUND:
      return "SOCKET_TYPE_VPPCOM_BOUND";

    default:
      return "SOCKET_TYPE_UNKNOWN";
    }
}

static inline char *
vcom_socket_epoll_type_str (vcom_epoll_type_t t)
{
  switch (t)
    {
    case EPOLL_TYPE_UNBOUND:
      return "EPOLL_TYPE_UNBOUND";

    case EPOLL_TYPE_KERNEL_BOUND:
      return "EPOLL_TYPE_KERNEL_BOUND";

    case EPOLL_TYPE_VPPCOM_BOUND:
      return "EPOLL_TYPE_VPPCOM_BOUND";

    default:
      return "EPOLL_TYPE_UNKNOWN";
    }
}

static inline char *
vcom_socket_vcom_fd_type_str (vcom_fd_type_t t)
{
  switch (t)
    {
    case FD_TYPE_KERNEL:
      return "FD_TYPE_KERNEL";

    case FD_TYPE_EPOLL:
      return "FD_TYPE_EPOLL";

    case FD_TYPE_VCOM_SOCKET:
      return "FD_TYPE_VCOM_SOCKET";

    default:
      return "FD_TYPE_UNKNOWN";
    }
}

static inline int
vcom_socket_type_is_vppcom_bound (vcom_socket_type_t t)
{
  return t == SOCKET_TYPE_VPPCOM_BOUND;
}

static inline int
vcom_socket_epoll_type_is_vppcom_bound (vcom_epoll_type_t t)
{
  return t == EPOLL_TYPE_VPPCOM_BOUND;
}

static inline void
vsocket_init (vcom_socket_t * vsock)
{
  memset (vsock, 0, sizeof (*vsock));

  vsock->fd = INVALID_FD;
  vsock->sid = INVALID_SESSION_ID;
  vsock->type = SOCKET_TYPE_UNBOUND;
  /* vcom socket attributes init here */
}

static inline void
vepoll_init (vcom_epoll_t * vepoll)
{
  memset (vepoll, 0, sizeof (*vepoll));

  vepoll->epfd = INVALID_EPFD;
  vepoll->vep_idx = INVALID_VEP_IDX;
  vepoll->type = EPOLL_TYPE_UNBOUND;
  vepoll->flags = 0;

  vepoll->count = 0;
  vepoll->close = 0;
  /* vcom epoll attributes init here */
}

static inline void
vepitem_init (vcom_epitem_t * vepitem)
{
  struct epoll_event event = {.events = 0,.data.fd = INVALID_FD };

  memset (vepitem, 0, sizeof (*vepitem));

  vepitem->epfd = INVALID_EPFD;

  vepitem->fd = INVALID_FD;
  vepitem->next_fd = INVALID_FD;
  vepitem->prev_fd = INVALID_FD;

  vepitem->type = FD_TYPE_INVALID;

  vepitem->event = event;
  vepitem->revent = event;
  /* vepoll attributes init here */
}

static inline void
vepitemkey_init (vcom_epitem_key_t * epfdfd)
{
  memset (epfdfd, 0, sizeof (*epfdfd));

  epfdfd->epfd = INVALID_EPFD;
  epfdfd->fd = INVALID_FD;
}

static inline void
vsocket_set (vcom_socket_t * vsock, i32 fd, i32 sid, vcom_socket_type_t type)
{
  vsock->fd = fd;
  vsock->sid = sid;
  vsock->type = type;
  /* vcom socket attributes set here */
}

static inline void
vepoll_set (vcom_epoll_t * vepoll,
	    i32 epfd, i32 vep_idx,
	    vcom_epoll_type_t type, i32 flags, i32 count, u32 close)
{
  vepoll->epfd = epfd;
  vepoll->vep_idx = vep_idx;
  vepoll->type = type;
  vepoll->flags = flags;

  vepoll->count = count;
  vepoll->close = close;
  /* vcom epoll attributes set here */
}

static inline void
vepitem_set (vcom_epitem_t * vepitem,
	     i32 epfd,
	     i32 fd, i32 next_fd, i32 prev_fd,
	     vcom_fd_type_t type,
	     struct epoll_event event, struct epoll_event revent)
{
  vepitem->epfd = epfd;

  vepitem->fd = fd;
  vepitem->next_fd = next_fd;
  vepitem->prev_fd = prev_fd;

  vepitem->type = type;

  vepitem->event = event;
  vepitem->revent = revent;
  /* vcom epitem attributes set here */
}

static inline void
vepitemkey_set (vcom_epitem_key_t * epfdfd, i32 epfd, i32 fd)
{
  epfdfd->epfd = epfd;
  epfdfd->fd = fd;
}

static inline int
vsocket_is_vppcom_bound (vcom_socket_t * vsock)
{
  return vcom_socket_type_is_vppcom_bound (vsock->type);
}

static inline int
vepoll_is_vppcom_bound (vcom_epoll_t * vepoll)
{
  return vcom_socket_epoll_type_is_vppcom_bound (vepoll->type);
}

int vcom_socket_main_init (void);

void vcom_socket_main_destroy (void);

void vcom_socket_main_show (void);

int vcom_socket_is_vcom_fd (int fd);

int vcom_socket_is_vcom_epfd (int epfd);

int vcom_socket_close (int __fd);

ssize_t vcom_socket_read (int __fd, void *__buf, size_t __nbytes);

ssize_t vcom_socket_readv (int __fd, const struct iovec *__iov, int __iovcnt);

ssize_t vcom_socket_write (int __fd, const void *__buf, size_t __n);

ssize_t vcom_socket_writev (int __fd, const struct iovec *__iov,
			    int __iovcnt);

int vcom_socket_fcntl_va (int __fd, int __cmd, va_list __ap);

int vcom_socket_ioctl_va (int __fd, unsigned long int __cmd, va_list __ap);

int
vcom_socket_select (int vcom_nfds, fd_set * __restrict vcom_readfds,
		    fd_set * __restrict vcom_writefds,
		    fd_set * __restrict vcom_exceptfds,
		    struct timeval *__restrict timeout);


int vcom_socket_socket (int __domain, int __type, int __protocol);

int
vcom_socket_socketpair (int __domain, int __type, int __protocol,
			int __fds[2]);

int vcom_socket_bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

int
vcom_socket_getsockname (int __fd, __SOCKADDR_ARG __addr,
			 socklen_t * __restrict __len);

int
vcom_socket_connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

int
vcom_socket_getpeername (int __fd, __SOCKADDR_ARG __addr,
			 socklen_t * __restrict __len);

ssize_t
vcom_socket_send (int __fd, const void *__buf, size_t __n, int __flags);

ssize_t vcom_socket_recv (int __fd, void *__buf, size_t __n, int __flags);

/*
 * RETURN   1 if __fd is (SOCK_STREAM, SOCK_SEQPACKET),
 * 0 otherwise
 * */
int vcom_socket_is_connection_mode_socket (int __fd);

ssize_t
vcom_socket_sendto (int __fd, const void *__buf, size_t __n,
		    int __flags, __CONST_SOCKADDR_ARG __addr,
		    socklen_t __addr_len);

ssize_t
vcom_socket_recvfrom (int __fd, void *__restrict __buf, size_t __n,
		      int __flags, __SOCKADDR_ARG __addr,
		      socklen_t * __restrict __addr_len);

ssize_t
vcom_socket_sendmsg (int __fd, const struct msghdr *__message, int __flags);

#ifdef __USE_GNU
int
vcom_socket_sendmmsg (int __fd, struct mmsghdr *__vmessages,
		      unsigned int __vlen, int __flags);
#endif

ssize_t vcom_socket_recvmsg (int __fd, struct msghdr *__message, int __flags);

#ifdef __USE_GNU
int
vcom_socket_recvmmsg (int __fd, struct mmsghdr *__vmessages,
		      unsigned int __vlen, int __flags,
		      struct timespec *__tmo);
#endif

int
vcom_socket_getsockopt (int __fd, int __level, int __optname,
			void *__restrict __optval,
			socklen_t * __restrict __optlen);

int
vcom_socket_setsockopt (int __fd, int __level, int __optname,
			const void *__optval, socklen_t __optlen);

int vcom_socket_listen (int __fd, int __n);

int
vcom_socket_accept (int __fd, __SOCKADDR_ARG __addr,
		    socklen_t * __restrict __addr_len);

int
vcom_socket_accept4 (int __fd, __SOCKADDR_ARG __addr,
		     socklen_t * __restrict __addr_len, int __flags);

int vcom_socket_shutdown (int __fd, int __how);

int vcom_socket_epoll_create1 (int __flags);

int
vcom_socket_epoll_ctl (int __epfd, int __op, int __fd,
		       struct epoll_event *__event);

int
vcom_socket_epoll_pwait (int __epfd, struct epoll_event *__events,
			 int __maxevents, int __timeout,
			 const __sigset_t * __ss);

/*
 * handle only vcom fds
 */
int vcom_socket_poll (struct pollfd *__fds, nfds_t __nfds, int __timeout);

#ifdef __USE_GNU
int
vcom_socket_ppoll (struct pollfd *__fds, nfds_t __nfds,
		   const struct timespec *__timeout, const __sigset_t * __ss);
#endif

#endif /* included_vcom_socket_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
