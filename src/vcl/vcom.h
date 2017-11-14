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

#ifndef included_vcom_h
#define included_vcom_h

#if (CLIB_DEBUG > 0)
/* Set VCOM_DEBUG 2 for connection debug, 3 for read/write debug output */
#define VCOM_DEBUG 1
#else
#define VCOM_DEBUG 0
#endif

#include <vppinfra/error.h>
#include <vppinfra/types.h>
#include <vcl/vcom_glibc_socket.h>

#define MAX_VCOM_APP_NAME  256

/* Returns 0 on success or -1 on error. */
extern int vcom_set_app_name (char *__app_name);

/*
 *
 * File descriptor based APIs
 *
 */

/*
 * vpp implementation of glibc APIs from <unistd.h>
 */
extern int vcom_close (int __fd);

extern ssize_t __wur vcom_read (int __fd, void *__buf, size_t __nbytes);

extern ssize_t __wur vcom_write (int __fd, const void *__buf, size_t __n);

extern ssize_t __wur vcom_readv (int __fd, const struct iovec *__iov,
				 int __iovcnt);

extern ssize_t __wur vcom_writev (int __fd, const struct iovec *__iov,
				  int __iovcnt);

/*
 * vpp implementation of glibc APIs from <fcntl.h>
 */
extern int vcom_fcntl (int __fd, int __cmd, ...);

/*
 * VPP implementation of glibc APIs ioctl
 */
extern int vcom_ioctl (int __fd, unsigned long int __cmd, ...);

/*
 * vpp implementation of glibc APIs from <sys/select.h>
 */
extern int
vcom_select (int __nfds, fd_set * __restrict __readfds,
	     fd_set * __restrict __writefds,
	     fd_set * __restrict __exceptfds,
	     struct timeval *__restrict __timeout);

#ifdef __USE_XOPEN2K
extern int
vcom_pselect (int __nfds, fd_set * __restrict __readfds,
	      fd_set * __restrict __writefds,
	      fd_set * __restrict __exceptfds,
	      const struct timespec *__restrict __timeout,
	      const __sigset_t * __restrict __sigmask);
#endif

/*
 * vpp implementation of glibc APIs from <sys/socket.h>
 */
extern int __THROW vcom_socket (int __domain, int __type, int __protocol);

/* On Linux, the only supported domain for this call is AF_UNIX
* (or synonymously, AF_LOCAL). Most implementations have the
* same restriction.
* vpp does not implement AF_UNIX domain in this release.
* */
extern int __THROW
vcom_socketpair (int __domain, int __type, int __protocol, int __fds[2]);

extern int __THROW
vcom_bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

extern int __THROW
vcom_getsockname (int __fd, __SOCKADDR_ARG __addr,
		  socklen_t * __restrict __len);

extern int
vcom_connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

extern int __THROW
vcom_getpeername (int __fd, __SOCKADDR_ARG __addr,
		  socklen_t * __restrict __len);

extern ssize_t
vcom_sendfile (int __out_fd, int __in_fd, off_t * __offset, int __len);

extern ssize_t vcom_recv (int __fd, void *__buf, size_t __n, int __flags);

extern ssize_t
vcom_sendto (int __fd, const void *__buf, size_t __n,
	     int __flags, __CONST_SOCKADDR_ARG __addr, socklen_t __addr_len);

extern ssize_t
vcom_recvfrom (int __fd, void *__restrict __buf,
	       size_t __n, int __flags,
	       __SOCKADDR_ARG __addr, socklen_t * __restrict __addr_len);

extern ssize_t
vcom_sendmsg (int __fd, const struct msghdr *__message, int __flags);

#ifdef __USE_GNU
extern int
sendmmsg (int __fd, struct mmsghdr *__vmessages,
	  unsigned int __vlen, int __flags);
#endif

extern ssize_t vcom_recvmsg (int __fd, struct msghdr *__message, int __flags);

#ifdef __USE_GNU
extern int
vcom_recvmmsg (int __fd, struct mmsghdr *__vmessages,
	       unsigned int __vlen, int __flags, struct timespec *__tmo);
#endif

extern int __THROW
vcom_getsockopt (int __fd, int __level, int __optname,
		 void *__restrict __optval, socklen_t * __restrict __optlen);

extern int __THROW
vcom_setsockopt (int __fd, int __level, int __optname,
		 const void *__optval, socklen_t __optlen);

extern int __THROW vcom_listen (int __fd, int __n);

extern int
vcom_accept (int __fd, __SOCKADDR_ARG __addr,
	     socklen_t * __restrict __addr_len);

#ifdef __USE_GNU
/*
 * Similar to 'accept' but takes an additional parameter to specify
 * flags.
 * */
/* TBD: implemented later */
extern int
vcom_accept4 (int __fd, __SOCKADDR_ARG __addr,
	      socklen_t * __restrict __addr_len, int __flags);
#endif

extern int __THROW vcom_shutdown (int __fd, int __how);

extern int __THROW vcom_epoll_create (int __size);

extern int __THROW vcom_epoll_create1 (int __flags);

extern int __THROW
vcom_epoll_ctl (int __epfd, int __op, int __fd, struct epoll_event *__event);

extern int
vcom_epoll_wait (int __epfd, struct epoll_event *__events,
		 int __maxevents, int __timeout);

extern int
vcom_epoll_pwait (int __epfd, struct epoll_event *__events,
		  int __maxevents, int __timeout, const __sigset_t * __ss);

/*
 * NOTE: observed __nfds is less than 128 from kubecon strace files
 * for the POC, it's fair to assume that nfds is less than 1024.
 * TBD: make it thread safe and design to scale.
 * */
#define MAX_POLL_NFDS_DEFAULT   1024
extern int vcom_poll (struct pollfd *__fds, nfds_t __nfds, int __timeout);

#ifdef __USE_GNU
extern int
vcom_ppoll (struct pollfd *__fds, nfds_t __nfds,
	    const struct timespec *__timeout, const __sigset_t * __ss);
#endif


#endif /* included_vcom_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
