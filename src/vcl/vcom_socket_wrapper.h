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

/*
 * Copyright (c) 2005-2008 Jelmer Vernooij <jelmer@samba.org>
 * Copyright (C) 2006-2014 Stefan Metzmacher <metze@samba.org>
 * Copyright (C) 2013-2014 Andreas Schneider <asn@samba.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
   Socket wrapper library. Passes all socket communication over
   unix domain sockets if the environment variable SOCKET_WRAPPER_DIR
   is set.
*/

#ifndef included_vcom_socket_wrapper_h
#define included_vcom_socket_wrapper_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <vcl/vcom.h>


/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

#define HAVE_CONSTRUCTOR_ATTRIBUTE
#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE __attribute__ ((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */

#define HAVE_DESTRUCTOR_ATTRIBUTE
#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif

#define HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#ifdef HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE __attribute__((no_sanitize_address))
#else
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
#endif

/*
 * IMPORTANT
 *
 * Functions especially from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
int libc_accept4 (int sockfd, struct sockaddr *addr, socklen_t * addrlen,
		  int flags);

int libc_accept (int sockfd, struct sockaddr *addr, socklen_t * addrlen);

int libc_bind (int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int libc_close (int fd);

int libc_connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#if 0
/* TBD: dup and dup2 to be implemented later */
int libc_dup (int fd);

int libc_dup2 (int oldfd, int newfd);
#endif

#ifdef HAVE_EVENTFD
int libc_eventfd (int count, int flags);
#endif

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE int
libc_vfcntl (int fd, int cmd, va_list ap);

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE int
libc_vioctl (int fd, int cmd, va_list ap);

int libc_getpeername (int sockfd, struct sockaddr *addr, socklen_t * addrlen);

int libc_getsockname (int sockfd, struct sockaddr *addr, socklen_t * addrlen);

int
libc_getsockopt (int sockfd,
		 int level, int optname, void *optval, socklen_t * optlen);

int libc_listen (int sockfd, int backlog);

int libc_read (int fd, void *buf, size_t count);

ssize_t libc_readv (int fd, const struct iovec *iov, int iovcnt);

int libc_recv (int sockfd, void *buf, size_t len, int flags);

int
libc_recvfrom (int sockfd,
	       void *buf,
	       size_t len,
	       int flags, struct sockaddr *src_addr, socklen_t * addrlen);

int libc_recvmsg (int sockfd, struct msghdr *msg, int flags);

int libc_send (int sockfd, const void *buf, size_t len, int flags);

ssize_t libc_sendfile (int out_fd, int in_fd, off_t * offset, size_t len);

int libc_sendmsg (int sockfd, const struct msghdr *msg, int flags);

int
libc_sendto (int sockfd,
	     const void *buf,
	     size_t len,
	     int flags, const struct sockaddr *dst_addr, socklen_t addrlen);

int
libc_setsockopt (int sockfd,
		 int level, int optname, const void *optval,
		 socklen_t optlen);

int libc_socket (int domain, int type, int protocol);

int libc_socketpair (int domain, int type, int protocol, int sv[2]);

ssize_t libc_write (int fd, const void *buf, size_t count);

ssize_t libc_writev (int fd, const struct iovec *iov, int iovcnt);

int libc_shutdown (int fd, int how);

int
libc_select (int __nfds, fd_set * __restrict __readfds,
	     fd_set * __restrict __writefds,
	     fd_set * __restrict __exceptfds,
	     struct timeval *__restrict __timeout);

#ifdef __USE_XOPEN2K
int
libc_pselect (int __nfds, fd_set * __restrict __readfds,
	      fd_set * __restrict __writefds,
	      fd_set * __restrict __exceptfds,
	      const struct timespec *__restrict __timeout,
	      const __sigset_t * __restrict __sigmask);
#endif

int libc_epoll_create (int __size);

int libc_epoll_create1 (int __flags);

int libc_epoll_ctl (int __epfd, int __op, int __fd,
		    struct epoll_event *__event);

int libc_epoll_wait (int __epfd, struct epoll_event *__events,
		     int __maxevents, int __timeout);

int libc_epoll_pwait (int __epfd, struct epoll_event *__events,
		      int __maxevents, int __timeout,
		      const __sigset_t * __ss);

int libc_poll (struct pollfd *__fds, nfds_t __nfds, int __timeout);

#ifdef __USE_GNU
int libc_ppoll (struct pollfd *__fds, nfds_t __nfds,
		const struct timespec *__timeout, const __sigset_t * __ss);
#endif

void swrap_constructor (void);

void swrap_destructor (void);

#endif /* included_vcom_socket_wrapper_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
