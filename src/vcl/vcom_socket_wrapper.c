/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <signal.h>
#include <dlfcn.h>

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>

#include <vcl/vcom_socket_wrapper.h>


enum swrap_dbglvl_e
{
  SWRAP_LOG_ERROR = 0,
  SWRAP_LOG_WARN,
  SWRAP_LOG_DEBUG,
  SWRAP_LOG_TRACE
};


/* Macros for accessing mutexes */
#define SWRAP_LOCK(m) do { \
        pthread_mutex_lock(&(m ## _mutex)); \
} while(0)

#define SWRAP_UNLOCK(m) do { \
        pthread_mutex_unlock(&(m ## _mutex)); \
} while(0)

/* Add new global locks here please */
#define SWRAP_LOCK_ALL \
        SWRAP_LOCK(libc_symbol_binding); \

#define SWRAP_UNLOCK_ALL \
        SWRAP_UNLOCK(libc_symbol_binding); \



/* The mutex for accessing the global libc.symbols */
static pthread_mutex_t libc_symbol_binding_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Function prototypes */

#ifdef NDEBUG
#define SWRAP_LOG(...)
#else
static unsigned int swrap_log_lvl = SWRAP_LOG_WARN;

static void
swrap_log (enum swrap_dbglvl_e dbglvl, const char *func,
	   const char *format, ...)
PRINTF_ATTRIBUTE (3, 4);
#define SWRAP_LOG(dbglvl, ...) swrap_log((dbglvl), __func__, __VA_ARGS__)

     static void
       swrap_log (enum swrap_dbglvl_e dbglvl,
		  const char *func, const char *format, ...)
{
  char buffer[1024];
  va_list va;

  va_start (va, format);
  vsnprintf (buffer, sizeof (buffer), format, va);
  va_end (va);

  if (dbglvl <= swrap_log_lvl)
    {
      switch (dbglvl)
	{
	case SWRAP_LOG_ERROR:
	  fprintf (stderr,
		   "SWRAP_ERROR(%d) - %s: %s\n",
		   (int) getpid (), func, buffer);
	  break;
	case SWRAP_LOG_WARN:
	  fprintf (stderr,
		   "SWRAP_WARN(%d) - %s: %s\n",
		   (int) getpid (), func, buffer);
	  break;
	case SWRAP_LOG_DEBUG:
	  fprintf (stderr,
		   "SWRAP_DEBUG(%d) - %s: %s\n",
		   (int) getpid (), func, buffer);
	  break;
	case SWRAP_LOG_TRACE:
	  fprintf (stderr,
		   "SWRAP_TRACE(%d) - %s: %s\n",
		   (int) getpid (), func, buffer);
	  break;
	}
    }
}
#endif


/*********************************************************
 * SWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

typedef int (*__libc_accept4) (int sockfd,
			       struct sockaddr * addr,
			       socklen_t * addrlen, int flags);
typedef int (*__libc_accept) (int sockfd,
			      struct sockaddr * addr, socklen_t * addrlen);
typedef int (*__libc_bind) (int sockfd,
			    const struct sockaddr * addr, socklen_t addrlen);
typedef int (*__libc_close) (int fd);
typedef int (*__libc_connect) (int sockfd,
			       const struct sockaddr * addr,
			       socklen_t addrlen);

#if 0
/* TBD: dup and dup2 to be implemented later */
typedef int (*__libc_dup) (int fd);
typedef int (*__libc_dup2) (int oldfd, int newfd);
#endif

typedef int (*__libc_fcntl) (int fd, int cmd, ...);
typedef FILE *(*__libc_fopen) (const char *name, const char *mode);
#ifdef HAVE_FOPEN64
typedef FILE *(*__libc_fopen64) (const char *name, const char *mode);
#endif
#ifdef HAVE_EVENTFD
typedef int (*__libc_eventfd) (int count, int flags);
#endif
typedef int (*__libc_getpeername) (int sockfd,
				   struct sockaddr * addr,
				   socklen_t * addrlen);
typedef int (*__libc_getsockname) (int sockfd,
				   struct sockaddr * addr,
				   socklen_t * addrlen);
typedef int (*__libc_getsockopt) (int sockfd,
				  int level,
				  int optname,
				  void *optval, socklen_t * optlen);
typedef int (*__libc_ioctl) (int d, unsigned long int request, ...);
typedef int (*__libc_listen) (int sockfd, int backlog);
typedef int (*__libc_open) (const char *pathname, int flags, mode_t mode);
#ifdef HAVE_OPEN64
typedef int (*__libc_open64) (const char *pathname, int flags, mode_t mode);
#endif /* HAVE_OPEN64 */
typedef int (*__libc_openat) (int dirfd, const char *path, int flags, ...);
typedef int (*__libc_pipe) (int pipefd[2]);
typedef int (*__libc_read) (int fd, void *buf, size_t count);
typedef ssize_t (*__libc_readv) (int fd, const struct iovec * iov,
				 int iovcnt);
typedef int (*__libc_recv) (int sockfd, void *buf, size_t len, int flags);
typedef int (*__libc_recvfrom) (int sockfd,
				void *buf,
				size_t len,
				int flags,
				struct sockaddr * src_addr,
				socklen_t * addrlen);
typedef int (*__libc_recvmsg) (int sockfd, const struct msghdr * msg,
			       int flags);
typedef int (*__libc_send) (int sockfd, const void *buf, size_t len,
			    int flags);
typedef ssize_t (*__libc_sendfile) (int out_fd, int in_fd, off_t * offset,
				    size_t len);
typedef int (*__libc_sendmsg) (int sockfd, const struct msghdr * msg,
			       int flags);
typedef int (*__libc_sendto) (int sockfd, const void *buf, size_t len,
			      int flags, const struct sockaddr * dst_addr,
			      socklen_t addrlen);
typedef int (*__libc_setsockopt) (int sockfd, int level, int optname,
				  const void *optval, socklen_t optlen);
#ifdef HAVE_SIGNALFD
typedef int (*__libc_signalfd) (int fd, const sigset_t * mask, int flags);
#endif
typedef int (*__libc_socket) (int domain, int type, int protocol);
typedef int (*__libc_socketpair) (int domain, int type, int protocol,
				  int sv[2]);
#ifdef HAVE_TIMERFD_CREATE
typedef int (*__libc_timerfd_create) (int clockid, int flags);
#endif
typedef ssize_t (*__libc_write) (int fd, const void *buf, size_t count);
typedef ssize_t (*__libc_writev) (int fd, const struct iovec * iov,
				  int iovcnt);

typedef int (*__libc_shutdown) (int fd, int how);

typedef int (*__libc_select) (int __nfds, fd_set * __restrict __readfds,
			      fd_set * __restrict __writefds,
			      fd_set * __restrict __exceptfds,
			      struct timeval * __restrict __timeout);

#ifdef __USE_XOPEN2K
typedef int (*__libc_pselect) (int __nfds, fd_set * __restrict __readfds,
			       fd_set * __restrict __writefds,
			       fd_set * __restrict __exceptfds,
			       const struct timespec * __restrict __timeout,
			       const __sigset_t * __restrict __sigmask);
#endif

typedef int (*__libc_epoll_create) (int __size);

typedef int (*__libc_epoll_create1) (int __flags);

typedef int (*__libc_epoll_ctl) (int __epfd, int __op, int __fd,
				 struct epoll_event * __event);

typedef int (*__libc_epoll_wait) (int __epfd, struct epoll_event * __events,
				  int __maxevents, int __timeout);

typedef int (*__libc_epoll_pwait) (int __epfd, struct epoll_event * __events,
				   int __maxevents, int __timeout,
				   const __sigset_t * __ss);

typedef int (*__libc_poll) (struct pollfd * __fds, nfds_t __nfds,
			    int __timeout);

#ifdef __USE_GNU
typedef int (*__libc_ppoll) (struct pollfd * __fds, nfds_t __nfds,
			     const struct timespec * __timeout,
			     const __sigset_t * __ss);
#endif


#define SWRAP_SYMBOL_ENTRY(i) \
        union { \
                __libc_##i f; \
                void *obj; \
        } _libc_##i

struct swrap_libc_symbols
{
  SWRAP_SYMBOL_ENTRY (accept4);
  SWRAP_SYMBOL_ENTRY (accept);
  SWRAP_SYMBOL_ENTRY (bind);
  SWRAP_SYMBOL_ENTRY (close);
  SWRAP_SYMBOL_ENTRY (connect);
#if 0
  /* TBD: dup and dup2 to be implemented later */
  SWRAP_SYMBOL_ENTRY (dup);
  SWRAP_SYMBOL_ENTRY (dup2);
#endif
  SWRAP_SYMBOL_ENTRY (fcntl);
  SWRAP_SYMBOL_ENTRY (fopen);
#ifdef HAVE_FOPEN64
  SWRAP_SYMBOL_ENTRY (fopen64);
#endif
#ifdef HAVE_EVENTFD
  SWRAP_SYMBOL_ENTRY (eventfd);
#endif
  SWRAP_SYMBOL_ENTRY (getpeername);
  SWRAP_SYMBOL_ENTRY (getsockname);
  SWRAP_SYMBOL_ENTRY (getsockopt);
  SWRAP_SYMBOL_ENTRY (ioctl);
  SWRAP_SYMBOL_ENTRY (listen);
  SWRAP_SYMBOL_ENTRY (open);
#ifdef HAVE_OPEN64
  SWRAP_SYMBOL_ENTRY (open64);
#endif
  SWRAP_SYMBOL_ENTRY (openat);
  SWRAP_SYMBOL_ENTRY (pipe);
  SWRAP_SYMBOL_ENTRY (read);
  SWRAP_SYMBOL_ENTRY (readv);
  SWRAP_SYMBOL_ENTRY (recv);
  SWRAP_SYMBOL_ENTRY (recvfrom);
  SWRAP_SYMBOL_ENTRY (recvmsg);
  SWRAP_SYMBOL_ENTRY (send);
  SWRAP_SYMBOL_ENTRY (sendfile);
  SWRAP_SYMBOL_ENTRY (sendmsg);
  SWRAP_SYMBOL_ENTRY (sendto);
  SWRAP_SYMBOL_ENTRY (setsockopt);
#ifdef HAVE_SIGNALFD
  SWRAP_SYMBOL_ENTRY (signalfd);
#endif
  SWRAP_SYMBOL_ENTRY (socket);
  SWRAP_SYMBOL_ENTRY (socketpair);
#ifdef HAVE_TIMERFD_CREATE
  SWRAP_SYMBOL_ENTRY (timerfd_create);
#endif
  SWRAP_SYMBOL_ENTRY (write);
  SWRAP_SYMBOL_ENTRY (writev);

  SWRAP_SYMBOL_ENTRY (shutdown);
  SWRAP_SYMBOL_ENTRY (select);
#ifdef __USE_XOPEN2K
  SWRAP_SYMBOL_ENTRY (pselect);
#endif
  SWRAP_SYMBOL_ENTRY (epoll_create);
  SWRAP_SYMBOL_ENTRY (epoll_create1);
  SWRAP_SYMBOL_ENTRY (epoll_ctl);
  SWRAP_SYMBOL_ENTRY (epoll_wait);
  SWRAP_SYMBOL_ENTRY (epoll_pwait);
  SWRAP_SYMBOL_ENTRY (poll);
#ifdef __USE_GNU
  SWRAP_SYMBOL_ENTRY (ppoll);
#endif
};

struct swrap
{
  struct
  {
    void *handle;
    void *socket_handle;
    struct swrap_libc_symbols symbols;
  } libc;
};

static struct swrap swrap;

#define LIBC_NAME "libc.so"

enum swrap_lib
{
  SWRAP_LIBC,
};

#ifndef NDEBUG
static const char *
swrap_str_lib (enum swrap_lib lib)
{
  switch (lib)
    {
    case SWRAP_LIBC:
      return "libc";
    }

  /* Compiler would warn us about unhandled enum value if we get here */
  return "unknown";
}
#endif

static void *
swrap_load_lib_handle (enum swrap_lib lib)
{
  int flags = RTLD_LAZY;
  void *handle = NULL;
  int i;

#ifdef RTLD_DEEPBIND
  flags |= RTLD_DEEPBIND;
#endif

  switch (lib)
    {
    case SWRAP_LIBC:
      handle = swrap.libc.handle;
#ifdef LIBC_SO
      if (handle == NULL)
	{
	  handle = dlopen (LIBC_SO, flags);

	  swrap.libc.handle = handle;
	}
#endif
      if (handle == NULL)
	{
	  for (i = 10; i >= 0; i--)
	    {
	      char soname[256] = { 0 };

	      snprintf (soname, sizeof (soname), "libc.so.%d", i);
	      handle = dlopen (soname, flags);
	      if (handle != NULL)
		{
		  break;
		}
	    }

	  swrap.libc.handle = handle;
	}
      break;
    }

  if (handle == NULL)
    {
      SWRAP_LOG (SWRAP_LOG_ERROR,
		 "Failed to dlopen library: %s\n", dlerror ());
      exit (-1);
    }

  return handle;
}

static void *
_swrap_bind_symbol (enum swrap_lib lib, const char *fn_name)
{
  void *handle;
  void *func;

  handle = swrap_load_lib_handle (lib);

  func = dlsym (handle, fn_name);
  if (func == NULL)
    {
      SWRAP_LOG (SWRAP_LOG_ERROR,
		 "Failed to find %s: %s\n", fn_name, dlerror ());
      exit (-1);
    }

  SWRAP_LOG (SWRAP_LOG_TRACE,
	     "Loaded %s from %s", fn_name, swrap_str_lib (lib));

  return func;
}

#define swrap_bind_symbol_libc(sym_name) \
        SWRAP_LOCK(libc_symbol_binding); \
        if (swrap.libc.symbols._libc_##sym_name.obj == NULL) { \
                swrap.libc.symbols._libc_##sym_name.obj = \
                        _swrap_bind_symbol(SWRAP_LIBC, #sym_name); \
        } \
        SWRAP_UNLOCK(libc_symbol_binding)

/*
 * IMPORTANT
 *
 * Functions especially from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
int
libc_accept4 (int sockfd,
	      struct sockaddr *addr, socklen_t * addrlen, int flags)
{
  swrap_bind_symbol_libc (accept4);

  return swrap.libc.symbols._libc_accept4.f (sockfd, addr, addrlen, flags);
}

int
libc_accept (int sockfd, struct sockaddr *addr, socklen_t * addrlen)
{
  swrap_bind_symbol_libc (accept);

  return swrap.libc.symbols._libc_accept.f (sockfd, addr, addrlen);
}

int
libc_bind (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  swrap_bind_symbol_libc (bind);

  return swrap.libc.symbols._libc_bind.f (sockfd, addr, addrlen);
}

int
libc_close (int fd)
{
  swrap_bind_symbol_libc (close);

  return swrap.libc.symbols._libc_close.f (fd);
}

int
libc_connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  swrap_bind_symbol_libc (connect);

  return swrap.libc.symbols._libc_connect.f (sockfd, addr, addrlen);
}

#if 0
/* TBD: dup and dup2 to be implemented later */
int
libc_dup (int fd)
{
  swrap_bind_symbol_libc (dup);

  return swrap.libc.symbols._libc_dup.f (fd);
}

int
libc_dup2 (int oldfd, int newfd)
{
  swrap_bind_symbol_libc (dup2);

  return swrap.libc.symbols._libc_dup2.f (oldfd, newfd);
}
#endif

#ifdef HAVE_EVENTFD
int
libc_eventfd (int count, int flags)
{
  swrap_bind_symbol_libc (eventfd);

  return swrap.libc.symbols._libc_eventfd.f (count, flags);
}
#endif

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE int
libc_vfcntl (int fd, int cmd, va_list ap)
{
  long int args[4];
  int rc;
  int i;

  swrap_bind_symbol_libc (fcntl);

  for (i = 0; i < 4; i++)
    {
      args[i] = va_arg (ap, long int);
    }

  rc = swrap.libc.symbols._libc_fcntl.f (fd,
					 cmd,
					 args[0], args[1], args[2], args[3]);

  return rc;
}

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE int
libc_vioctl (int fd, int cmd, va_list ap)
{
  long int args[4];
  int rc;
  int i;

  swrap_bind_symbol_libc (ioctl);

  for (i = 0; i < 4; i++)
    {
      args[i] = va_arg (ap, long int);
    }

  rc = swrap.libc.symbols._libc_ioctl.f (fd,
					 cmd,
					 args[0], args[1], args[2], args[3]);

  return rc;
}

int
libc_getpeername (int sockfd, struct sockaddr *addr, socklen_t * addrlen)
{
  swrap_bind_symbol_libc (getpeername);

  return swrap.libc.symbols._libc_getpeername.f (sockfd, addr, addrlen);
}

int
libc_getsockname (int sockfd, struct sockaddr *addr, socklen_t * addrlen)
{
  swrap_bind_symbol_libc (getsockname);

  return swrap.libc.symbols._libc_getsockname.f (sockfd, addr, addrlen);
}

int
libc_getsockopt (int sockfd,
		 int level, int optname, void *optval, socklen_t * optlen)
{
  swrap_bind_symbol_libc (getsockopt);

  return swrap.libc.symbols._libc_getsockopt.f (sockfd,
						level,
						optname, optval, optlen);
}

int
libc_listen (int sockfd, int backlog)
{
  swrap_bind_symbol_libc (listen);

  return swrap.libc.symbols._libc_listen.f (sockfd, backlog);
}

/* TBD: libc_read() should return ssize_t not an int */
int
libc_read (int fd, void *buf, size_t count)
{
  swrap_bind_symbol_libc (read);

  return swrap.libc.symbols._libc_read.f (fd, buf, count);
}

ssize_t
libc_readv (int fd, const struct iovec * iov, int iovcnt)
{
  swrap_bind_symbol_libc (readv);

  return swrap.libc.symbols._libc_readv.f (fd, iov, iovcnt);
}

int
libc_recv (int sockfd, void *buf, size_t len, int flags)
{
  swrap_bind_symbol_libc (recv);

  return swrap.libc.symbols._libc_recv.f (sockfd, buf, len, flags);
}

int
libc_recvfrom (int sockfd,
	       void *buf,
	       size_t len,
	       int flags, struct sockaddr *src_addr, socklen_t * addrlen)
{
  swrap_bind_symbol_libc (recvfrom);

  return swrap.libc.symbols._libc_recvfrom.f (sockfd,
					      buf,
					      len, flags, src_addr, addrlen);
}

int
libc_recvmsg (int sockfd, struct msghdr *msg, int flags)
{
  swrap_bind_symbol_libc (recvmsg);

  return swrap.libc.symbols._libc_recvmsg.f (sockfd, msg, flags);
}

int
libc_send (int sockfd, const void *buf, size_t len, int flags)
{
  swrap_bind_symbol_libc (send);

  return swrap.libc.symbols._libc_send.f (sockfd, buf, len, flags);
}

ssize_t
libc_sendfile (int out_fd, int in_fd, off_t * offset, size_t len)
{
  swrap_bind_symbol_libc (sendfile);

  return swrap.libc.symbols._libc_sendfile.f (out_fd, in_fd, offset, len);
}

int
libc_sendmsg (int sockfd, const struct msghdr *msg, int flags)
{
  swrap_bind_symbol_libc (sendmsg);

  return swrap.libc.symbols._libc_sendmsg.f (sockfd, msg, flags);
}

int
libc_sendto (int sockfd,
	     const void *buf,
	     size_t len,
	     int flags, const struct sockaddr *dst_addr, socklen_t addrlen)
{
  swrap_bind_symbol_libc (sendto);

  return swrap.libc.symbols._libc_sendto.f (sockfd,
					    buf,
					    len, flags, dst_addr, addrlen);
}

int
libc_setsockopt (int sockfd,
		 int level, int optname, const void *optval, socklen_t optlen)
{
  swrap_bind_symbol_libc (setsockopt);

  return swrap.libc.symbols._libc_setsockopt.f (sockfd,
						level,
						optname, optval, optlen);
}

int
libc_socket (int domain, int type, int protocol)
{
  swrap_bind_symbol_libc (socket);

  return swrap.libc.symbols._libc_socket.f (domain, type, protocol);
}

int
libc_socketpair (int domain, int type, int protocol, int sv[2])
{
  swrap_bind_symbol_libc (socketpair);

  return swrap.libc.symbols._libc_socketpair.f (domain, type, protocol, sv);
}

ssize_t
libc_write (int fd, const void *buf, size_t count)
{
  swrap_bind_symbol_libc (write);

  return swrap.libc.symbols._libc_write.f (fd, buf, count);
}

ssize_t
libc_writev (int fd, const struct iovec * iov, int iovcnt)
{
  swrap_bind_symbol_libc (writev);

  return swrap.libc.symbols._libc_writev.f (fd, iov, iovcnt);
}

int
libc_shutdown (int fd, int how)
{
  swrap_bind_symbol_libc (shutdown);

  return swrap.libc.symbols._libc_shutdown.f (fd, how);
}

int
libc_select (int __nfds, fd_set * __restrict __readfds,
	     fd_set * __restrict __writefds,
	     fd_set * __restrict __exceptfds,
	     struct timeval *__restrict __timeout)
{
  swrap_bind_symbol_libc (select);

  return swrap.libc.symbols._libc_select.f (__nfds, __readfds,
					    __writefds,
					    __exceptfds, __timeout);
}

#ifdef __USE_XOPEN2K
int
libc_pselect (int __nfds, fd_set * __restrict __readfds,
	      fd_set * __restrict __writefds,
	      fd_set * __restrict __exceptfds,
	      const struct timespec *__restrict __timeout,
	      const __sigset_t * __restrict __sigmask)
{
  swrap_bind_symbol_libc (pselect);

  return swrap.libc.symbols._libc_pselect.f (__nfds, __readfds,
					     __writefds,
					     __exceptfds,
					     __timeout, __sigmask);
}
#endif

int
libc_epoll_create (int __size)
{
  swrap_bind_symbol_libc (epoll_create);

  return swrap.libc.symbols._libc_epoll_create.f (__size);
}

int
libc_epoll_create1 (int __flags)
{
  swrap_bind_symbol_libc (epoll_create1);

  return swrap.libc.symbols._libc_epoll_create1.f (__flags);
}

int
libc_epoll_ctl (int __epfd, int __op, int __fd, struct epoll_event *__event)
{
  swrap_bind_symbol_libc (epoll_ctl);

  return swrap.libc.symbols._libc_epoll_ctl.f (__epfd, __op, __fd, __event);
}

int
libc_epoll_wait (int __epfd, struct epoll_event *__events,
		 int __maxevents, int __timeout)
{
  swrap_bind_symbol_libc (epoll_wait);

  return swrap.libc.symbols._libc_epoll_wait.f (__epfd, __events,
						__maxevents, __timeout);
}

int
libc_epoll_pwait (int __epfd, struct epoll_event *__events,
		  int __maxevents, int __timeout, const __sigset_t * __ss)
{
  swrap_bind_symbol_libc (epoll_pwait);

  return swrap.libc.symbols._libc_epoll_pwait.f (__epfd, __events,
						 __maxevents, __timeout,
						 __ss);
}

int
libc_poll (struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
  swrap_bind_symbol_libc (poll);

  return swrap.libc.symbols._libc_poll.f (__fds, __nfds, __timeout);
}

#ifdef __USE_GNU
int
libc_ppoll (struct pollfd *__fds, nfds_t __nfds,
	    const struct timespec *__timeout, const __sigset_t * __ss)
{
  swrap_bind_symbol_libc (ppoll);

  return swrap.libc.symbols._libc_ppoll.f (__fds, __nfds, __timeout, __ss);
}
#endif

static void
swrap_thread_prepare (void)
{
  SWRAP_LOCK_ALL;
}

static void
swrap_thread_parent (void)
{
  SWRAP_UNLOCK_ALL;
}

static void
swrap_thread_child (void)
{
  SWRAP_UNLOCK_ALL;
}

/****************************
 * CONSTRUCTOR
 ***************************/
void
swrap_constructor (void)
{
  /*
   * If we hold a lock and the application forks, then the child
   * is not able to unlock the mutex and we are in a deadlock.
   * This should prevent such deadlocks.
   */
  pthread_atfork (&swrap_thread_prepare,
		  &swrap_thread_parent, &swrap_thread_child);
}

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * sockets get closed and the unix file for the socket are unlinked.
 */
void
swrap_destructor (void)
{
  if (swrap.libc.handle != NULL)
    {
      dlclose (swrap.libc.handle);
    }
  if (swrap.libc.socket_handle)
    {
      dlclose (swrap.libc.socket_handle);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
