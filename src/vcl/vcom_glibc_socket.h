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

#ifndef included_vcom_glibc_socket_h
#define included_vcom_glibc_socket_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <sys/epoll.h>

#include <signal.h>
#include <poll.h>

/*
 *
 * Generic glibc fd api
 *
 */
/*
 * glibc APIs from <unistd.h>
 */

/* Close the file descriptor FD.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int close (int __fd);

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t __wur read (int __fd, void *__buf, size_t __nbytes);

/* Write N bytes of BUF to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t __wur write (int __fd, const void *__buf, size_t __n);


/*
 * glibc APIs from <fcntl.h>
 */

/* Do the file control operation described by CMD on FD.
   The remaining arguments are interpreted depending on CMD.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int fcntl (int __fd, int __cmd, ...);


/*
 * glibc APIs from <sys/select.h>
 */

/* Check the first NFDS descriptors each in READFDS (if not NULL) for read
   readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
   (if not NULL) for exceptional conditions.  If TIMEOUT is not NULL, time out
   after waiting the interval specified therein.  Returns the number of ready
   descriptors, or -1 for errors.


   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
select (int __nfds, fd_set * __restrict __readfds,
	fd_set * __restrict __writefds,
	fd_set * __restrict __exceptfds,
	struct timeval *__restrict __timeout);

#ifdef __USE_XOPEN2K
/* Same as above only that the TIMEOUT value is given with higher
   resolution and a sigmask which is been set temporarily.  This version
   should be used.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
pselect (int __nfds, fd_set * __restrict __readfds,
	 fd_set * __restrict __writefds,
	 fd_set * __restrict __exceptfds,
	 const struct timespec *__restrict __timeout,
	 const __sigset_t * __restrict __sigmask);
#endif


/*
 *
 * Socket specific glibc api
 *
 */

/*
 * glibc APIs from <sys/socket.h>
 */

/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
extern int __THROW socket (int __domain, int __type, int __protocol);

/* Create two new sockets, of type TYPE in domain DOMAIN and using
   protocol PROTOCOL, which are connected to each other, and put file
   descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
   one will be chosen automatically.  Returns 0 on success, -1 for errors.  */
extern int __THROW
socketpair (int __domain, int __type, int __protocol, int __fds[2]);

/* Give the socket FD the local address ADDR (which is LEN bytes long).  */
extern int __THROW
bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

/* Put the local address of FD into *ADDR and its length in *LEN.  */
extern int __THROW
getsockname (int __fd, __SOCKADDR_ARG __addr, socklen_t * __restrict __len);

/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);

/* Put the address of the peer connected to socket FD into *ADDR
   (which is *LEN bytes long), and its actual length into *LEN.  */
extern int __THROW
getpeername (int __fd, __SOCKADDR_ARG __addr, socklen_t * __restrict __len);

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t send (int __fd, const void *__buf, size_t __n, int __flags);

extern ssize_t sendfile (int __out_fd, int __in_fd, off_t * __offset,
			 size_t __len);

/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t recv (int __fd, void *__buf, size_t __n, int __flags);

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t
sendto (int __fd, const void *__buf, size_t __n,
	int __flags, __CONST_SOCKADDR_ARG __addr, socklen_t __addr_len);

/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t
recvfrom (int __fd, void *__restrict __buf,
	  size_t __n, int __flags,
	  __SOCKADDR_ARG __addr, socklen_t * __restrict __addr_len);

/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t
sendmsg (int __fd, const struct msghdr *__message, int __flags);

#ifdef __USE_GNU
/* Send a VLEN messages as described by VMESSAGES to socket FD.
   Returns the number of datagrams successfully written or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
sendmmsg (int __fd, struct mmsghdr *__vmessages,
	  unsigned int __vlen, int __flags);
#endif

/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t recvmsg (int __fd, struct msghdr *__message, int __flags);

#ifdef __USE_GNU
/* Receive up to VLEN messages as described by VMESSAGES from socket FD.
   Returns the number of messages received or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
recvmmsg (int __fd, struct mmsghdr *__vmessages,
	  unsigned int __vlen, int __flags, struct timespec *__tmo);
#endif


/* Put the current value for socket FD's option OPTNAME at protocol level LEVEL
   into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
   actual length.  Returns 0 on success, -1 for errors.  */
extern int __THROW
getsockopt (int __fd, int __level, int __optname,
	    void *__restrict __optval, socklen_t * __restrict __optlen);

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern int __THROW
setsockopt (int __fd, int __level, int __optname,
	    const void *__optval, socklen_t __optlen);

/* Prepare to accept connections on socket FD.
   N connection requests will be queued before further requests are refused.
   Returns 0 on success, -1 for errors.  */
extern int __THROW listen (int __fd, int __n);

/* Await a connection on socket FD.
   When a connection arrives, open a new socket to communicate with it,
   set *ADDR (which is *ADDR_LEN bytes long) to the address of the connecting
   peer and *ADDR_LEN to the address's actual length, and return the
   new socket's descriptor, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
accept (int __fd, __SOCKADDR_ARG __addr, socklen_t * __restrict __addr_len);

/* Similar to 'accept' but takes an additional parameter to specify flags.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
     /* TBD: implemented later */
extern int
accept4 (int __fd, __SOCKADDR_ARG __addr,
	 socklen_t * __restrict __addr_len, int __flags);

/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */
extern int __THROW shutdown (int __fd, int __how);


/*
 * glibc APIs from <sys/epoll.h>
 */

/* Creates an epoll instance.  Returns an fd for the new instance.
   The "size" parameter is a hint specifying the number of file
   descriptors to be associated with the new instance.  The fd
   returned by epoll_create() should be closed with close().  */
extern int __THROW epoll_create (int __size);

/* Same as epoll_create but with an FLAGS parameter.  The unused SIZE
   parameter has been dropped.  */
extern int __THROW epoll_create1 (int __flags);

/* Manipulate an epoll instance "epfd". Returns 0 in case of success,
   -1 in case of error ( the "errno" variable will contain the
   specific error code ) The "op" parameter is one of the EPOLL_CTL_*
   constants defined above. The "fd" parameter is the target of the
   operation. The "event" parameter describes which events the caller
   is interested in and any associated user data.  */
extern int __THROW
epoll_ctl (int __epfd, int __op, int __fd, struct epoll_event *__event);

#define EP_INT_MAX ((int)(~0U>>1))
#define EP_MAX_EVENTS (EP_INT_MAX / sizeof(struct epoll_event))

/* Wait for events on an epoll instance "epfd". Returns the number of
   triggered events returned in "events" buffer. Or -1 in case of
   error with the "errno" variable set to the specific error code. The
   "events" parameter is a buffer that will contain triggered
   events. The "maxevents" is the maximum number of events to be
   returned ( usually size of "events" ). The "timeout" parameter
   specifies the maximum wait time in milliseconds (-1 == infinite).

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
epoll_wait (int __epfd, struct epoll_event *__events,
	    int __maxevents, int __timeout);

/* Same as epoll_wait, but the thread's signal mask is temporarily
   and atomically replaced with the one provided as parameter.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int
epoll_pwait (int __epfd, struct epoll_event *__events,
	     int __maxevents, int __timeout, const __sigset_t * __ss);

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
   an event to occur; if TIMEOUT is -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int poll (struct pollfd *__fds, nfds_t __nfds, int __timeout);

#ifdef __USE_GNU
/* Like poll, but before waiting the threads signal mask is replaced
   with that specified in the fourth parameter.  For better usability,
   the timeout value is specified using a TIMESPEC object.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int ppoll (struct pollfd *__fds, nfds_t __nfds,
		  const struct timespec *__timeout, const __sigset_t * __ss);
#endif


#endif /* included_vcom_glibc_socket_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
