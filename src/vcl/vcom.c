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
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <sys/resource.h>

#include <vcl/vcom_socket_wrapper.h>
#include <vcl/vcom.h>
#include <sys/time.h>

#include <vcl/vppcom.h>
#include <vcl/vcom_socket.h>

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b)                       \
    __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

#define HAVE_CONSTRUCTOR_ATTRIBUTE
#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE                       \
    __attribute__ ((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */

#define HAVE_DESTRUCTOR_ATTRIBUTE
#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE                        \
    __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif

#define HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#ifdef HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE           \
    __attribute__((no_sanitize_address))
#else
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
#endif

#define VCOM_SOCKET_FD_MAX  0x10000

static char vcom_app_name[MAX_VCOM_APP_NAME];

/*
 * RETURN:  0 on success or -1 on error.
 * */
int
vcom_set_app_name (char *__app_name)
{
  return snprintf (vcom_app_name, MAX_VCOM_APP_NAME, "vcom-%s-%d",
		   __app_name, getpid ()) < 0 ? -1 : 0;
}

static char *
vcom_get_app_name ()
{
  if (vcom_app_name[0] == '\0')
    {
      snprintf (vcom_app_name, MAX_VCOM_APP_NAME, "vcom-app-%d", getpid ());
    }
  return vcom_app_name;
}

/*
 * 1 if init, 0 otherwise
 */
static int is_vcom_init;

/*
 * TBD: Make it thread safe
 */

/*
 * constructor function called before main is called
 * RETURN: 0 on success -1 on failure
 * */
static inline int
vcom_init ()
{
  pid_t pid = getpid ();

  if (!is_vcom_init)
    {
      if (vppcom_app_create (vcom_get_app_name ()) != 0)
	{
	  printf ("\n[%d] vcom_init...failed!\n", pid);
	  if (VCOM_DEBUG > 0)
	    fprintf (stderr,
		     "[%d] vcom_init: vppcom_app_create failed!\n", pid);
	  return -1;
	}
      if (vcom_socket_main_init () != 0)
	{
	  printf ("\n[%d] vcom_init...failed!\n", pid);
	  if (VCOM_DEBUG > 0)
	    fprintf (stderr,
		     "[%d] vcom_init: vcom_socket_main_init failed!\n", pid);
	  return -1;
	}

      is_vcom_init = 1;
      printf ("\n[%d] vcom_init...done!\n", pid);
    }
  return 0;
}

static inline void
vcom_destroy (void)
{
  pid_t pid = getpid ();

  if (is_vcom_init)
    {
      vcom_socket_main_destroy ();
      vppcom_app_destroy ();
      is_vcom_init = 0;
      fprintf (stderr, "\n[%d] vcom_destroy...done!\n", pid);
    }
}

static inline int
is_vcom_socket_fd (int fd)
{
  return vcom_socket_is_vcom_fd (fd);
}

static inline int
is_vcom_epfd (int epfd)
{
  return vcom_socket_is_vcom_epfd (epfd);
}


/*
 *
 * Generic glibc fd api
 *
 */

/* Close the file descriptor FD.

   This function is a cancellation point and therefore
   not marked with __THROW.  */
/*
 * PRE:     is_vcom_socket_fd(__fd) == 1
 * RETURN:  0 on success and -1 for errors.
 * */
int
vcom_close (int __fd)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  if (vcom_socket_close (__fd) != 0)
    {
      return -1;
    }

  return 0;
}

/*
 * RETURN:  0 on success, or -1 on error
 */
int
close (int __fd)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd) || is_vcom_epfd (__fd))
    {
      if (VCOM_DEBUG > 0)
	vcom_socket_main_show ();
      rv = vcom_close (__fd);
      if (VCOM_DEBUG > 0)
	fprintf (stderr, "[%d] close: " "'%04d'='%04d'\n", pid, rv, __fd);
      if (VCOM_DEBUG > 0)
	vcom_socket_main_show ();
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_close (__fd);
}

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore
   not marked with __THROW.  */
ssize_t
vcom_read (int __fd, void *__buf, size_t __nbytes)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_read (__fd, __buf, __nbytes);
}

ssize_t
read (int __fd, void *__buf, size_t __nbytes)
{
  ssize_t size = 0;
  pid_t pid = getpid ();
  pthread_t tid = pthread_self ();

  if (is_vcom_socket_fd (__fd))
    {
      if (VCOM_DEBUG > 2)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] read:1 "
		 "'%04d'='%04d', '%p', '%04d'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 (int) size, __fd, __buf, (int) __nbytes);
      size = vcom_read (__fd, __buf, __nbytes);
      if (VCOM_DEBUG > 2)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] read:2 "
		 "'%04d'='%04d', '%p', '%04d'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 (int) size, __fd, __buf, (int) __nbytes);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_read (__fd, __buf, __nbytes);
}

ssize_t
vcom_readv (int __fd, const struct iovec * __iov, int __iovcnt)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_readv (__fd, __iov, __iovcnt);
}

ssize_t
readv (int __fd, const struct iovec * __iov, int __iovcnt)
{
  ssize_t size = 0;

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_readv (__fd, __iov, __iovcnt);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  else
    return libc_readv (__fd, __iov, __iovcnt);
}

/* Write N bytes of BUF to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore
   not marked with __THROW.  */
ssize_t
vcom_write (int __fd, const void *__buf, size_t __n)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_write (__fd, (void *) __buf, __n);
}

ssize_t
write (int __fd, const void *__buf, size_t __n)
{
  ssize_t size = 0;
  pid_t pid = getpid ();
  pthread_t tid = pthread_self ();

  if (is_vcom_socket_fd (__fd))
    {
      if (VCOM_DEBUG > 2)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] write:1 "
		 "'%04d'='%04d', '%p', '%04d'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 (int) size, __fd, __buf, (int) __n);
      size = vcom_write (__fd, __buf, __n);
      if (VCOM_DEBUG > 2)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] write:2 "
		 "'%04d'='%04d', '%p', '%04d'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 (int) size, __fd, __buf, (int) __n);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_write (__fd, __buf, __n);
}

ssize_t
vcom_writev (int __fd, const struct iovec * __iov, int __iovcnt)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_writev (__fd, __iov, __iovcnt);
}

ssize_t
writev (int __fd, const struct iovec * __iov, int __iovcnt)
{
  ssize_t size = 0;

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_writev (__fd, __iov, __iovcnt);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  else
    return libc_writev (__fd, __iov, __iovcnt);
}

/* Do the file control operation described by CMD on FD.
   The remaining arguments are interpreted depending on CMD.

   This function is a cancellation point and therefore
   not marked with __THROW.  */
int
vcom_fcntl_va (int __fd, int __cmd, va_list __ap)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_fcntl_va (__fd, __cmd, __ap);
}

int
vcom_fcntl (int __fd, int __cmd, ...)
{
  int rv = -1;
  va_list ap;

  if (is_vcom_socket_fd (__fd))
    {
      va_start (ap, __cmd);
      rv = vcom_fcntl_va (__fd, __cmd, ap);
      va_end (ap);
    }
  return rv;
}

int
fcntl (int __fd, int __cmd, ...)
{
  int rv;
  va_list ap;
  pid_t pid = getpid ();

  va_start (ap, __cmd);
  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_fcntl_va (__fd, __cmd, ap);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] fcntl: "
		 "'%04d'='%04d', '%04d'\n", pid, rv, __fd, __cmd);
      if (rv < 0)
	{
	  errno = -rv;
	  rv = -1;
	}
      goto out;
    }
  rv = libc_vfcntl (__fd, __cmd, ap);

out:
  va_end (ap);
  return rv;
}

int
vcom_ioctl_va (int __fd, unsigned long int __cmd, va_list __ap)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_ioctl_va (__fd, __cmd, __ap);
}

int
vcom_ioctl (int __fd, unsigned long int __cmd, ...)
{
  int rv = -1;
  va_list ap;

  if (is_vcom_socket_fd (__fd))
    {
      va_start (ap, __cmd);
      rv = vcom_ioctl_va (__fd, __cmd, ap);
      va_end (ap);
    }
  return rv;
}

int
ioctl (int __fd, unsigned long int __cmd, ...)
{
  int rv;
  va_list ap;
  pid_t pid = getpid ();

  va_start (ap, __cmd);
  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_ioctl_va (__fd, __cmd, ap);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] ioctl: "
		 "'%04d'='%04d', '%04ld'\n", pid, rv, __fd, __cmd);
      if (rv < 0)
	{
	  errno = -rv;
	  rv = -1;
	}
      goto out;
    }
  rv = libc_vioctl (__fd, __cmd, ap);

out:
  va_end (ap);
  return rv;
}

/*
 * Check the first NFDS descriptors each in READFDS (if not NULL) for
 *  read readiness, in WRITEFDS (if not NULL) for write readiness,
 *  and in EXCEPTFDS (if not NULL) for exceptional conditions.
 *  If TIMEOUT is not NULL, time out after waiting the interval
 *  specified therein.  Returns the number of ready descriptors,
 *  or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */

/*
 * clear all vcom FDs from fd_sets __readfds, __writefds and
 * __exceptfds and update the new nfds
 *
 * new nfds is the highest-numbered file descriptor
 * in any of the three sets, plus 1
 *
 * Return the number of file descriptors contained in the
 * three descriptor sets. ie. the total number of the bits
 * that are set in  __readfds, __writefds and __exceptfds
 */
static inline int
vcom_fd_clear (int __nfds,
	       int *__new_nfds,
	       fd_set * __restrict __readfds,
	       fd_set * __restrict __writefds,
	       fd_set * __restrict __exceptfds)
{
  int fd;
  /* invalid max_fd is -1 */
  int max_fd = -1;
  int nfd = 0;


  /* clear all vcom fd from the sets */
  for (fd = 0; fd < __nfds; fd++)
    {

      /* clear vcom fd from set */
      /*
       * F fd set
       */
#define _(F)                                    \
      if ((F) && FD_ISSET (fd, (F)))            \
        {                                       \
          if (is_vcom_socket_fd (fd))           \
            {                                   \
              FD_CLR (fd, (F));                 \
            }                                   \
        }


      _(__readfds);
      _(__writefds);
      _(__exceptfds);
#undef _
    }

  /*
   *  compute nfd and __new_nfds
   */
  for (fd = 0; fd < __nfds; fd++)
    {

      /*
       * F fd set
       */
#define _(F)                                    \
      if ((F) && FD_ISSET (fd, (F)))            \
        {                                       \
          if (fd > max_fd)                      \
            {                                   \
              max_fd = fd;                      \
            }                                   \
          ++nfd;                                \
        }


      _(__readfds);
      _(__writefds);
      _(__exceptfds);
#undef _
    }

  *__new_nfds = max_fd != -1 ? max_fd + 1 : 0;
  return nfd;
}

/*
 * Return the number of file descriptors contained in the
 * three descriptor sets. ie. the total number of the bits
 * that are set in  __readfds, __writefds and __exceptfds
 */
static inline int
vcom_fd_set (int __nfds,
	     /* dest */
	     int *__new_nfds,
	     fd_set * __restrict __readfds,
	     fd_set * __restrict __writefds, fd_set * __restrict __exceptfds,
	     /* src */
	     fd_set * __restrict __saved_readfds,
	     fd_set * __restrict __saved_writefds,
	     fd_set * __restrict __saved_exceptfds)
{
  int fd;
  /* invalid max_fd is -1 */
  int max_fd = -1;
  int nfd = 0;

  for (fd = 0; fd < __nfds; fd++)
    {
      /*
       * F fd set
       * S saved fd set
       */
#define _(S,F)                                  \
      if ((F) && (S) && FD_ISSET (fd, (S)))     \
        {                                       \
          if (is_vcom_socket_fd (fd))           \
            {                                   \
              FD_SET (fd, (F));                 \
            }                                   \
        }


      _(__saved_readfds, __readfds);
      _(__saved_writefds, __writefds);
#undef _
    }


  /*
   *  compute nfd and __new_nfds
   */
  for (fd = 0; fd < __nfds; fd++)
    {

      /*
       * F fd set
       */
#define _(F)                                    \
      if ((F) && FD_ISSET (fd, (F)))            \
        {                                       \
          if (fd > max_fd)                      \
            {                                   \
              max_fd = fd;                      \
            }                                   \
          ++nfd;                                \
        }


      _(__readfds);
      _(__writefds);
      _(__exceptfds);
#undef _
    }

  *__new_nfds = max_fd != -1 ? max_fd + 1 : 0;
  return nfd;
}

/*
 * split select sets(src) into
 * vcom sets(dest1) and libc sets(dest2)
 */
static inline void
vcom_fd_set_split (
		    /* src, select sets */
		    int nfds,
		    fd_set * __restrict readfds,
		    fd_set * __restrict writefds,
		    fd_set * __restrict exceptfds,
		    /* dest1, vcom sets */
		    int *vcom_nfds,
		    fd_set * __restrict vcom_readfds,
		    fd_set * __restrict vcom_writefds,
		    fd_set * __restrict vcom_exceptfds, int *vcom_nfd,
		    /* dest2, libc sets */
		    int *libc_nfds,
		    fd_set * __restrict libc_readfds,
		    fd_set * __restrict libc_writefds,
		    fd_set * __restrict libc_exceptfds, int *libc_nfd)
{
  int fd;

  /* vcom */
  /* invalid max_fd is -1 */
  int vcom_max_fd = -1;
  int vcom_nfd2 = 0;

  /* libc */
  /* invalid max_fd is -1 */
  int libc_max_fd = -1;
  int libc_nfd2 = 0;


  for (fd = 0; fd < nfds; fd++)
    {
      /*
       * S select fd set
       * V vcom fd set
       * L libc fd set
       */
#define _(S,V,L)                            \
      if ((S) && FD_ISSET (fd, (S)))        \
        {                                   \
          if (is_vcom_socket_fd (fd))       \
            {                               \
              if ((V))                      \
                {                           \
                  FD_SET(fd, (V));          \
                  if (fd > vcom_max_fd)     \
                    {                       \
                      vcom_max_fd = fd;     \
                    }                       \
                  ++vcom_nfd2;              \
                }                           \
            }                               \
          else                              \
            {                               \
              if ((L))                      \
                {                           \
                  FD_SET(fd, (L));          \
                  if (fd > libc_max_fd)     \
                    {                       \
                      libc_max_fd = fd;     \
                    }                       \
                  ++libc_nfd2;              \
                }                           \
            }                               \
        }


      _(readfds, vcom_readfds, libc_readfds);
      _(writefds, vcom_writefds, libc_writefds);
      _(exceptfds, vcom_exceptfds, libc_exceptfds);
#undef _
    }

  if (vcom_nfds)
    *vcom_nfds = vcom_max_fd != -1 ? vcom_max_fd + 1 : 0;
  if (vcom_nfd)
    *vcom_nfd = vcom_nfd2;
  if (libc_nfds)
    *libc_nfds = libc_max_fd != -1 ? libc_max_fd + 1 : 0;
  if (libc_nfd)
    *libc_nfd = libc_nfd2;
}

/*
 * merge vcom sets(src1) and libc sets(src2)
 * into select sets(dest)
 */
static inline void
vcom_fd_set_merge (
		    /* dest, select sets */
		    int *nfds,
		    fd_set * __restrict readfds,
		    fd_set * __restrict writefds,
		    fd_set * __restrict exceptfds, int *nfd,
		    /* src1, vcom sets */
		    int vcom_nfds,
		    fd_set * __restrict vcom_readfds,
		    fd_set * __restrict vcom_writefds,
		    fd_set * __restrict vcom_exceptfds, int vcom_nfd,
		    /* src2, libc sets */
		    int libc_nfds,
		    fd_set * __restrict libc_readfds,
		    fd_set * __restrict libc_writefds,
		    fd_set * __restrict libc_exceptfds, int libc_nfd)
{
  int fd;
  /* invalid max_fd is -1 */
  int max_fd = -1;
  int nfd2 = 0;


  /* FD_BIT_OR
   *
   * dest |= src at current bit index
   * update MAX and NFD of dest fd set
   *
   *
   * FS source fd set
   * FD dest fd set
   * BI bit index
   * MAX current max_fd of dest fd sets
   * NFD current nfd of dest fd sets
   * N  nfds of source fd set
   */
#define FD_BIT_OR(FD,FS,BI,          \
                  MAX,NFD)           \
  if ((FS) && (FD) && FD_ISSET ((BI), (FS)))    \
    {                                           \
      FD_SET ((BI), (FD));                      \
      if ((BI) > (MAX))                         \
        {                                       \
          (MAX) = (BI);                         \
        }                                       \
      ++(NFD);                                  \
    }


  /* FD_RWE_SET_OR */
  /*
   * SR,SW,SE source RWE fd sets
   * DR,DW,DE dest RWE fd sets
   * BI bit index
   * NFDS  nfds of source fd sets
   * MAX current max_fd of dest fd sets
   * NFD current nfd of dest fd sets
   */
#define FD_RWE_SETS_OR(DR,DW,DE,      \
                      SR,SW,SE,       \
                      BI,NFDS,        \
                      MAX,NFD)        \
  do                                                      \
    {                                                     \
      for ((BI) = 0; (BI) < (NFDS); (BI)++)               \
        {                                                 \
          FD_BIT_OR((DR), (SR), (BI), (MAX), (NFD));      \
          FD_BIT_OR((DW), (SW), (BI), (MAX), (NFD));      \
          FD_BIT_OR((DE), (SE), (BI), (MAX), (NFD));      \
        }                                                 \
      }                                                   \
    while (0);


  /* source(vcom) to dest(select) rwe fd sets */
  FD_RWE_SETS_OR (readfds, writefds, exceptfds,
		  vcom_readfds, vcom_writefds, vcom_exceptfds,
		  fd, vcom_nfds, max_fd, nfd2);

  /* source(libc) to dest(select) rwe fd sets */
  FD_RWE_SETS_OR (readfds, writefds, exceptfds,
		  libc_readfds, libc_writefds, libc_exceptfds,
		  fd, libc_nfds, max_fd, nfd2);

#undef FD_RWE_SETS_OR
#undef FD_BIT_OR

  if (nfds)
    *nfds = max_fd != -1 ? max_fd + 1 : 0;
  if (nfd)
    *nfd = nfd2;
}

/*
 * RETURN 1 if fds is NULL or empty. 0 otherwise
 */
static inline int
fd_set_iszero (fd_set * __restrict fds)
{
  int fd;

  /* NULL fds */
  if (!fds)
    return 1;

  for (fd = 0; fd < FD_SETSIZE; fd++)
    {
      if (FD_ISSET (fd, fds))
	{
	  /* non-empty fds */
	  return 0;
	}
    }
  /* empty fds */
  return 1;
}


/*
 * ################
 * kernel time64.h
 * ################
 * */
typedef long int s64;
typedef unsigned long int u64;

typedef long long int __s64;
typedef unsigned long long int __u64;

typedef __s64 time64_t;
typedef __u64 timeu64_t;

/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL


/*
 * ################
 * kernel time.h
 * ################
 * */


#define TIME_T_MAX      (time_t)((1UL << ((sizeof(time_t) << 3) - 1)) - 1)

#ifdef VCOM_USE_TIMESPEC_EQUAL
static inline int
timespec_equal (const struct timespec *a, const struct timespec *b)
{
  return (a->tv_sec == b->tv_sec) && (a->tv_nsec == b->tv_nsec);
}
#endif

/*
 * lhs < rhs:  return <0
 * lhs == rhs: return 0
 * lhs > rhs:  return >0
 */
static inline int
timespec_compare (const struct timespec *lhs, const struct timespec *rhs)
{
  if (lhs->tv_sec < rhs->tv_sec)
    return -1;
  if (lhs->tv_sec > rhs->tv_sec)
    return 1;
  return lhs->tv_nsec - rhs->tv_nsec;
}

#ifdef VCOM_USE_TIMEVAL_COMPARE
static inline int
timeval_compare (const struct timeval *lhs, const struct timeval *rhs)
{
  if (lhs->tv_sec < rhs->tv_sec)
    return -1;
  if (lhs->tv_sec > rhs->tv_sec)
    return 1;
  return lhs->tv_usec - rhs->tv_usec;
}
#endif

extern void set_normalized_timespec (struct timespec *ts, time_t sec,
				     s64 nsec);

static inline struct timespec
timespec_add (struct timespec lhs, struct timespec rhs)
{
  struct timespec ts_delta;
  set_normalized_timespec (&ts_delta, lhs.tv_sec + rhs.tv_sec,
			   lhs.tv_nsec + rhs.tv_nsec);
  return ts_delta;
}

/*
 * sub = lhs - rhs, in normalized form
 */
static inline struct timespec
timespec_sub (struct timespec lhs, struct timespec rhs)
{
  struct timespec ts_delta;
  set_normalized_timespec (&ts_delta, lhs.tv_sec - rhs.tv_sec,
			   lhs.tv_nsec - rhs.tv_nsec);
  return ts_delta;
}

/*
 * ################
 * kernel time.c
 * ################
 * */


/**
 * set_normalized_timespec - set timespec sec and nsec parts and normalize
 *
 * @ts:         pointer to timespec variable to be set
 * @sec:        seconds to set
 * @nsec:       nanoseconds to set
 *
 * Set seconds and nanoseconds field of a timespec variable and
 * normalize to the timespec storage format
 *
 * Note: The tv_nsec part is always in the range of
 *      0 <= tv_nsec < NSEC_PER_SEC
 * For negative values only the tv_sec field is negative !
 */
void
set_normalized_timespec (struct timespec *ts, time_t sec, s64 nsec)
{
  while (nsec >= NSEC_PER_SEC)
    {
      /*
       * The following asm() prevents the compiler from
       * optimising this loop into a modulo operation. See
       * also __iter_div_u64_rem() in include/linux/time.h
       */
    asm ("":"+rm" (nsec));
      nsec -= NSEC_PER_SEC;
      ++sec;
    }
  while (nsec < 0)
    {
    asm ("":"+rm" (nsec));
      nsec += NSEC_PER_SEC;
      --sec;
    }
  ts->tv_sec = sec;
  ts->tv_nsec = nsec;
}

#define vcom_timerisvalid(tvp)        (!((tvp)->tv_sec < 0 || (tvp)->tv_usec < 0))

/* Macros for converting between `struct timeval' and `struct timespec'.  */
#define VCOM_TIMEVAL_TO_TIMESPEC(tv, ts) {                             \
        (ts)->tv_sec = (tv)->tv_sec;                                    \
        (ts)->tv_nsec = (tv)->tv_usec * 1000;                           \
}
#define VCOM_TIMESPEC_TO_TIMEVAL(tv, ts) {                             \
        (tv)->tv_sec = (ts)->tv_sec;                                    \
        (tv)->tv_usec = (ts)->tv_nsec / 1000;                           \
}

static inline int
vcom_select_impl (int vcom_nfds, fd_set * __restrict vcom_readfds,
		  fd_set * __restrict vcom_writefds,
		  fd_set * __restrict vcom_exceptfds,
		  struct timeval *__restrict timeout)
{
  return vcom_socket_select (vcom_nfds, vcom_readfds,
			     vcom_writefds, vcom_exceptfds, timeout);
}

int
vcom_select (int __nfds, fd_set * __restrict __readfds,
	     fd_set * __restrict __writefds,
	     fd_set * __restrict __exceptfds,
	     struct timeval *__restrict __timeout)
{
  int rv;
  int rv2 = 0;
  pid_t pid = getpid ();

  int timedout = 0;
  /* block indefinitely */
  int no_timeout = 0;
  int first_clock_gettime_failed = 0;
  /* timeout value in units of timespec */
  struct timespec timeout_ts;
  struct timespec start_time, now, end_time;

  /* select sets attributes - after merge */
  int new_nfds = 0;
  int new_nfd = -1;

  /* vcom */
  int vcom_nfds = 0;
  fd_set vcom_readfds;
  fd_set vcom_writefds;
  fd_set vcom_exceptfds;
  int vcom_nfd = -1;

  /* libc */
  int libc_nfds = 0;
  fd_set libc_readfds;
  fd_set libc_writefds;
  fd_set libc_exceptfds;
  int libc_nfd = -1;

  /* for polling */
  struct timeval tv = {.tv_sec = 0,.tv_usec = 0 };

  /* validate __timeout */
  if (__timeout)
    {
      /* validate tv_sec */
      /* bogus */
      if (!vcom_timerisvalid (__timeout))
	{
	  rv = -EINVAL;
	  goto select_done;
	}

      /* validate tv_usec */
      /* TBD: */
      /* init timeout_ts */
      VCOM_TIMEVAL_TO_TIMESPEC (__timeout, &timeout_ts);
      set_normalized_timespec (&timeout_ts,
			       timeout_ts.tv_sec, timeout_ts.tv_nsec);
    }

  rv = clock_gettime (CLOCK_MONOTONIC, &start_time);
  if (rv == -1)
    {
      rv = -errno;
      first_clock_gettime_failed = 1;
      goto select_done;
    }

  /* init end_time */
  if (__timeout)
    {
      if (timerisset (__timeout))
	{
	  end_time = timespec_add (start_time, timeout_ts);
	}
      else
	{
	  /*
	   * if both fields of the timeout structure are zero,
	   * then select returns immediately
	   * */
	  end_time = start_time;
	}
    }
  else
    {
      /* block indefinitely */
      no_timeout = 1;
    }



  if (vcom_init () != 0)
    {
      rv = -1;
      goto select_done;
    }

  /* validate __nfds */
  if (__nfds < 0 || __nfds > FD_SETSIZE)
    {
      rv = -EINVAL;
      goto select_done;
    }


  /*
   * usleep(3) emulation
   * */

  /* call libc_select() with a finite timeout and
   * no file descriptors or empty fd sets and
   * zero nfds */
  if (__nfds == 0 &&
      (!__readfds || fd_set_iszero (__readfds)) &&
      (!__writefds || fd_set_iszero (__writefds)) &&
      (!__exceptfds || fd_set_iszero (__exceptfds)))
    {
      if (__timeout)
	{
	  rv = libc_select (__nfds,
			    __readfds, __writefds, __exceptfds, __timeout);
	  if (rv == -1)
	    rv = -errno;
	}
      else
	{
	  /* TBD: block indefinitely or return -EINVAL */
	  rv = -EINVAL;
	}
      goto select_done;
    }

  /* init once before the polling loop */

  /* zero vcom and libc fd sets */
  /*
   * S select fd set
   * V vcom fd set
   * L libc fd set
   */
#define _(S,V,L)      \
  if ((S))            \
    {                 \
      FD_ZERO ((V));  \
      FD_ZERO ((L));  \
    }


  _(__readfds, &vcom_readfds, &libc_readfds);
  _(__writefds, &vcom_writefds, &libc_writefds);
  _(__exceptfds, &vcom_exceptfds, &libc_exceptfds);
#undef _
  new_nfds = 0;
  new_nfd = -1;

  vcom_nfds = 0;
  vcom_nfd = -1;
  libc_nfds = 0;
  libc_nfd = -1;

  vcom_fd_set_split (
		      /* src, select sets */
		      __nfds, __readfds, __writefds, __exceptfds,
		      /* dest1, vcom sets */
		      __readfds || __writefds || __exceptfds ?
		      &vcom_nfds : NULL,
		      __readfds ? &vcom_readfds : NULL,
		      __writefds ? &vcom_writefds : NULL,
		      __exceptfds ? &vcom_exceptfds : NULL,
		      __readfds || __writefds || __exceptfds ?
		      &vcom_nfd : NULL,
		      /* dest2, libc sets */
		      __readfds || __writefds || __exceptfds ?
		      &libc_nfds : NULL,
		      __readfds ? &libc_readfds : NULL,
		      __writefds ? &libc_writefds : NULL,
		      __exceptfds ? &libc_exceptfds : NULL,
		      __readfds || __writefds || __exceptfds ?
		      &libc_nfd : NULL);

  /*
   * polling loop
   * */
  do
    {
      new_nfd = -1;
      vcom_nfd = -1;
      libc_nfd = -1;

      /*
       * if both fields of timeval structure are zero,
       * vcom_select_impl and libc_select returns immediately.
       * useful for polling and ensure fairness among
       * file descriptors watched.
       */

      /* for polling */
      tv.tv_sec = 0;
      tv.tv_usec = 0;

      /* select on vcom fds */
      if (vcom_nfds)
	{
	  vcom_nfd = vcom_select_impl (vcom_nfds,
				       __readfds ? &vcom_readfds : NULL,
				       __writefds ? &vcom_writefds : NULL,
				       __exceptfds ? &vcom_exceptfds : NULL,
				       &tv);
	  if (VCOM_DEBUG > 2)
	    fprintf (stderr,
		     "[%d] select vcom: "
		     "'%04d'='%04d'\n", pid, vcom_nfd, vcom_nfds);

	  if (vcom_nfd < 0)
	    {
	      rv = vcom_nfd;
	      goto select_done;
	    }
	}
      /* select on libc fds */
      if (libc_nfds)
	{
	  libc_nfd = libc_select (libc_nfds,
				  __readfds ? &libc_readfds : NULL,
				  __writefds ? &libc_writefds : NULL,
				  __exceptfds ? &libc_exceptfds : NULL, &tv);
	  if (VCOM_DEBUG > 2)
	    fprintf (stderr,
		     "[%d] select libc: "
		     "'%04d'='%04d'\n", pid, libc_nfd, libc_nfds);

	  if (libc_nfd < 0)
	    {
	      /* tv becomes undefined */
	      libc_nfd = errno;
	      rv = libc_nfd;
	      goto select_done;
	    }
	}

      /* check if any file descriptors changed status */
      if ((vcom_nfds && vcom_nfd > 0) || (libc_nfds && libc_nfd > 0))
	{
	  /* zero the sets before merge and exit */

	  /*
	   * F fd set
	   */
#define _(F)                  \
          if ((F))            \
            {                 \
              FD_ZERO ((F));  \
            }


	  _(__readfds);
	  _(__writefds);
	  _(__exceptfds);
#undef _
	  new_nfds = 0;
	  new_nfd = -1;

	  /*
	   * on exit, sets are modified in place to indicate which
	   * file descriptors actually changed status
	   * */
	  vcom_fd_set_merge (
			      /* dest, select sets */
			      &new_nfds,
			      __readfds, __writefds, __exceptfds, &new_nfd,
			      /* src1, vcom sets */
			      vcom_nfds,
			      __readfds ? &vcom_readfds : NULL,
			      __writefds ? &vcom_writefds : NULL,
			      __exceptfds ? &vcom_exceptfds : NULL, vcom_nfd,
			      /* src2, libc sets */
			      libc_nfds,
			      __readfds ? &libc_readfds : NULL,
			      __writefds ? &libc_writefds : NULL,
			      __exceptfds ? &libc_exceptfds : NULL, libc_nfd);
	  /*
	   * return the number of file descriptors contained in the
	   * three returned sets
	   * */
	  rv = 0;
	  /*
	   * for documentation
	   *
	   * if(vcom_nfd > 0)
	   *   rv += vcom_nfd;
	   * if(libc_nfd > 0)
	   *   rv += libc_nfd;
	   */

	  rv = new_nfd == -1 ? 0 : new_nfd;
	  goto select_done;
	}

      rv = clock_gettime (CLOCK_MONOTONIC, &now);
      if (rv == -1)
	{
	  rv = -errno;
	  goto select_done;
	}
    }
  while (no_timeout || timespec_compare (&now, &end_time) < 0);

  /* timeout expired before anything interesting happened */
  timedout = 1;
  rv = 0;

select_done:
  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] vselect1: " "'%04d'='%04d'\n", pid, rv, __nfds);
  /*
   * modify timeout parameter to reflect the amount of time not slept
   * */
  if (__timeout)
    {
      if (vcom_timerisvalid (__timeout))
	{
	  /* timeout expired */
	  if (timedout)
	    {
	      timerclear (__timeout);
	    }
	  else if (!first_clock_gettime_failed)
	    {
	      rv2 = clock_gettime (CLOCK_MONOTONIC, &now);
	      if (rv2 == -1)
		{
		  rv = -errno;
		}
	      else
		{
		  struct timespec ts_delta;
		  ts_delta = timespec_sub (end_time, now);
		  VCOM_TIMESPEC_TO_TIMEVAL (__timeout, &ts_delta);
		}
	    }
	}
    }
  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] vselect2: " "'%04d',='%04d'\n", pid, rv, __nfds);

  return rv;
}

int
vcom_select_internal (int __nfds, fd_set * __restrict __readfds,
		      fd_set * __restrict __writefds,
		      fd_set * __restrict __exceptfds,
		      struct timeval *__restrict __timeout)
{
  int rv;
  int new_nfds = 0;
  int nfd = 0;
  pid_t pid = getpid ();

  fd_set saved_readfds;
  fd_set saved_writefds;
  fd_set saved_exceptfds;

  /* validate __nfds */
  if (__nfds < 0)
    {
      errno = EINVAL;
      return -1;
    }

  /* validate __timeout */
  if (__timeout)
    {
      /* validate tv_sec */
      /* bogus */
      if (__timeout->tv_sec < 0 || __timeout->tv_usec < 0)
	{
	  errno = EINVAL;
	  return -1;
	}

      /* validate tv_usec */
      /* TBD: */
    }

  /* init saved_x fds */
  if (__readfds)
    {
      saved_readfds = *__readfds;
      /*
         memcpy (&saved_readfds, __readfds, sizeof (*__readfds));
       */
    }
  else
    {
      FD_ZERO (&saved_readfds);
    }

  if (__writefds)
    {
      saved_writefds = *__writefds;
      /*
         memcpy (&saved_writefds, __writefds, sizeof (*__writefds));
       */

    }
  else
    {
      FD_ZERO (&saved_writefds);
    }

  if (__exceptfds)
    {
      saved_exceptfds = *__exceptfds;
      /*
         memcpy (&saved_exceptfds, __exceptfds, sizeof (*__exceptfds));
       */

    }
  else
    {
      FD_ZERO (&saved_exceptfds);
    }

  /* clear vcom fds */
  nfd = vcom_fd_clear (__nfds, &new_nfds, __readfds, __writefds, __exceptfds);

  /* set to an invalid value */
  rv = -2;
  /* have kernel fds */
  if (new_nfds)
    rv = libc_select (new_nfds, __readfds,
		      __writefds, __exceptfds, __timeout);

  if (new_nfds && rv == -1)
    {
      /* on error, the file descriptor sets are unmodified */
      if (__readfds)
	*__readfds = saved_readfds;
      if (__writefds)
	*__writefds = saved_writefds;
      if (__exceptfds)
	*__exceptfds = saved_exceptfds;
      return rv;
    }
  else if ((new_nfds && rv != -1) || (rv == -2))
    {
      /* restore vcom fds */
      nfd = vcom_fd_set (__nfds,
			 &new_nfds,
			 __readfds,
			 __writefds,
			 __exceptfds,
			 &saved_readfds, &saved_writefds, &saved_exceptfds);
      rv = nfd;
    }

  if (VCOM_DEBUG > 0)
    fprintf (stderr, "[%d] select: " "'%04d'='%04d'\n", pid, rv, __nfds);
  return rv;
}

int
select (int __nfds, fd_set * __restrict __readfds,
	fd_set * __restrict __writefds,
	fd_set * __restrict __exceptfds, struct timeval *__restrict __timeout)
{
  int rv = 0;
  pid_t pid = getpid ();

  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] select1: " "'%04d'='%04d'\n", pid, rv, __nfds);
  rv = vcom_select (__nfds, __readfds, __writefds, __exceptfds, __timeout);
  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] select2: " "'%04d'='%04d'\n", pid, rv, __nfds);
  if (rv < 0)
    {
      errno = -rv;
      return -1;
    }
  return rv;
}

#ifdef __USE_XOPEN2K
/*
 * Same as above only that the TIMEOUT value is given with higher
 * resolution and a sigmask which is been set temporarily.  This
 * version should be used.
 *
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
int
vcom_pselect (int __nfds, fd_set * __restrict __readfds,
	      fd_set * __restrict __writefds,
	      fd_set * __restrict __exceptfds,
	      const struct timespec *__restrict __timeout,
	      const __sigset_t * __restrict __sigmask)
{
  int fd;
  int vcom_nfds = 0;

  for (fd = 0; fd < __nfds; fd++)
    {
      if (__readfds && FD_ISSET (fd, __readfds))
	{
	  if (is_vcom_socket_fd (fd))
	    {
	      vcom_nfds++;
	    }
	}

      if (__writefds && FD_ISSET (fd, __writefds))
	{
	  if (is_vcom_socket_fd (fd))
	    {
	      vcom_nfds++;
	    }
	}
      if (__exceptfds && FD_ISSET (fd, __exceptfds))
	{
	  if (is_vcom_socket_fd (fd))
	    {
	      FD_CLR (fd, __exceptfds);
	    }
	}
    }
  return vcom_nfds;
}

int
pselect (int __nfds, fd_set * __restrict __readfds,
	 fd_set * __restrict __writefds,
	 fd_set * __restrict __exceptfds,
	 const struct timespec *__restrict __timeout,
	 const __sigset_t * __restrict __sigmask)
{
  int rv;
  int new_nfds = 0;
  int nfd = 0;
  pid_t pid = getpid ();

  fd_set saved_readfds;
  fd_set saved_writefds;
  fd_set saved_exceptfds;

  /* validate __nfds */
  if (__nfds < 0)
    {
      errno = EINVAL;
      return -1;
    }

  /* validate __timeout */
  if (__timeout)
    {
      /* validate tv_sec */
      /* bogus */
      if (__timeout->tv_sec < 0 || __timeout->tv_nsec < 0)
	{
	  errno = EINVAL;
	  return -1;
	}

      /* validate tv_usec */
      /* TBD: */
    }

  /* init saved fds */
  if (__readfds)
    {
      saved_readfds = *__readfds;
      /*
         memcpy (&saved_readfds, __readfds, sizeof (*__readfds));
       */
    }
  else
    {
      FD_ZERO (&saved_readfds);
    }

  if (__writefds)
    {
      saved_writefds = *__writefds;
      /*
         memcpy (&saved_writefds, __writefds, sizeof (*__writefds));
       */

    }
  else
    {
      FD_ZERO (&saved_writefds);
    }

  if (__exceptfds)
    {
      saved_exceptfds = *__exceptfds;
      /*
         memcpy (&saved_exceptfds, __exceptfds, sizeof (*__exceptfds));
       */

    }
  else
    {
      FD_ZERO (&saved_exceptfds);
    }

  /* clear vcom fds */
  nfd = vcom_fd_clear (__nfds, &new_nfds, __readfds, __writefds, __exceptfds);

  /* set to an invalid value */
  rv = -2;
  if (new_nfds)
    rv = libc_pselect (new_nfds,
		       __readfds,
		       __writefds, __exceptfds, __timeout, __sigmask);

  if (new_nfds && rv == -1)
    {
      /* on error, the file descriptor sets are unmodified */
      if (__readfds)
	*__readfds = saved_readfds;
      if (__writefds)
	*__writefds = saved_writefds;
      if (__exceptfds)
	*__exceptfds = saved_exceptfds;
      return rv;
    }
  else if ((new_nfds && rv != -1) || (rv == -2))
    {
      /* restore vcom fds */
      nfd = vcom_fd_set (__nfds,
			 &new_nfds,
			 __readfds,
			 __writefds,
			 __exceptfds,
			 &saved_readfds, &saved_writefds, &saved_exceptfds);
      rv = nfd;
    }

  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] pselect: " "'%04d'='%04d'\n", pid, rv, __nfds);
  return rv;
}
#endif

/*
 *
 * Socket specific glibc api
 *
 */

/* Create a new socket of type TYPE in domain DOMAIN, using
 * protocol PROTOCOL.  If PROTOCOL is zero, one is chosen
 * automatically. Returns a file descriptor for the new socket,
 * or -1 for errors.
 * RETURN:  a valid file descriptor for the new socket,
 * or -1 for errors.
 * */

int
vcom_socket (int __domain, int __type, int __protocol)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_socket (__domain, __type, __protocol);
}

int
socket (int __domain, int __type, int __protocol)
{
  int rv;
  pid_t pid = getpid ();
  pthread_t tid = pthread_self ();

  /* handle domains implemented by vpp */
  switch (__domain)
    {
    case AF_INET:
    case AF_INET6:
      /* handle types implemented by vpp */
      switch (__type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
	{
	case SOCK_STREAM:
	case SOCK_DGRAM:
	  if (VCOM_DEBUG > 0)
	    vcom_socket_main_show ();
	  rv = vcom_socket (__domain, __type, __protocol);
	  if (VCOM_DEBUG > 0)
	    fprintf (stderr,
		     "[%d][%lu (0x%lx)] socket: "
		     "'%04d'= D='%04d', T='%04d', P='%04d'\n",
		     pid, (unsigned long) tid, (unsigned long) tid,
		     rv, __domain, __type, __protocol);
	  if (VCOM_DEBUG > 0)
	    vcom_socket_main_show ();
	  if (rv < 0)
	    {
	      errno = -rv;
	      return -1;
	    }
	  return rv;
	  break;

	default:
	  goto CALL_GLIBC_SOCKET_API;
	  break;
	}

      break;

    default:
      goto CALL_GLIBC_SOCKET_API;
      break;
    }

CALL_GLIBC_SOCKET_API:
  return libc_socket (__domain, __type, __protocol);
}

/*
 * Create two new sockets, of type TYPE in domain DOMAIN and using
 * protocol PROTOCOL, which are connected to each other, and put file
 * descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
 * one will be chosen automatically.
 * Returns 0 on success, -1 for errors.
 * */
int
vcom_socketpair (int __domain, int __type, int __protocol, int __fds[2])
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_socketpair (__domain, __type, __protocol, __fds);
}

int
socketpair (int __domain, int __type, int __protocol, int __fds[2])
{
  int rv;
  pid_t pid = getpid ();

  /* handle domains implemented by vpp */
  switch (__domain)
    {
    case AF_INET:
    case AF_INET6:
      /* handle types implemented by vpp */
      switch (__type)
	{
	case SOCK_STREAM:
	case SOCK_DGRAM:
	  rv = vcom_socketpair (__domain, __type, __protocol, __fds);
	  if (VCOM_DEBUG > 0)
	    fprintf (stderr,
		     "[%d] socketpair: "
		     "'%04d'= D='%04d', T='%04d', P='%04d'\n",
		     pid, rv, __domain, __type, __protocol);
	  if (rv < 0)
	    {
	      errno = -rv;
	      return -1;
	    }
	  return 0;
	  break;

	default:
	  goto CALL_GLIBC_SOCKET_API;
	  break;
	}

      break;

    default:
      goto CALL_GLIBC_SOCKET_API;
      break;
    }

CALL_GLIBC_SOCKET_API:
  return libc_socketpair (__domain, __type, __protocol, __fds);
}

/*
 * Give the socket FD the local address ADDR
 * (which is LEN bytes long).
 * */
int
vcom_bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
  int rv;

  if (vcom_init () != 0)
    {
      return -1;
    }

  /* validate __len */
  switch (__addr->sa_family)
    {
    case AF_INET:
      if (__len != sizeof (struct sockaddr_in))
	return -EINVAL;
      break;
    case AF_INET6:
      if (__len != sizeof (struct sockaddr_in6))
	return -EINVAL;
      break;

    default:
      return -1;
      break;
    }

  /* handle domains implemented by vpp */
  switch (__addr->sa_family)
    {
    case AF_INET:
    case AF_INET6:
      rv = vcom_socket_bind (__fd, __addr, __len);
      return rv;
      break;

    default:
      return -1;
      break;
    }

  return -1;
}

int
bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {

      rv = vcom_bind (__fd, __addr, __len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] bind: "
		 "'%04d'='%04d', '%p', '%04d'\n",
		 pid, rv, __fd, __addr, __len);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_bind (__fd, __addr, __len);
}

/*
 * Put the local address of FD into *ADDR and its length in *LEN.
 * */
int
vcom_getsockname (int __fd, __SOCKADDR_ARG __addr,
		  socklen_t * __restrict __len)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_getsockname (__fd, __addr, __len);
}

int
getsockname (int __fd, __SOCKADDR_ARG __addr, socklen_t * __restrict __len)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_getsockname (__fd, __addr, __len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] getsockname: "
		 "'%04d'='%04d', '%p', '%p'\n", pid, rv, __fd, __addr, __len);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_getsockname (__fd, __addr, __len);
}

/*
 * Open a connection on socket FD to peer at ADDR
 * (which LEN bytes long). For connectionless socket types, just set
 * the default address to send to and the only address from which to
 * accept transmissions. Return 0 on success, -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
int
vcom_connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
  int rv = -1;

  if (vcom_init () != 0)
    {
      return -1;
    }

  /* validate __len */
  switch (__addr->sa_family)
    {
    case AF_INET:
      if (__len != INET_ADDRSTRLEN)
	return -1;
      break;
    case AF_INET6:
      if (__len != INET6_ADDRSTRLEN)
	return -1;
      break;

    default:
      return -1;
      break;
    }

  /* handle domains implemented by vpp */
  switch (__addr->sa_family)
    {
    case AF_INET:
    case AF_INET6:
      rv = vcom_socket_connect (__fd, __addr, __len);
      break;

    default:
      return -1;
      break;
    }

  return rv;
}

int
connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
  int rv;
  pid_t pid = getpid ();
  pthread_t tid = pthread_self ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_connect (__fd, __addr, __len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] connect: "
		 "'%04d'='%04d', '%p', '%04d'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 rv, __fd, __addr, __len);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }

  return libc_connect (__fd, __addr, __len);
}

/*
 * Put the address of the peer connected to socket FD into *ADDR
 * (which is *LEN bytes long), and its actual length into *LEN.
 * */
int
vcom_getpeername (int __fd, __SOCKADDR_ARG __addr,
		  socklen_t * __restrict __len)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_getpeername (__fd, __addr, __len);
}

int
getpeername (int __fd, __SOCKADDR_ARG __addr, socklen_t * __restrict __len)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_getpeername (__fd, __addr, __len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] getpeername: "
		 "'%04d'='%04d', '%p', '%p'\n", pid, rv, __fd, __addr, __len);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_getpeername (__fd, __addr, __len);
}

/*
 * Send N bytes of BUF to socket FD.  Returns the number sent or -1.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
ssize_t
vcom_send (int __fd, const void *__buf, size_t __n, int __flags)
{

  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_send (__fd, (void *) __buf, (int) __n, __flags);
}

ssize_t
send (int __fd, const void *__buf, size_t __n, int __flags)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_send (__fd, __buf, __n, __flags);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] send: "
		 "'%04d'='%04d', '%p', '%04d', '%04x'\n",
		 pid, (int) size, __fd, __buf, (int) __n, __flags);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_send (__fd, __buf, __n, __flags);
}

/*
 * Read N bytes into BUF from socket FD.
 * Returns the number read or -1 for errors.
 * This function is a cancellation point and therefore not marked
 *  with __THROW.
 *  */
ssize_t
vcom_recv (int __fd, void *__buf, size_t __n, int __flags)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_recv (__fd, __buf, __n, __flags);
}

ssize_t
recv (int __fd, void *__buf, size_t __n, int __flags)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_recv (__fd, __buf, __n, __flags);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] recv: "
		 "'%04d'='%04d', '%p', '%04d', '%04x'\n",
		 pid, (int) size, __fd, __buf, (int) __n, __flags);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_recv (__fd, __buf, __n, __flags);
}

/*
 * Send N bytes of BUF on socket FD to peer at address ADDR (which is
 * ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
ssize_t
vcom_sendto (int __fd, const void *__buf, size_t __n, int __flags,
	     __CONST_SOCKADDR_ARG __addr, socklen_t __addr_len)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_sendto (__fd, __buf, __n, __flags, __addr, __addr_len);
}

ssize_t
sendto (int __fd, const void *__buf, size_t __n, int __flags,
	__CONST_SOCKADDR_ARG __addr, socklen_t __addr_len)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_sendto (__fd, __buf, __n, __flags, __addr, __addr_len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] sendto: "
		 "'%04d'='%04d', '%p', '%04d', '%04x', "
		 "'%p', '%04d'\n",
		 pid, (int) size, __fd, __buf, (int) __n, __flags,
		 __addr, __addr_len);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_sendto (__fd, __buf, __n, __flags, __addr, __addr_len);
}

/*
 * Read N bytes into BUF through socket FD.
 * If ADDR is not NULL, fill in *ADDR_LEN bytes of it with the
 * address of the sender, and store the actual size of the address
 * in *ADDR_LEN.
 * Returns the number of bytes read or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
ssize_t
vcom_recvfrom (int __fd, void *__restrict __buf, size_t __n,
	       int __flags,
	       __SOCKADDR_ARG __addr, socklen_t * __restrict __addr_len)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_recvfrom (__fd, __buf, __n, __flags, __addr, __addr_len);
}

ssize_t
recvfrom (int __fd, void *__restrict __buf, size_t __n,
	  int __flags,
	  __SOCKADDR_ARG __addr, socklen_t * __restrict __addr_len)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_recvfrom (__fd, __buf, __n, __flags, __addr, __addr_len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] recvfrom: "
		 "'%04d'='%04d', '%p', '%04d', '%04x', "
		 "'%p', '%p'\n",
		 pid, (int) size, __fd, __buf, (int) __n, __flags,
		 __addr, __addr_len);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_recvfrom (__fd, __buf, __n, __flags, __addr, __addr_len);
}

/*
 * Send a message described MESSAGE on socket FD.
 * Returns the number of bytes sent, or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
ssize_t
vcom_sendmsg (int __fd, const struct msghdr * __message, int __flags)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_sendmsg (__fd, __message, __flags);
}

ssize_t
sendmsg (int __fd, const struct msghdr * __message, int __flags)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_sendmsg (__fd, __message, __flags);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] sendmsg: "
		 "'%04d'='%04d', '%p', '%04x'\n",
		 pid, (int) size, __fd, __message, __flags);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_sendmsg (__fd, __message, __flags);
}

#ifdef __USE_GNU
/*
 * Send a VLEN messages as described by VMESSAGES to socket FD.
 * Returns the number of datagrams successfully written
 * or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
int
vcom_sendmmsg (int __fd, struct mmsghdr *__vmessages,
	       unsigned int __vlen, int __flags)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_sendmmsg (__fd, __message, __vlen, __flags);
}

int
sendmmsg (int __fd, struct mmsghdr *__vmessages,
	  unsigned int __vlen, int __flags)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_sendmmsg (__fd, __message, __vlen, __flags);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] sendmmsg: "
		 "'%04d'='%04d', '%p', '%04d', '%04x'\n",
		 pid, (int) size, __fd, __vmessages, __vlen, __flags);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_sendmmsg (__fd, __message, __vlen, __flags);
}

#endif

/*
 * Receive a message as described by MESSAGE from socket FD.
 * Returns the number of bytes read or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
ssize_t
vcom_recvmsg (int __fd, struct msghdr * __message, int __flags)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_recvmsg (__fd, __message, __flags);
}

ssize_t
recvmsg (int __fd, struct msghdr * __message, int __flags)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_recvmsg (__fd, __message, __flags);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] recvmsg: "
		 "'%04d'='%04d', '%p', '%04x'\n",
		 pid, (int) size, __fd, __message, __flags);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_recvmsg (__fd, __message, __flags);
}

#ifdef __USE_GNU
/*
 * Receive up to VLEN messages as described by VMESSAGES from socket FD.
 * Returns the number of messages received or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
int
vcom_recvmmsg (int __fd, struct mmsghdr *__vmessages,
	       unsigned int __vlen, int __flags, struct timespec *__tmo)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_recvmmsg (__fd, __message, __vlen, __flags, __tmo);
}

int
recvmmsg (int __fd, struct mmsghdr *__vmessages,
	  unsigned int __vlen, int __flags, struct timespec *__tmo)
{
  ssize_t size;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      size = vcom_recvmmsg (__fd, __message, __vlen, __flags, __tmo);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] recvmmsg: "
		 "'%04d'='%04d', '%p', "
		 "'%04d', '%04x', '%p'\n",
		 pid, (int) size, __fd, __vmessages, __vlen, __flags, __tmo);
      if (size < 0)
	{
	  errno = -size;
	  return -1;
	}
      return size;
    }
  return libc_recvmmsg (__fd, __message, __vlen, __flags, __tmo);
}

#endif

/*
 * Put the current value for socket FD's option OPTNAME
 * at protocol level LEVEL into OPTVAL (which is *OPTLEN bytes long),
 * and set *OPTLEN to the value's actual length.
 * Returns 0 on success, -1 for errors.
 * */
int
vcom_getsockopt (int __fd, int __level, int __optname,
		 void *__restrict __optval, socklen_t * __restrict __optlen)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_getsockopt (__fd, __level, __optname,
				 __optval, __optlen);
}

int
getsockopt (int __fd, int __level, int __optname,
	    void *__restrict __optval, socklen_t * __restrict __optlen)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_getsockopt (__fd, __level, __optname, __optval, __optlen);
      if (VCOM_DEBUG > 2)
	fprintf (stderr,
		 "[%d] getsockopt: "
		 "'%04d'='%04d', '%04d', '%04d', "
		 "'%p', '%p'\n",
		 pid, rv, __fd, __level, __optname, __optval, __optlen);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_getsockopt (__fd, __level, __optname, __optval, __optlen);
}

/*
 * Set socket FD's option OPTNAME at protocol level LEVEL
 * to *OPTVAL (which is OPTLEN bytes long).
 * Returns 0 on success, -1 for errors.
 * */
int
vcom_setsockopt (int __fd, int __level, int __optname,
		 const void *__optval, socklen_t __optlen)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_setsockopt (__fd, __level, __optname,
				 __optval, __optlen);
}

int
setsockopt (int __fd, int __level, int __optname,
	    const void *__optval, socklen_t __optlen)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_setsockopt (__fd, __level, __optname, __optval, __optlen);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] setsockopt: "
		 "'%04d'='%04d', '%04d', '%04d', "
		 "'%p', '%04d'\n",
		 pid, rv, __fd, __level, __optname, __optval, __optlen);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_setsockopt (__fd, __level, __optname, __optval, __optlen);
}

/*
 * Prepare to accept connections on socket FD.
 * N connection requests will be queued before further
 * requests are refused.
 * Returns 0 on success, -1 for errors.
 * */
int
vcom_listen (int __fd, int __n)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_listen (__fd, __n);
}

int
listen (int __fd, int __n)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_listen (__fd, __n);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] listen: "
		 "'%04d'='%04d', '%04d'\n", pid, rv, __fd, __n);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_listen (__fd, __n);
}

/*
 * Await a connection on socket FD.
 * When a connection arrives, open a new socket to communicate
 * with it, set *ADDR (which is *ADDR_LEN bytes long) to the address
 * of the connecting peer and *ADDR_LEN to the address's actual
 * length, and return the new socket's descriptor, or -1 for errors.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
int
vcom_accept (int __fd, __SOCKADDR_ARG __addr,
	     socklen_t * __restrict __addr_len)
{

  if (vcom_init () != 0)
    {
      return -1;
    }
  return vcom_socket_accept (__fd, __addr, __addr_len);
}

int
accept (int __fd, __SOCKADDR_ARG __addr, socklen_t * __restrict __addr_len)
{
  int rv = -1;
  pid_t pid = getpid ();
  pthread_t tid = pthread_self ();

  if (is_vcom_socket_fd (__fd))
    {
      if (VCOM_DEBUG > 0)
	vcom_socket_main_show ();
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] accept1: "
		 "'%04d'='%04d', '%p', '%p'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 rv, __fd, __addr, __addr_len);
      rv = vcom_accept (__fd, __addr, __addr_len);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d][%lu (0x%lx)] accept2: "
		 "'%04d'='%04d', '%p', '%p'\n",
		 pid, (unsigned long) tid, (unsigned long) tid,
		 rv, __fd, __addr, __addr_len);
      if (VCOM_DEBUG > 0)
	vcom_socket_main_show ();
      if (rv < 0)
	{
	  errno = -rv;
	  return -1;
	}
      return rv;
    }
  return libc_accept (__fd, __addr, __addr_len);
}

/*
 * Similar to 'accept' but takes an additional parameter to specify
 * flags.
 * This function is a cancellation point and therefore not marked
 * with __THROW.
 * */
int
vcom_accept4 (int __fd, __SOCKADDR_ARG __addr,
	      socklen_t * __restrict __addr_len, int __flags)
{

  if (vcom_init () != 0)
    {
      return -1;
    }

  return vcom_socket_accept4 (__fd, __addr, __addr_len, __flags);
}

int
accept4 (int __fd, __SOCKADDR_ARG __addr,
	 socklen_t * __restrict __addr_len, int __flags)
{
  int rv = 0;
  pid_t pid = getpid ();

  fprintf (stderr,
	   "[%d] accept4: in the beginning... "
	   "'%04d'='%04d', '%p', '%p', '%04x'\n",
	   pid, rv, __fd, __addr, __addr_len, __flags);

  if (is_vcom_socket_fd (__fd))
    {
      if (VCOM_DEBUG > 0)
	vcom_socket_main_show ();
      rv = vcom_accept4 (__fd, __addr, __addr_len, __flags);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] accept4: VCL "
		 "'%04d'='%04d', '%p', '%p', '%04x'\n",
		 pid, rv, __fd, __addr, __addr_len, __flags);
      if (VCOM_DEBUG > 0)
	vcom_socket_main_show ();
      if (rv < 0)
	{
	  errno = -rv;
	  return -1;
	}
      return rv;
    }
  fprintf (stderr,
	   "[%d] accept4: libc "
	   "'%04d'='%04d', '%p', '%p', '%04x'\n",
	   pid, rv, __fd, __addr, __addr_len, __flags);

  return libc_accept4 (__fd, __addr, __addr_len, __flags);
}

/*
 * Shut down all or part of the connection open on socket FD.
 * HOW determines what to shut down:
 *   SHUT_RD   = No more receptions;
 *   SHUT_WR   = No more transmissions;
 *   SHUT_RDWR = No more receptions or transmissions.
 * Returns 0 on success, -1 for errors.
 * */
int
vcom_shutdown (int __fd, int __how)
{
  if (vcom_init () != 0)
    {
      return -1;
    }
  return vcom_socket_shutdown (__fd, __how);
}

int
shutdown (int __fd, int __how)
{
  int rv;
  pid_t pid = getpid ();

  if (is_vcom_socket_fd (__fd))
    {
      rv = vcom_shutdown (__fd, __how);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] shutdown: "
		 "'%04d'='%04d', '%04d'\n", pid, rv, __fd, __how);
      if (rv != 0)
	{
	  errno = -rv;
	  return -1;
	}
      return 0;
    }
  return libc_shutdown (__fd, __how);
}

int
vcom_epoll_create (int __size)
{

  if (vcom_init () != 0)
    {
      return -1;
    }

  if (__size <= 0)
    {
      return -EINVAL;
    }

  /* __size argument is ignored "thereafter" */
  return vcom_epoll_create1 (0);
}

/*
 * __size argument is ignored, but must be greater than zero
 */
int
epoll_create (int __size)
{
  int rv = 0;
  pid_t pid = getpid ();

  rv = vcom_epoll_create (__size);
  if (VCOM_DEBUG > 0)
    fprintf (stderr,
	     "[%d] epoll_create: " "'%04d'='%04d'\n", pid, rv, __size);
  if (rv < 0)
    {
      errno = -rv;
      return -1;
    }
  return rv;
}

int
vcom_epoll_create1 (int __flags)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  if (__flags < 0)
    {
      return -EINVAL;
    }
  if (__flags & ~EPOLL_CLOEXEC)
    {
      return -EINVAL;
    }
  /* __flags can be either zero or EPOLL_CLOEXEC */
  /* implementation */
  return vcom_socket_epoll_create1 (__flags);
}

/*
 * __flags can be either zero or EPOLL_CLOEXEC
 * */
int
epoll_create1 (int __flags)
{
  int rv = 0;
  pid_t pid = getpid ();

  rv = vcom_epoll_create1 (__flags);
  if (VCOM_DEBUG > 0)
    fprintf (stderr,
	     "[%d] epoll_create: " "'%04d'='%08x'\n", pid, rv, __flags);
  if (rv < 0)
    {
      errno = -rv;
      return -1;
    }
  return rv;
}

static inline int
ep_op_has_event (int op)
{
  return op != EPOLL_CTL_DEL;
}

int
vcom_epoll_ctl (int __epfd, int __op, int __fd, struct epoll_event *__event)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  /*
   * the requested operation __op is not supported
   * by this interface */
  if (!((__op == EPOLL_CTL_ADD) ||
	(__op == EPOLL_CTL_MOD) || (__op == EPOLL_CTL_DEL)))
    {
      return -EINVAL;
    }

  /* op is ADD or MOD but event parameter is NULL */
  if ((ep_op_has_event (__op) && !__event))
    {
      return -EFAULT;
    }

  /* fd is same as epfd */
  /* do not permit adding an epoll file descriptor inside itself */
  if (__epfd == __fd)
    {
      return -EINVAL;
    }

  /* implementation */
  return vcom_socket_epoll_ctl (__epfd, __op, __fd, __event);
}

/*
 * implement the controller interface for epoll
 * that enables the insertion/removal/change of
 * file descriptors inside the interest set.
 */
int
epoll_ctl (int __epfd, int __op, int __fd, struct epoll_event *__event)
{
  int rv;
  pid_t pid = getpid ();

  rv = vcom_epoll_ctl (__epfd, __op, __fd, __event);
  if (VCOM_DEBUG > 0)
    fprintf (stderr,
	     "[%d] epoll_ctl: "
	     "'%04d'='%04d', '%04d', '%04d'\n", pid, rv, __epfd, __op, __fd);
  if (rv != 0)
    {
      errno = -rv;
      return -1;
    }
  return 0;
}

int
epoll_wait (int __epfd, struct epoll_event *__events,
	    int __maxevents, int __timeout)
{
  int rv;
  pid_t pid = getpid ();

  if (__maxevents <= 0 || __maxevents > EP_MAX_EVENTS)
    {
      fprintf (stderr, "[%d] ERROR: epoll_wait() invalid maxevents %d\n",
	       pid, __maxevents);
      errno = EINVAL;
      return -1;
    }

  rv =
    vcom_socket_epoll_pwait (__epfd, __events, __maxevents, __timeout, NULL);
  if (VCOM_DEBUG > 1)
    fprintf (stderr,
	     "[%d] epoll_wait: "
	     "'%04d'='%04d', '%p', "
	     "'%04d', '%04d'\n",
	     pid, rv, __epfd, __events, __maxevents, __timeout);
  if (rv < 0)
    {
      errno = -rv;
      return -1;
    }
  return rv;
}


int
epoll_pwait (int __epfd, struct epoll_event *__events,
	     int __maxevents, int __timeout, const __sigset_t * __ss)
{
  int rv;
  pid_t pid = getpid ();

  if (__maxevents <= 0 || __maxevents > EP_MAX_EVENTS)
    {
      errno = EINVAL;
      return -1;
    }

  if (is_vcom_epfd (__epfd))
    {
      rv =
	vcom_socket_epoll_pwait (__epfd, __events, __maxevents, __timeout,
				 __ss);
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] epoll_pwait: "
		 "'%04d'='%04d', '%p', "
		 "'%04d', '%04d', "
		 "'%p'\n",
		 pid, rv, __epfd, __events, __maxevents, __timeout, __ss);
      if (rv < 0)
	{
	  errno = -rv;
	  return -1;
	}
      return rv;
    }
  else
    {
      errno = EINVAL;
      return -1;
    }

  return 0;
}

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
   an event to occur; if TIMEOUT is -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */

int
vcom_poll (struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
  int rv = 0;
  pid_t pid = getpid ();

  struct rlimit nofile_limit;
  struct pollfd vcom_fds[MAX_POLL_NFDS_DEFAULT];
  nfds_t fds_idx = 0;

  /* actual set of file descriptors to be monitored */
  nfds_t libc_nfds = 0;
  nfds_t vcom_nfds = 0;

  /* ready file descriptors
   *
   * number of structures which have nonzero revents  fields
   * in other words, descriptors  with events or errors reported.
   * */
  /* after call to libc_poll () */
  int rlibc_nfds = 0;
  /* after call to vcom_socket_poll () */
  int rvcom_nfds = 0;


  /* timeout value in units of timespec */
  struct timespec timeout_ts;
  struct timespec start_time, now, end_time;


  /* get start_time */
  rv = clock_gettime (CLOCK_MONOTONIC, &start_time);
  if (rv == -1)
    {
      rv = -errno;
      goto poll_done;
    }

  /* set timeout_ts & end_time */
  if (__timeout >= 0)
    {
      /* set timeout_ts */
      timeout_ts.tv_sec = __timeout / MSEC_PER_SEC;
      timeout_ts.tv_nsec = (__timeout % MSEC_PER_SEC) * NSEC_PER_MSEC;
      set_normalized_timespec (&timeout_ts,
			       timeout_ts.tv_sec, timeout_ts.tv_nsec);
      /* set end_time */
      if (__timeout)
	{
	  end_time = timespec_add (start_time, timeout_ts);
	}
      else
	{
	  end_time = start_time;
	}
    }

  if (vcom_init () != 0)
    {
      rv = -1;
      goto poll_done;
    }

  /* validate __fds */
  if (!__fds)
    {
      rv = -EFAULT;
      goto poll_done;
    }

  /* validate __nfds */
  /*TBD: call getrlimit once when vcl-ldpreload library is init */
  rv = getrlimit (RLIMIT_NOFILE, &nofile_limit);
  if (rv != 0)
    {
      rv = -errno;
      goto poll_done;
    }
  if (__nfds >= nofile_limit.rlim_cur)
    {
      rv = -EINVAL;
      goto poll_done;
    }

  /*
   * for the POC, it's fair to assume that nfds is less than 1024
   * */
  if (__nfds >= MAX_POLL_NFDS_DEFAULT)
    {
      rv = -EINVAL;
      goto poll_done;
    }

  /* set revents field (output parameter)
   * to zero
   * */
  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      __fds[fds_idx].revents = 0;
    }

#if 0
  /* set revents field (output parameter)
   * to zero for user ignored fds
   * */
  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /*
       * if negative fd, ignore events field
       * and set output parameter (revents field) to zero */
      if (__fds[fds_idx].fd < 0)
	{
	  __fds[fds_idx].revents = 0;
	}
    }
#endif

  /*
   * 00. prepare __fds and vcom_fds for polling
   *     copy __fds to vcom_fds
   * 01. negate all except libc fds in __fds,
   *     ignore user negated fds
   * 02. negate all except vcom_fds in vocm fds,
   *     ignore user negated fds
   *     ignore fd 0 by setting it to negative number
   * */
  memcpy (vcom_fds, __fds, sizeof (*__fds) * __nfds);
  libc_nfds = 0;
  vcom_nfds = 0;
  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds */
      if (__fds[fds_idx].fd < 0)
	{
	  continue;
	}

      /*
       * 00. ignore vcom fds in __fds
       * 01. ignore libc fds in vcom_fds,
       *     ignore fd 0 by setting it to negative number.
       *     as fd 0 cannot be ignored.
       */
      if (is_vcom_socket_fd (__fds[fds_idx].fd) ||
	  is_vcom_epfd (__fds[fds_idx].fd))
	{
	  __fds[fds_idx].fd = -__fds[fds_idx].fd;
	  vcom_nfds++;
	}
      else
	{
	  libc_nfds++;
	  /* ignore fd 0 by setting it to negative number */
	  if (!vcom_fds[fds_idx].fd)
	    {
	      vcom_fds[fds_idx].fd = -1;
	    }
	  vcom_fds[fds_idx].fd = -vcom_fds[fds_idx].fd;
	}
    }

  /*
   * polling loop
   *
   * poll on libc fds and vcom fds
   *
   * specifying a timeout of zero causes libc_poll() and
   * vcom_socket_poll() to return immediately, even if no
   * file descriptors are ready
   * */
  do
    {
      rlibc_nfds = 0;
      rvcom_nfds = 0;

      /*
       * timeout parameter for libc_poll () set to zero
       * to poll on libc fds
       * */

      /* poll on libc fds */
      if (libc_nfds)
	{
	  /*
	   * a timeout of zero causes libc_poll()
	   * to return immediately
	   * */
	  rlibc_nfds = libc_poll (__fds, __nfds, 0);
	  if (VCOM_DEBUG > 2)
	    fprintf (stderr,
		     "[%d] poll libc: "
		     "'%04d'='%08lu'\n", pid, rlibc_nfds, __nfds);

	  if (rlibc_nfds < 0)
	    {
	      rv = -errno;
	      goto poll_done_update_nfds;
	    }
	}

      /*
       * timeout parameter for vcom_socket_poll () set to zero
       * to poll on vcom fds
       * */

      /* poll on vcom fds */
      if (vcom_nfds)
	{
	  /*
	   * a timeout of zero causes vcom_socket_poll()
	   * to return immediately
	   * */
	  rvcom_nfds = vcom_socket_poll (vcom_fds, __nfds, 0);
	  if (VCOM_DEBUG > 2)
	    fprintf (stderr,
		     "[%d] poll vcom: "
		     "'%04d'='%08lu'\n", pid, rvcom_nfds, __nfds);
	  if (rvcom_nfds < 0)
	    {
	      rv = rvcom_nfds;
	      goto poll_done_update_nfds;
	    }
	}

      /* check if any file descriptors changed status */
      if ((libc_nfds && rlibc_nfds > 0) || (vcom_nfds && rvcom_nfds > 0))
	{
	  /* something interesting happened */
	  rv = rlibc_nfds + rvcom_nfds;
	  goto poll_done_update_nfds;
	}

      rv = clock_gettime (CLOCK_MONOTONIC, &now);
      if (rv == -1)
	{
	  rv = -errno;
	  goto poll_done_update_nfds;
	}
    }

  /* block indefinitely || timeout elapsed  */
  while ((__timeout < 0) || timespec_compare (&now, &end_time) < 0);

  /* timeout expired before anything interesting happened */
  rv = 0;

poll_done_update_nfds:
  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds in vcom_fds
       * 00. user negated fds
       * 01. libc fds
       * */
      if (vcom_fds[fds_idx].fd < 0)
	{
	  continue;
	}

      /* from here on handle positive vcom fds */
      /*
       * restore vcom fds to positive number in __fds
       * and update revents in __fds with the events
       * that actually occurred in vcom fds
       * */
      __fds[fds_idx].fd = -__fds[fds_idx].fd;
      if (rvcom_nfds)
	{
	  __fds[fds_idx].revents = vcom_fds[fds_idx].revents;
	}
    }

poll_done:
  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] vpoll: " "'%04d'='%08lu'\n", pid, rv, __nfds);
  return rv;
}

/*
 * 00. The  field  __fds[i].fd contains a file descriptor for an
 *     open file.
 *     If this field is negative, then the corresponding
 *     events field is ignored and the revents field returns zero.
 *     The field __fds[i].events is an input parameter.
 *     The field __fds[i].revents is an output parameter.
 * 01. Specifying a negative value in  timeout
 *     means  an infinite timeout.
 *     Specifying a timeout of zero causes poll() to return
 *     immediately, even if no file descriptors are ready.
 *
 * NOTE: observed __nfds is less than 128 from kubecon strace files
 */


int
poll (struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
  int rv = 0;
  pid_t pid = getpid ();


  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] poll1: " "'%04d'='%08lu, %d, 0x%x'\n",
	     pid, rv, __nfds, __fds[0].fd, __fds[0].events);
  rv = vcom_poll (__fds, __nfds, __timeout);
  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] poll2: " "'%04d'='%08lu, %d, 0x%x'\n",
	     pid, rv, __nfds, __fds[0].fd, __fds[0].revents);
  if (rv < 0)
    {
      errno = -rv;
      return -1;
    }
  return rv;
}

#ifdef __USE_GNU
/* Like poll, but before waiting the threads signal mask is replaced
   with that specified in the fourth parameter.  For better usability,
   the timeout value is specified using a TIMESPEC object.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
int
vcom_ppoll (struct pollfd *__fds, nfds_t __nfds,
	    const struct timespec *__timeout, const __sigset_t * __ss)
{
  if (vcom_init () != 0)
    {
      return -1;
    }

  return -EOPNOTSUPP;
}

int
ppoll (struct pollfd *__fds, nfds_t __nfds,
       const struct timespec *__timeout, const __sigset_t * __ss)
{
  int rv = 0;

  errno = EOPNOTSUPP;
  rv = -1;
  return rv;
}
#endif

void CONSTRUCTOR_ATTRIBUTE vcom_constructor (void);

void DESTRUCTOR_ATTRIBUTE vcom_destructor (void);

void
vcom_constructor (void)
{
  pid_t pid = getpid ();

  swrap_constructor ();
  if (vcom_init () != 0)
    {
      printf ("\n[%d] vcom_constructor...failed!\n", pid);
    }
  else
    {
      printf ("\n[%d] vcom_constructor...done!\n", pid);
    }
}

/*
 * This function is called when the library is unloaded
 */
void
vcom_destructor (void)
{
  pid_t pid = getpid ();

  vcom_destroy ();
  swrap_destructor ();
  printf ("\n[%d] vcom_destructor...done!\n", pid);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
