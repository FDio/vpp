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
#include <netinet/tcp.h>

#include <vcl/ldp_socket_wrapper.h>
#include <vcl/ldp.h>
#include <sys/time.h>

#include <vcl/vcl_locked.h>
#include <vppinfra/time.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/lock.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>

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

#define LDP_MAX_NWORKERS 32

typedef struct ldp_worker_ctx_
{
  u8 *io_buffer;
  clib_time_t clib_time;

  /*
   * Select state
   */
  clib_bitmap_t *rd_bitmap;
  clib_bitmap_t *wr_bitmap;
  clib_bitmap_t *ex_bitmap;
  clib_bitmap_t *si_rd_bitmap;
  clib_bitmap_t *si_wr_bitmap;
  clib_bitmap_t *si_ex_bitmap;
  clib_bitmap_t *libc_rd_bitmap;
  clib_bitmap_t *libc_wr_bitmap;
  clib_bitmap_t *libc_ex_bitmap;
  u8 select_vcl;

  /*
   * Poll state
   */
  vcl_poll_t *vcl_poll;
  struct pollfd *libc_poll;
  u16 *libc_poll_idxs;

  /*
   * Epoll state
   */
  u8 epoll_wait_vcl;
  int vcl_mq_epfd;

} ldp_worker_ctx_t;

/* clib_bitmap_t, fd_mask and vcl_si_set are used interchangeably. Make sure
 * they are the same size */
STATIC_ASSERT (sizeof (clib_bitmap_t) == sizeof (fd_mask),
	       "ldp bitmap size mismatch");
STATIC_ASSERT (sizeof (vcl_si_set) == sizeof (fd_mask),
	       "ldp bitmap size mismatch");

typedef struct
{
  ldp_worker_ctx_t *workers;
  int init;
  char app_name[LDP_APP_NAME_MAX];
  u32 vlsh_bit_val;
  u32 vlsh_bit_mask;
  u32 debug;

  /** vcl needs next epoll_create to go to libc_epoll */
  u8 vcl_needs_real_epoll;
} ldp_main_t;

#define LDP_DEBUG ldp->debug

#define LDBG(_lvl, _fmt, _args...) 					\
  if (ldp->debug > _lvl)						\
    clib_warning ("ldp<%d>: " _fmt, getpid(), ##_args)

static ldp_main_t ldp_main = {
  .vlsh_bit_val = (1 << LDP_SID_BIT_MIN),
  .vlsh_bit_mask = (1 << LDP_SID_BIT_MIN) - 1,
  .debug = LDP_DEBUG_INIT,
};

static ldp_main_t *ldp = &ldp_main;

static inline ldp_worker_ctx_t *
ldp_worker_get_current (void)
{
  return (ldp->workers + vppcom_worker_index ());
}

/*
 * RETURN:  0 on success or -1 on error.
 * */
static inline void
ldp_set_app_name (char *app_name)
{
  int rv = snprintf (ldp->app_name, LDP_APP_NAME_MAX,
		     "ldp-%d-%s", getpid (), app_name);

  if (rv >= LDP_APP_NAME_MAX)
    app_name[LDP_APP_NAME_MAX - 1] = 0;
}

static inline char *
ldp_get_app_name ()
{
  if (ldp->app_name[0] == '\0')
    ldp_set_app_name ("app");

  return ldp->app_name;
}

static inline int
ldp_vlsh_to_fd (vls_handle_t vlsh)
{
  return (vlsh + ldp->vlsh_bit_val);
}

static inline vls_handle_t
ldp_fd_to_vlsh (int fd)
{
  if (fd < ldp->vlsh_bit_val)
    return VLS_INVALID_HANDLE;

  return (fd - ldp->vlsh_bit_val);
}

static inline int
ldp_init (void)
{
  ldp_worker_ctx_t *ldpw;
  int rv;

  if (PREDICT_TRUE (ldp->init))
    return 0;

  ldp->init = 1;
  ldp->vcl_needs_real_epoll = 1;
  rv = vls_app_create (ldp_get_app_name ());
  if (rv != VPPCOM_OK)
    {
      ldp->vcl_needs_real_epoll = 0;
      if (rv == VPPCOM_EEXIST)
	return 0;
      LDBG (2, "\nERROR: ldp_init: vppcom_app_create()"
	    " failed!  rv = %d (%s)\n", rv, vppcom_retval_str (rv));
      ldp->init = 0;
      return rv;
    }
  ldp->vcl_needs_real_epoll = 0;
  pool_alloc (ldp->workers, LDP_MAX_NWORKERS);
  ldpw = ldp_worker_get_current ();

  char *env_var_str = getenv (LDP_ENV_DEBUG);
  if (env_var_str)
    {
      u32 tmp;
      if (sscanf (env_var_str, "%u", &tmp) != 1)
	clib_warning ("LDP<%d>: WARNING: Invalid LDP debug level specified in"
		      " the env var " LDP_ENV_DEBUG " (%s)!", getpid (),
		      env_var_str);
      else
	{
	  ldp->debug = tmp;
	  LDBG (0, "configured LDP debug level (%u) from env var "
		LDP_ENV_DEBUG "!", ldp->debug);
	}
    }

  env_var_str = getenv (LDP_ENV_APP_NAME);
  if (env_var_str)
    {
      ldp_set_app_name (env_var_str);
      LDBG (0, "configured LDP app name (%s) from the env var "
	    LDP_ENV_APP_NAME "!", ldp->app_name);
    }

  env_var_str = getenv (LDP_ENV_SID_BIT);
  if (env_var_str)
    {
      u32 sb;
      if (sscanf (env_var_str, "%u", &sb) != 1)
	{
	  LDBG (0, "WARNING: Invalid LDP sid bit specified in the env var "
		LDP_ENV_SID_BIT " (%s)! sid bit value %d (0x%x)", env_var_str,
		ldp->vlsh_bit_val, ldp->vlsh_bit_val);
	}
      else if (sb < LDP_SID_BIT_MIN)
	{
	  ldp->vlsh_bit_val = (1 << LDP_SID_BIT_MIN);
	  ldp->vlsh_bit_mask = ldp->vlsh_bit_val - 1;

	  LDBG (0, "WARNING: LDP sid bit (%u) specified in the env var "
		LDP_ENV_SID_BIT " (%s) is too small. Using LDP_SID_BIT_MIN"
		" (%d)! sid bit value %d (0x%x)", sb, env_var_str,
		LDP_SID_BIT_MIN, ldp->vlsh_bit_val, ldp->vlsh_bit_val);
	}
      else if (sb > LDP_SID_BIT_MAX)
	{
	  ldp->vlsh_bit_val = (1 << LDP_SID_BIT_MAX);
	  ldp->vlsh_bit_mask = ldp->vlsh_bit_val - 1;

	  LDBG (0, "WARNING: LDP sid bit (%u) specified in the env var "
		LDP_ENV_SID_BIT " (%s) is too big. Using LDP_SID_BIT_MAX"
		" (%d)! sid bit value %d (0x%x)", sb, env_var_str,
		LDP_SID_BIT_MAX, ldp->vlsh_bit_val, ldp->vlsh_bit_val);
	}
      else
	{
	  ldp->vlsh_bit_val = (1 << sb);
	  ldp->vlsh_bit_mask = ldp->vlsh_bit_val - 1;

	  LDBG (0, "configured LDP sid bit (%u) from "
		LDP_ENV_SID_BIT "!  sid bit value %d (0x%x)", sb,
		ldp->vlsh_bit_val, ldp->vlsh_bit_val);
	}

      /* Make sure there are enough bits in the fd set for vcl sessions */
      if (ldp->vlsh_bit_val > FD_SETSIZE / 2)
	{
	  LDBG (0, "ERROR: LDP vlsh bit value %d > FD_SETSIZE/2 %d!",
		ldp->vlsh_bit_val, FD_SETSIZE / 2);
	  ldp->init = 0;
	  return -1;
	}
    }

  clib_time_init (&ldpw->clib_time);
  LDBG (0, "LDP initialization: done!");

  return 0;
}

int
close (int fd)
{
  vls_handle_t vlsh;
  int rv, epfd;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      epfd = vls_attr (vlsh, VPPCOM_ATTR_GET_LIBC_EPFD, 0, 0);
      if (epfd > 0)
	{
	  LDBG (0, "fd %d: calling libc_close: epfd %u", fd, epfd);

	  rv = libc_close (epfd);
	  if (rv < 0)
	    {
	      u32 size = sizeof (epfd);
	      epfd = 0;

	      (void) vls_attr (vlsh, VPPCOM_ATTR_SET_LIBC_EPFD, &epfd, &size);
	    }
	}
      else if (PREDICT_FALSE (epfd < 0))
	{
	  errno = -epfd;
	  rv = -1;
	  goto done;
	}

      LDBG (0, "fd %d: calling vls_close: vlsh %u", fd, vlsh);

      rv = vls_close (vlsh);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      LDBG (0, "fd %d: calling libc_close", fd);
      rv = libc_close (fd);
    }

done:
  return rv;
}

ssize_t
read (int fd, void *buf, size_t nbytes)
{
  vls_handle_t vlsh;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      size = vls_read (vlsh, buf, nbytes);
      if (size < 0)
	{
	  errno = -size;
	  size = -1;
	}
    }
  else
    {
      size = libc_read (fd, buf, nbytes);
    }

  return size;
}

ssize_t
readv (int fd, const struct iovec * iov, int iovcnt)
{
  int rv = 0, i, total = 0;
  vls_handle_t vlsh;
  ssize_t size = 0;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      do
	{
	  for (i = 0; i < iovcnt; ++i)
	    {
	      rv = vls_read (vlsh, iov[i].iov_base, iov[i].iov_len);
	      if (rv < 0)
		break;
	      else
		{
		  total += rv;
		  if (rv < iov[i].iov_len)
		    break;
		}
	    }
	}
      while ((rv >= 0) && (total == 0));

      if (rv < 0)
	{
	  errno = -rv;
	  size = -1;
	}
      else
	size = total;
    }
  else
    {
      size = libc_readv (fd, iov, iovcnt);
    }

  return size;
}

ssize_t
write (int fd, const void *buf, size_t nbytes)
{
  vls_handle_t vlsh;
  ssize_t size = 0;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      size = vls_write_msg (vlsh, (void *) buf, nbytes);
      if (size < 0)
	{
	  errno = -size;
	  size = -1;
	}
    }
  else
    {
      size = libc_write (fd, buf, nbytes);
    }

  return size;
}

ssize_t
writev (int fd, const struct iovec * iov, int iovcnt)
{
  ssize_t size = 0, total = 0;
  vls_handle_t vlsh;
  int i, rv = 0;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      do
	{
	  for (i = 0; i < iovcnt; ++i)
	    {
	      rv = vls_write_msg (vlsh, iov[i].iov_base, iov[i].iov_len);
	      if (rv < 0)
		break;
	      else
		{
		  total += rv;
		  if (rv < iov[i].iov_len)
		    break;
		}
	    }
	}
      while ((rv >= 0) && (total == 0));

      if (rv < 0)
	{
	  errno = -rv;
	  size = -1;
	}
      else
	size = total;
    }
  else
    {
      size = libc_writev (fd, iov, iovcnt);
    }

  return size;
}

int
fcntl (int fd, int cmd, ...)
{
  vls_handle_t vlsh;
  int rv = 0;
  va_list ap;

  if ((errno = -ldp_init ()))
    return -1;

  va_start (ap, cmd);

  vlsh = ldp_fd_to_vlsh (fd);
  LDBG (0, "fd %u vlsh %d, cmd %u", fd, vlsh, cmd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      int flags = va_arg (ap, int);
      u32 size;

      size = sizeof (flags);
      rv = -EOPNOTSUPP;
      switch (cmd)
	{
	case F_SETFL:
	  rv = vls_attr (vlsh, VPPCOM_ATTR_SET_FLAGS, &flags, &size);
	  break;

	case F_GETFL:
	  rv = vls_attr (vlsh, VPPCOM_ATTR_GET_FLAGS, &flags, &size);
	  if (rv == VPPCOM_OK)
	    rv = flags;
	  break;
	case F_SETFD:
	  /* TODO handle this */
	  LDBG (0, "F_SETFD ignored flags %u", flags);
	  rv = 0;
	  break;
	default:
	  rv = -EOPNOTSUPP;
	  break;
	}
      if (rv < 0)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      rv = libc_vfcntl (fd, cmd, ap);
    }

  va_end (ap);

  return rv;
}

int
ioctl (int fd, unsigned long int cmd, ...)
{
  vls_handle_t vlsh;
  va_list ap;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  va_start (ap, cmd);

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      switch (cmd)
	{
	case FIONREAD:
	  rv = vls_attr (vlsh, VPPCOM_ATTR_GET_NREAD, 0, 0);
	  break;

	case FIONBIO:
	  {
	    u32 flags = va_arg (ap, int) ? O_NONBLOCK : 0;
	    u32 size = sizeof (flags);

	    /* TBD: When VPPCOM_ATTR_[GS]ET_FLAGS supports flags other than
	     *      non-blocking, the flags should be read here and merged
	     *      with O_NONBLOCK.
	     */
	    rv = vls_attr (vlsh, VPPCOM_ATTR_SET_FLAGS, &flags, &size);
	  }
	  break;

	default:
	  rv = -EOPNOTSUPP;
	  break;
	}
      if (rv < 0)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      rv = libc_vioctl (fd, cmd, ap);
    }

  va_end (ap);
  return rv;
}

always_inline void
ldp_select_init_bitmaps (fd_set * __restrict original,
			 clib_bitmap_t ** resultb, clib_bitmap_t ** libcb,
			 clib_bitmap_t ** vclb, int nfds, u32 minbits,
			 u32 n_bytes, uword * si_bits, uword * libc_bits)
{
  uword si_bits_set, libc_bits_set;
  vls_handle_t vlsh;
  int fd;

  clib_bitmap_validate (*vclb, minbits);
  clib_bitmap_validate (*libcb, minbits);
  clib_bitmap_validate (*resultb, minbits);
  clib_memcpy_fast (*resultb, original, n_bytes);
  memset (original, 0, n_bytes);

  /* *INDENT-OFF* */
  clib_bitmap_foreach (fd, *resultb, ({
    if (fd > nfds)
      break;
    vlsh = ldp_fd_to_vlsh (fd);
    if (vlsh == VLS_INVALID_HANDLE)
      clib_bitmap_set_no_check (*libcb, fd, 1);
    else
      clib_bitmap_set_no_check (*vclb, vlsh_to_session_index (vlsh), 1);
  }));
  /* *INDENT-ON* */

  si_bits_set = clib_bitmap_last_set (*vclb) + 1;
  *si_bits = (si_bits_set > *si_bits) ? si_bits_set : *si_bits;

  libc_bits_set = clib_bitmap_last_set (*libcb) + 1;
  *libc_bits = (libc_bits_set > *libc_bits) ? libc_bits_set : *libc_bits;
}

always_inline int
ldp_select_vcl_bitmap_to_libc (clib_bitmap_t * vclb,
			       fd_set * __restrict libcb)
{
  vls_handle_t vlsh;
  uword si;
  int fd;

  if (!libcb)
    return 0;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (si, vclb, ({
    vlsh = vls_session_index_to_vlsh (si);
    fd = ldp_vlsh_to_fd (vlsh);
    if (PREDICT_FALSE (fd < 0))
      {
        errno = EBADFD;
        return -1;
      }
    FD_SET (fd, libcb);
  }));
  /* *INDENT-ON* */

  return 0;
}

int
ldp_pselect (int nfds, fd_set * __restrict readfds,
	     fd_set * __restrict writefds,
	     fd_set * __restrict exceptfds,
	     const struct timespec *__restrict timeout,
	     const __sigset_t * __restrict sigmask)
{
  u32 minbits = clib_max (nfds, BITS (uword)), n_bytes;
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  struct timespec libc_tspec = { 0 };
  f64 time_out, vcl_timeout;
  uword si_bits, libc_bits;
  int rv;

  if (nfds < 0)
    {
      errno = EINVAL;
      return -1;
    }

  if (timeout)
    {
      time_out = (timeout->tv_sec == 0 && timeout->tv_nsec == 0) ?
	(f64) 0 : (f64) timeout->tv_sec + (f64) timeout->tv_nsec / (f64) 1e9;

      /* select as fine grained sleep */
      if (!nfds)
	{
	  time_out += clib_time_now (&ldpw->clib_time);
	  while (clib_time_now (&ldpw->clib_time) < time_out)
	    ;
	  return 0;
	}
    }
  else if (!nfds)
    {
      errno = EINVAL;
      return -1;
    }
  else
    time_out = -1;


  if (nfds <= ldp->vlsh_bit_val)
    {
      rv = libc_pselect (nfds, readfds, writefds, exceptfds,
			 timeout, sigmask);
      goto done;
    }

  si_bits = libc_bits = 0;
  n_bytes = nfds / 8 + ((nfds % 8) ? 1 : 0);

  if (readfds)
    ldp_select_init_bitmaps (readfds, &ldpw->rd_bitmap, &ldpw->libc_rd_bitmap,
			     &ldpw->si_rd_bitmap, nfds, minbits, n_bytes,
			     &si_bits, &libc_bits);
  if (writefds)
    ldp_select_init_bitmaps (writefds, &ldpw->wr_bitmap,
			     &ldpw->libc_wr_bitmap, &ldpw->si_wr_bitmap, nfds,
			     minbits, n_bytes, &si_bits, &libc_bits);
  if (exceptfds)
    ldp_select_init_bitmaps (exceptfds, &ldpw->ex_bitmap,
			     &ldpw->libc_ex_bitmap, &ldpw->si_ex_bitmap, nfds,
			     minbits, n_bytes, &si_bits, &libc_bits);

  if (PREDICT_FALSE (!si_bits && !libc_bits))
    {
      errno = EINVAL;
      rv = -1;
      goto done;
    }

  vcl_timeout = libc_bits ? 0 : time_out;
  libc_tspec = si_bits ? libc_tspec : *timeout;

  do
    {
      if (si_bits)
	{
	  if (!ldpw->select_vcl)
	    {
	      if (readfds)
		clib_memcpy_fast (ldpw->rd_bitmap, ldpw->si_rd_bitmap,
				  vec_len (ldpw->rd_bitmap) *
				  sizeof (clib_bitmap_t));
	      if (writefds)
		clib_memcpy_fast (ldpw->wr_bitmap, ldpw->si_wr_bitmap,
				  vec_len (ldpw->wr_bitmap) *
				  sizeof (clib_bitmap_t));
	      if (exceptfds)
		clib_memcpy_fast (ldpw->ex_bitmap, ldpw->si_ex_bitmap,
				  vec_len (ldpw->ex_bitmap) *
				  sizeof (clib_bitmap_t));

	      rv = vppcom_select (si_bits, readfds ? ldpw->rd_bitmap : NULL,
		                  writefds ? ldpw->wr_bitmap : NULL,
		                  exceptfds ? ldpw->ex_bitmap : NULL,
		                  vcl_timeout);
	      if (rv < 0)
		{
		  errno = -rv;
		  rv = -1;
		}
	      else if (rv > 0)
		{
                  if (ldp_select_vcl_bitmap_to_libc (ldpw->rd_bitmap, readfds))
                    {
                      rv = -1;
                      goto done;
                    }

                  if (ldp_select_vcl_bitmap_to_libc (ldpw->wr_bitmap, writefds))
                    {
                      rv = -1;
                      goto done;
                    }

                  if (ldp_select_vcl_bitmap_to_libc (ldpw->ex_bitmap, exceptfds))
                    {
                      rv = -1;
                      goto done;
                    }

		  ldpw->select_vcl = 1;
		  goto done;
		}
	    }
	  else
	    ldpw->select_vcl = 0;
	}
      if (libc_bits)
	{
	  if (readfds)
	    clib_memcpy_fast (readfds, ldpw->libc_rd_bitmap,
			      vec_len (ldpw->libc_rd_bitmap) *
			      sizeof (clib_bitmap_t));
	  if (writefds)
	    clib_memcpy_fast (writefds, ldpw->libc_wr_bitmap,
			      vec_len (ldpw->libc_wr_bitmap) *
			      sizeof (clib_bitmap_t));
	  if (exceptfds)
	    clib_memcpy_fast (exceptfds, ldpw->libc_ex_bitmap,
			      vec_len (ldpw->libc_ex_bitmap) *
			      sizeof (clib_bitmap_t));
	  rv = libc_pselect (libc_bits,
			     readfds ? readfds : NULL,
			     writefds ? writefds : NULL,
			     exceptfds ? exceptfds : NULL, &libc_tspec,
			sigmask);
	  if (rv != 0)
	    goto done;
	}
    }
  while ((time_out == -1) || (clib_time_now (&ldpw->clib_time) < time_out));
  rv = 0;

done:
  /* TBD: set timeout to amount of time left */
  clib_bitmap_zero (ldpw->rd_bitmap);
  clib_bitmap_zero (ldpw->si_rd_bitmap);
  clib_bitmap_zero (ldpw->libc_rd_bitmap);
  clib_bitmap_zero (ldpw->wr_bitmap);
  clib_bitmap_zero (ldpw->si_wr_bitmap);
  clib_bitmap_zero (ldpw->libc_wr_bitmap);
  clib_bitmap_zero (ldpw->ex_bitmap);
  clib_bitmap_zero (ldpw->si_ex_bitmap);
  clib_bitmap_zero (ldpw->libc_ex_bitmap);

  return rv;
}

int
select (int nfds, fd_set * __restrict readfds,
	fd_set * __restrict writefds,
	fd_set * __restrict exceptfds, struct timeval *__restrict timeout)
{
  struct timespec tspec;

  if (timeout)
    {
      tspec.tv_sec = timeout->tv_sec;
      tspec.tv_nsec = timeout->tv_usec * 1000;
    }
  return ldp_pselect (nfds, readfds, writefds, exceptfds,
		      timeout ? &tspec : NULL, NULL);
}

#ifdef __USE_XOPEN2K
int
pselect (int nfds, fd_set * __restrict readfds,
	 fd_set * __restrict writefds,
	 fd_set * __restrict exceptfds,
	 const struct timespec *__restrict timeout,
	 const __sigset_t * __restrict sigmask)
{
  return ldp_pselect (nfds, readfds, writefds, exceptfds, timeout, 0);
}
#endif

int
socket (int domain, int type, int protocol)
{
  int rv, sock_type = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
  u8 is_nonblocking = type & SOCK_NONBLOCK ? 1 : 0;
  vls_handle_t vlsh;

  if ((errno = -ldp_init ()))
    return -1;

  if (((domain == AF_INET) || (domain == AF_INET6)) &&
      ((sock_type == SOCK_STREAM) || (sock_type == SOCK_DGRAM)))
    {
      u8 proto = ((sock_type == SOCK_DGRAM) ?
		  VPPCOM_PROTO_UDP : VPPCOM_PROTO_TCP);

      LDBG (0, "calling vls_create: proto %u (%s), is_nonblocking %u",
	    proto, vppcom_proto_str (proto), is_nonblocking);

      vlsh = vls_create (proto, is_nonblocking);
      if (vlsh < 0)
	{
	  errno = -vlsh;
	  rv = -1;
	}
      else
	{
	  rv = ldp_vlsh_to_fd (vlsh);
	}
    }
  else
    {
      LDBG (0, "calling libc_socket");
      rv = libc_socket (domain, type, protocol);
    }

  return rv;
}

/*
 * Create two new sockets, of type TYPE in domain DOMAIN and using
 * protocol PROTOCOL, which are connected to each other, and put file
 * descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
 * one will be chosen automatically.
 * Returns 0 on success, -1 for errors.
 * */
int
socketpair (int domain, int type, int protocol, int fds[2])
{
  int rv, sock_type = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);

  if ((errno = -ldp_init ()))
    return -1;

  if (((domain == AF_INET) || (domain == AF_INET6)) &&
      ((sock_type == SOCK_STREAM) || (sock_type == SOCK_DGRAM)))
    {
      LDBG (0, "LDP-TBD");
      errno = ENOSYS;
      rv = -1;
    }
  else
    {
      LDBG (1, "calling libc_socketpair");
      rv = libc_socketpair (domain, type, protocol, fds);
    }

  return rv;
}

int
bind (int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;

      switch (addr->sa_family)
	{
	case AF_INET:
	  if (len != sizeof (struct sockaddr_in))
	    {
	      LDBG (0, "ERROR: fd %d: vlsh %u: Invalid AF_INET addr len %u!",
		    fd, vlsh, len);
	      errno = EINVAL;
	      rv = -1;
	      goto done;
	    }
	  ep.is_ip4 = VPPCOM_IS_IP4;
	  ep.ip = (u8 *) & ((const struct sockaddr_in *) addr)->sin_addr;
	  ep.port = (u16) ((const struct sockaddr_in *) addr)->sin_port;
	  break;

	case AF_INET6:
	  if (len != sizeof (struct sockaddr_in6))
	    {
	      LDBG (0, "ERROR: fd %d: vlsh %u: Invalid AF_INET6 addr len %u!",
		    fd, vlsh, len);
	      errno = EINVAL;
	      rv = -1;
	      goto done;
	    }
	  ep.is_ip4 = VPPCOM_IS_IP6;
	  ep.ip = (u8 *) & ((const struct sockaddr_in6 *) addr)->sin6_addr;
	  ep.port = (u16) ((const struct sockaddr_in6 *) addr)->sin6_port;
	  break;

	default:
	  LDBG (0, "ERROR: fd %d: vlsh %u: Unsupported address family %u!",
		fd, vlsh, addr->sa_family);
	  errno = EAFNOSUPPORT;
	  rv = -1;
	  goto done;
	}
      LDBG (0, "fd %d: calling vls_bind: vlsh %u, addr %p, len %u", fd, vlsh,
	    addr, len);

      rv = vls_bind (vlsh, &ep);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      LDBG (0, "fd %d: calling libc_bind: addr %p, len %u", fd, addr, len);
      rv = libc_bind (fd, addr, len);
    }

done:
  LDBG (1, "fd %d: returning %d", fd, rv);

  return rv;
}

static inline int
ldp_copy_ep_to_sockaddr (__SOCKADDR_ARG addr, socklen_t * __restrict len,
			 vppcom_endpt_t * ep)
{
  int rv = 0;
  int sa_len, copy_len;

  if ((errno = -ldp_init ()))
    return -1;

  if (addr && len && ep)
    {
      addr->sa_family = (ep->is_ip4 == VPPCOM_IS_IP4) ? AF_INET : AF_INET6;
      switch (addr->sa_family)
	{
	case AF_INET:
	  ((struct sockaddr_in *) addr)->sin_port = ep->port;
	  if (*len > sizeof (struct sockaddr_in))
	    *len = sizeof (struct sockaddr_in);
	  sa_len = sizeof (struct sockaddr_in) - sizeof (struct in_addr);
	  copy_len = *len - sa_len;
	  if (copy_len > 0)
	    memcpy (&((struct sockaddr_in *) addr)->sin_addr, ep->ip,
		    copy_len);
	  break;

	case AF_INET6:
	  ((struct sockaddr_in6 *) addr)->sin6_port = ep->port;
	  if (*len > sizeof (struct sockaddr_in6))
	    *len = sizeof (struct sockaddr_in6);
	  sa_len = sizeof (struct sockaddr_in6) - sizeof (struct in6_addr);
	  copy_len = *len - sa_len;
	  if (copy_len > 0)
	    memcpy (((struct sockaddr_in6 *) addr)->sin6_addr.
		    __in6_u.__u6_addr8, ep->ip, copy_len);
	  break;

	default:
	  /* Not possible */
	  rv = -EAFNOSUPPORT;
	  break;
	}
    }
  return rv;
}

int
getsockname (int fd, __SOCKADDR_ARG addr, socklen_t * __restrict len)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;
      u8 addr_buf[sizeof (struct in6_addr)];
      u32 size = sizeof (ep);

      ep.ip = addr_buf;

      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_LCL_ADDR, &ep, &size);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
      else
	{
	  rv = ldp_copy_ep_to_sockaddr (addr, len, &ep);
	  if (rv != VPPCOM_OK)
	    {
	      errno = -rv;
	      rv = -1;
	    }
	}
    }
  else
    {
      rv = libc_getsockname (fd, addr, len);
    }

  return rv;
}

int
connect (int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  if (!addr)
    {
      LDBG (0, "ERROR: fd %d: NULL addr, len %u", fd, len);
      errno = EINVAL;
      rv = -1;
      goto done;
    }

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;

      switch (addr->sa_family)
	{
	case AF_INET:
	  if (len != sizeof (struct sockaddr_in))
	    {
	      LDBG (0, "fd %d: ERROR vlsh %u: Invalid AF_INET addr len %u!",
		    fd, vlsh, len);
	      errno = EINVAL;
	      rv = -1;
	      goto done;
	    }
	  ep.is_ip4 = VPPCOM_IS_IP4;
	  ep.ip = (u8 *) & ((const struct sockaddr_in *) addr)->sin_addr;
	  ep.port = (u16) ((const struct sockaddr_in *) addr)->sin_port;
	  break;

	case AF_INET6:
	  if (len != sizeof (struct sockaddr_in6))
	    {
	      LDBG (0, "fd %d: ERROR vlsh %u: Invalid AF_INET6 addr len %u!",
		    fd, vlsh, len);
	      errno = EINVAL;
	      rv = -1;
	      goto done;
	    }
	  ep.is_ip4 = VPPCOM_IS_IP6;
	  ep.ip = (u8 *) & ((const struct sockaddr_in6 *) addr)->sin6_addr;
	  ep.port = (u16) ((const struct sockaddr_in6 *) addr)->sin6_port;
	  break;

	default:
	  LDBG (0, "fd %d: ERROR vlsh %u: Unsupported address family %u!",
		fd, vlsh, addr->sa_family);
	  errno = EAFNOSUPPORT;
	  rv = -1;
	  goto done;
	}
      LDBG (0, "fd %d: calling vls_connect(): vlsh %u addr %p len %u", fd,
	    vlsh, addr, len);

      rv = vls_connect (vlsh, &ep);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      LDBG (0, "fd %d: calling libc_connect(): addr %p, len %u",
	    fd, addr, len);

      rv = libc_connect (fd, addr, len);
    }

done:
  LDBG (1, "fd %d: returning %d (0x%x)", fd, rv, rv);
  return rv;
}

int
getpeername (int fd, __SOCKADDR_ARG addr, socklen_t * __restrict len)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;
      u8 addr_buf[sizeof (struct in6_addr)];
      u32 size = sizeof (ep);

      ep.ip = addr_buf;
      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_PEER_ADDR, &ep, &size);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
      else
	{
	  rv = ldp_copy_ep_to_sockaddr (addr, len, &ep);
	  if (rv != VPPCOM_OK)
	    {
	      errno = -rv;
	      rv = -1;
	    }
	}
    }
  else
    {
      rv = libc_getpeername (fd, addr, len);
    }

  return rv;
}

ssize_t
send (int fd, const void *buf, size_t n, int flags)
{
  vls_handle_t vlsh = ldp_fd_to_vlsh (fd);
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  if (vlsh != VLS_INVALID_HANDLE)
    {
      size = vls_sendto (vlsh, (void *) buf, n, flags, NULL);
      if (size < VPPCOM_OK)
	{
	  errno = -size;
	  size = -1;
	}
    }
  else
    {
      size = libc_send (fd, buf, n, flags);
    }

  return size;
}

ssize_t
sendfile (int out_fd, int in_fd, off_t * offset, size_t len)
{
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  vls_handle_t vlsh;
  ssize_t size = 0;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (out_fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      int rv;
      ssize_t results = 0;
      size_t n_bytes_left = len;
      size_t bytes_to_read;
      int nbytes;
      u8 eagain = 0;
      u32 flags, flags_len = sizeof (flags);

      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_FLAGS, &flags, &flags_len);
      if (PREDICT_FALSE (rv != VPPCOM_OK))
	{
	  LDBG (0, "ERROR: out fd %d: vls_attr: vlsh %u, returned %d (%s)!",
		out_fd, vlsh, rv, vppcom_retval_str (rv));

	  vec_reset_length (ldpw->io_buffer);
	  errno = -rv;
	  size = -1;
	  goto done;
	}

      if (offset)
	{
	  off_t off = lseek (in_fd, *offset, SEEK_SET);
	  if (PREDICT_FALSE (off == -1))
	    {
	      size = -1;
	      goto done;
	    }

	  ASSERT (off == *offset);
	}

      do
	{
	  size = vls_attr (vlsh, VPPCOM_ATTR_GET_NWRITE, 0, 0);
	  if (size < 0)
	    {
	      LDBG (0, "ERROR: fd %d: vls_attr: vlsh %u returned %d (%s)!",
		    out_fd, vlsh, size, vppcom_retval_str (size));
	      vec_reset_length (ldpw->io_buffer);
	      errno = -size;
	      size = -1;
	      goto done;
	    }

	  bytes_to_read = size;
	  if (bytes_to_read == 0)
	    {
	      if (flags & O_NONBLOCK)
		{
		  if (!results)
		    eagain = 1;
		  goto update_offset;
		}
	      else
		continue;
	    }
	  bytes_to_read = clib_min (n_bytes_left, bytes_to_read);
	  vec_validate (ldpw->io_buffer, bytes_to_read);
	  nbytes = libc_read (in_fd, ldpw->io_buffer, bytes_to_read);
	  if (nbytes < 0)
	    {
	      if (results == 0)
		{
		  vec_reset_length (ldpw->io_buffer);
		  size = -1;
		  goto done;
		}
	      goto update_offset;
	    }

	  size = vls_write (vlsh, ldpw->io_buffer, nbytes);
	  if (size < 0)
	    {
	      if (size == VPPCOM_EAGAIN)
		{
		  if (flags & O_NONBLOCK)
		    {
		      if (!results)
			eagain = 1;
		      goto update_offset;
		    }
		  else
		    continue;
		}
	      if (results == 0)
		{
		  vec_reset_length (ldpw->io_buffer);
		  errno = -size;
		  size = -1;
		  goto done;
		}
	      goto update_offset;
	    }

	  results += nbytes;
	  ASSERT (n_bytes_left >= nbytes);
	  n_bytes_left = n_bytes_left - nbytes;
	}
      while (n_bytes_left > 0);

    update_offset:
      vec_reset_length (ldpw->io_buffer);
      if (offset)
	{
	  off_t off = lseek (in_fd, *offset, SEEK_SET);
	  if (PREDICT_FALSE (off == -1))
	    {
	      size = -1;
	      goto done;
	    }

	  ASSERT (off == *offset);
	  *offset += results + 1;
	}
      if (eagain)
	{
	  errno = EAGAIN;
	  size = -1;
	}
      else
	size = results;
    }
  else
    {
      size = libc_sendfile (out_fd, in_fd, offset, len);
    }

done:
  return size;
}

ssize_t
sendfile64 (int out_fd, int in_fd, off_t * offset, size_t len)
{
  return sendfile (out_fd, in_fd, offset, len);
}

ssize_t
recv (int fd, void *buf, size_t n, int flags)
{
  vls_handle_t vlsh;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      size = vls_recvfrom (vlsh, buf, n, flags, NULL);
      if (size < 0)
	errno = -size;
    }
  else
    {
      size = libc_recv (fd, buf, n, flags);
    }

  return size;
}

ssize_t
sendto (int fd, const void *buf, size_t n, int flags,
	__CONST_SOCKADDR_ARG addr, socklen_t addr_len)
{
  vls_handle_t vlsh;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != INVALID_SESSION_ID)
    {
      vppcom_endpt_t *ep = 0;
      vppcom_endpt_t _ep;

      if (addr)
	{
	  ep = &_ep;
	  switch (addr->sa_family)
	    {
	    case AF_INET:
	      ep->is_ip4 = VPPCOM_IS_IP4;
	      ep->ip =
		(uint8_t *) & ((const struct sockaddr_in *) addr)->sin_addr;
	      ep->port =
		(uint16_t) ((const struct sockaddr_in *) addr)->sin_port;
	      break;

	    case AF_INET6:
	      ep->is_ip4 = VPPCOM_IS_IP6;
	      ep->ip =
		(uint8_t *) & ((const struct sockaddr_in6 *) addr)->sin6_addr;
	      ep->port =
		(uint16_t) ((const struct sockaddr_in6 *) addr)->sin6_port;
	      break;

	    default:
	      errno = EAFNOSUPPORT;
	      size = -1;
	      goto done;
	    }
	}

      size = vls_sendto (vlsh, (void *) buf, n, flags, ep);
      if (size < 0)
	{
	  errno = -size;
	  size = -1;
	}
    }
  else
    {
      size = libc_sendto (fd, buf, n, flags, addr, addr_len);
    }

done:
  return size;
}

ssize_t
recvfrom (int fd, void *__restrict buf, size_t n, int flags,
	  __SOCKADDR_ARG addr, socklen_t * __restrict addr_len)
{
  vls_handle_t sid;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  sid = ldp_fd_to_vlsh (fd);
  if (sid != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;
      u8 src_addr[sizeof (struct sockaddr_in6)];

      if (addr)
	{
	  ep.ip = src_addr;
	  size = vls_recvfrom (sid, buf, n, flags, &ep);

	  if (size > 0)
	    size = ldp_copy_ep_to_sockaddr (addr, addr_len, &ep);
	}
      else
	size = vls_recvfrom (sid, buf, n, flags, NULL);

      if (size < 0)
	{
	  errno = -size;
	  size = -1;
	}
    }
  else
    {
      size = libc_recvfrom (fd, buf, n, flags, addr, addr_len);
    }

  return size;
}

ssize_t
sendmsg (int fd, const struct msghdr * message, int flags)
{
  vls_handle_t vlsh;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      LDBG (0, "LDP-TBD");
      errno = ENOSYS;
      size = -1;
    }
  else
    {
      size = libc_sendmsg (fd, message, flags);
    }

  return size;
}

#ifdef USE_GNU
int
sendmmsg (int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags)
{
  ssize_t size;
  const char *func_str;
  u32 sh = ldp_fd_to_vlsh (fd);

  if ((errno = -ldp_init ()))
    return -1;

  if (sh != INVALID_SESSION_ID)
    {
      clib_warning ("LDP<%d>: LDP-TBD", getpid ());
      errno = ENOSYS;
      size = -1;
    }
  else
    {
      func_str = "libc_sendmmsg";

      if (LDP_DEBUG > 2)
	clib_warning ("LDP<%d>: fd %d (0x%x): calling %s(): "
		      "vmessages %p, vlen %u, flags 0x%x",
		      getpid (), fd, fd, func_str, vmessages, vlen, flags);

      size = libc_sendmmsg (fd, vmessages, vlen, flags);
    }

  if (LDP_DEBUG > 2)
    {
      if (size < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: fd %d (0x%x): %s() failed! "
			"rv %d, errno = %d", getpid (), fd, fd,
			func_str, size, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: fd %d (0x%x): returning %d (0x%x)",
		      getpid (), fd, fd, size, size);
    }
  return size;
}
#endif

ssize_t
recvmsg (int fd, struct msghdr * message, int flags)
{
  vls_handle_t vlsh;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      LDBG (0, "LDP-TBD");
      errno = ENOSYS;
      size = -1;
    }
  else
    {
      size = libc_recvmsg (fd, message, flags);
    }

  return size;
}

#ifdef USE_GNU
int
recvmmsg (int fd, struct mmsghdr *vmessages,
	  unsigned int vlen, int flags, struct timespec *tmo)
{
  ssize_t size;
  const char *func_str;
  u32 sh = ldp_fd_to_vlsh (fd);

  if ((errno = -ldp_init ()))
    return -1;

  if (sh != INVALID_SESSION_ID)
    {
      clib_warning ("LDP<%d>: LDP-TBD", getpid ());
      errno = ENOSYS;
      size = -1;
    }
  else
    {
      func_str = "libc_recvmmsg";

      if (LDP_DEBUG > 2)
	clib_warning ("LDP<%d>: fd %d (0x%x): calling %s(): "
		      "vmessages %p, vlen %u, flags 0x%x, tmo %p",
		      getpid (), fd, fd, func_str, vmessages, vlen,
		      flags, tmo);

      size = libc_recvmmsg (fd, vmessages, vlen, flags, tmo);
    }

  if (LDP_DEBUG > 2)
    {
      if (size < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: fd %d (0x%x): %s() failed! "
			"rv %d, errno = %d", getpid (), fd, fd,
			func_str, size, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: fd %d (0x%x): returning %d (0x%x)",
		      getpid (), fd, fd, size, size);
    }
  return size;
}
#endif

int
getsockopt (int fd, int level, int optname,
	    void *__restrict optval, socklen_t * __restrict optlen)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      rv = -EOPNOTSUPP;

      switch (level)
	{
	case SOL_TCP:
	  switch (optname)
	    {
	    case TCP_NODELAY:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_TCP_NODELAY,
			     optval, optlen);
	      break;
	    case TCP_MAXSEG:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_TCP_USER_MSS,
			     optval, optlen);
	      break;
	    case TCP_KEEPIDLE:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_TCP_KEEPIDLE,
			     optval, optlen);
	      break;
	    case TCP_KEEPINTVL:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_TCP_KEEPINTVL,
			     optval, optlen);
	      break;
	    case TCP_INFO:
	      if (optval && optlen && (*optlen == sizeof (struct tcp_info)))
		{
		  LDBG (1, "fd %d: vlsh %u SOL_TCP, TCP_INFO, optval %p, "
			"optlen %d: #LDP-NOP#", fd, vlsh, optval, *optlen);
		  memset (optval, 0, *optlen);
		  rv = VPPCOM_OK;
		}
	      else
		rv = -EFAULT;
	      break;
	    default:
	      LDBG (0, "ERROR: fd %d: getsockopt SOL_TCP: sid %u, "
		    "optname %d unsupported!", fd, vlsh, optname);
	      break;
	    }
	  break;
	case SOL_IPV6:
	  switch (optname)
	    {
	    case IPV6_V6ONLY:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_V6ONLY, optval, optlen);
	      break;
	    default:
	      LDBG (0, "ERROR: fd %d: getsockopt SOL_IPV6: vlsh %u "
		    "optname %d unsupported!", fd, vlsh, optname);
	      break;
	    }
	  break;
	case SOL_SOCKET:
	  switch (optname)
	    {
	    case SO_ACCEPTCONN:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_LISTEN, optval, optlen);
	      break;
	    case SO_KEEPALIVE:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_KEEPALIVE, optval, optlen);
	      break;
	    case SO_PROTOCOL:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_PROTOCOL, optval, optlen);
	      *(int *) optval = *(int *) optval ? SOCK_DGRAM : SOCK_STREAM;
	      break;
	    case SO_SNDBUF:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_TX_FIFO_LEN,
			     optval, optlen);
	      break;
	    case SO_RCVBUF:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_RX_FIFO_LEN,
			     optval, optlen);
	      break;
	    case SO_REUSEADDR:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_REUSEADDR, optval, optlen);
	      break;
	    case SO_BROADCAST:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_BROADCAST, optval, optlen);
	      break;
	    case SO_ERROR:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_GET_ERROR, optval, optlen);
	      break;
	    default:
	      LDBG (0, "ERROR: fd %d: getsockopt SOL_SOCKET: vlsh %u "
		    "optname %d unsupported!", fd, vlsh, optname);
	      break;
	    }
	  break;
	default:
	  break;
	}

      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      rv = libc_getsockopt (fd, level, optname, optval, optlen);
    }

  return rv;
}

int
setsockopt (int fd, int level, int optname,
	    const void *optval, socklen_t optlen)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      rv = -EOPNOTSUPP;

      switch (level)
	{
	case SOL_TCP:
	  switch (optname)
	    {
	    case TCP_NODELAY:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_TCP_NODELAY,
			     (void *) optval, &optlen);
	      break;
	    case TCP_MAXSEG:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_TCP_USER_MSS,
			     (void *) optval, &optlen);
	      break;
	    case TCP_KEEPIDLE:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_TCP_KEEPIDLE,
			     (void *) optval, &optlen);
	      break;
	    case TCP_KEEPINTVL:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_TCP_KEEPINTVL,
			     (void *) optval, &optlen);
	      break;
	    default:
	      LDBG (0, "ERROR: fd %d: setsockopt() SOL_TCP: vlsh %u"
		    "optname %d unsupported!", fd, vlsh, optname);
	      break;
	    }
	  break;
	case SOL_IPV6:
	  switch (optname)
	    {
	    case IPV6_V6ONLY:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_V6ONLY,
			     (void *) optval, &optlen);
	      break;
	    default:
	      LDBG (0, "ERROR: fd %d: setsockopt SOL_IPV6: vlsh %u"
		    "optname %d unsupported!", fd, vlsh, optname);
	      break;
	    }
	  break;
	case SOL_SOCKET:
	  switch (optname)
	    {
	    case SO_KEEPALIVE:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_KEEPALIVE,
			     (void *) optval, &optlen);
	      break;
	    case SO_REUSEADDR:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_REUSEADDR,
			     (void *) optval, &optlen);
	      break;
	    case SO_BROADCAST:
	      rv = vls_attr (vlsh, VPPCOM_ATTR_SET_BROADCAST,
			     (void *) optval, &optlen);
	      break;
	    default:
	      LDBG (0, "ERROR: fd %d: setsockopt SOL_SOCKET: vlsh %u "
		    "optname %d unsupported!", fd, vlsh, optname);
	      break;
	    }
	  break;
	default:
	  break;
	}

      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      rv = libc_setsockopt (fd, level, optname, optval, optlen);
    }

  return rv;
}

int
listen (int fd, int n)
{
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      LDBG (0, "fd %d: calling vls_listen: vlsh %u, n %d", fd, vlsh, n);

      rv = vls_listen (vlsh, n);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      LDBG (0, "fd %d: calling libc_listen(): n %d", fd, n);
      rv = libc_listen (fd, n);
    }

  LDBG (1, "fd %d: returning %d", fd, rv);
  return rv;
}

static inline int
ldp_accept4 (int listen_fd, __SOCKADDR_ARG addr,
	     socklen_t * __restrict addr_len, int flags)
{
  vls_handle_t listen_vlsh, accept_vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  listen_vlsh = ldp_fd_to_vlsh (listen_fd);
  if (listen_vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;
      u8 src_addr[sizeof (struct sockaddr_in6)];
      memset (&ep, 0, sizeof (ep));
      ep.ip = src_addr;

      LDBG (0, "listen fd %d: calling vppcom_session_accept: listen sid %u,"
	    " ep %p, flags 0x%x", listen_fd, listen_vlsh, ep, flags);

      accept_vlsh = vls_accept (listen_vlsh, &ep, flags);
      if (accept_vlsh < 0)
	{
	  errno = -accept_vlsh;
	  rv = -1;
	}
      else
	{
	  rv = ldp_copy_ep_to_sockaddr (addr, addr_len, &ep);
	  if (rv != VPPCOM_OK)
	    {
	      (void) vls_close (accept_vlsh);
	      errno = -rv;
	      rv = -1;
	    }
	  else
	    {
	      rv = ldp_vlsh_to_fd (accept_vlsh);
	    }
	}
    }
  else
    {
      LDBG (0, "listen fd %d: calling libc_accept4(): addr %p, addr_len %p,"
	    " flags 0x%x", listen_fd, addr, addr_len, flags);

      rv = libc_accept4 (listen_fd, addr, addr_len, flags);
    }

  LDBG (1, "listen fd %d: accept returning %d", listen_fd, rv);

  return rv;
}

int
accept4 (int fd, __SOCKADDR_ARG addr, socklen_t * __restrict addr_len,
	 int flags)
{
  return ldp_accept4 (fd, addr, addr_len, flags);
}

int
accept (int fd, __SOCKADDR_ARG addr, socklen_t * __restrict addr_len)
{
  return ldp_accept4 (fd, addr, addr_len, 0);
}

int
shutdown (int fd, int how)
{
  vls_handle_t vlsh;
  int rv = 0, flags;
  u32 flags_len = sizeof (flags);

  if ((errno = -ldp_init ()))
    return -1;

  vlsh = ldp_fd_to_vlsh (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      LDBG (0, "called shutdown: fd %u vlsh %u how %d", fd, vlsh, how);

      if (vls_attr (vlsh, VPPCOM_ATTR_SET_SHUT, &how, &flags_len))
	{
	  close (fd);
	  return -1;
	}

      if (vls_attr (vlsh, VPPCOM_ATTR_GET_SHUT, &flags, &flags_len))
	{
	  close (fd);
	  return -1;
	}

      if (flags == SHUT_RDWR)
	rv = close (fd);
    }
  else
    {
      LDBG (0, "fd %d: calling libc_shutdown: how %d", fd, how);
      rv = libc_shutdown (fd, how);
    }

  return rv;
}

int
epoll_create1 (int flags)
{
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  vls_handle_t vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  if (ldp->vcl_needs_real_epoll)
    {
      rv = libc_epoll_create1 (flags);
      ldp->vcl_needs_real_epoll = 0;
      ldpw->vcl_mq_epfd = rv;
      LDBG (0, "created vcl epfd %u", rv);
      return rv;
    }

  vlsh = vls_epoll_create ();
  if (PREDICT_FALSE (vlsh == VLS_INVALID_HANDLE))
    {
      errno = -vlsh;
      rv = -1;
    }
  else
    {
      rv = ldp_vlsh_to_fd (vlsh);
    }
  LDBG (0, "epoll_create epfd %u vlsh %u", rv, vlsh);
  return rv;
}

int
epoll_create (int size)
{
  return epoll_create1 (0);
}

int
epoll_ctl (int epfd, int op, int fd, struct epoll_event *event)
{
  vls_handle_t vep_vlsh, vlsh;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  vep_vlsh = ldp_fd_to_vlsh (epfd);
  if (PREDICT_FALSE (vep_vlsh == VLS_INVALID_HANDLE))
    {
      /* The LDP epoll_create1 always creates VCL epfd's.
       * The app should never have a kernel base epoll fd unless it
       * was acquired outside of the LD_PRELOAD process context.
       * In any case, if we get one, punt it to libc_epoll_ctl.
       */
      LDBG (1, "epfd %d: calling libc_epoll_ctl: op %d, fd %d"
	    " event %p", epfd, op, fd, event);

      rv = libc_epoll_ctl (epfd, op, fd, event);
      goto done;
    }

  vlsh = ldp_fd_to_vlsh (fd);

  LDBG (0, "epfd %d ep_vlsh %d, fd %u vlsh %d, op %u", epfd, vep_vlsh, fd,
	vlsh, op);

  if (vlsh != VLS_INVALID_HANDLE)
    {
      LDBG (1, "epfd %d: calling vls_epoll_ctl: ep_vlsh %d op %d, vlsh %u,"
	    " event %p", epfd, vep_vlsh, vlsh, event);

      rv = vls_epoll_ctl (vep_vlsh, op, vlsh, event);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      int libc_epfd;
      u32 size = sizeof (epfd);

      libc_epfd = vls_attr (vep_vlsh, VPPCOM_ATTR_GET_LIBC_EPFD, 0, 0);
      if (!libc_epfd)
	{
	  LDBG (1, "epfd %d, vep_vlsh %d calling libc_epoll_create1: "
		"EPOLL_CLOEXEC", epfd, vep_vlsh);

	  libc_epfd = libc_epoll_create1 (EPOLL_CLOEXEC);
	  if (libc_epfd < 0)
	    {
	      rv = libc_epfd;
	      goto done;
	    }

	  rv = vls_attr (vep_vlsh, VPPCOM_ATTR_SET_LIBC_EPFD, &libc_epfd,
			 &size);
	  if (rv < 0)
	    {
	      errno = -rv;
	      rv = -1;
	      goto done;
	    }
	}
      else if (PREDICT_FALSE (libc_epfd < 0))
	{
	  errno = -epfd;
	  rv = -1;
	  goto done;
	}

      LDBG (1, "epfd %d: calling libc_epoll_ctl: libc_epfd %d, op %d, fd %d,"
	    " event %p", epfd, libc_epfd, op, fd, event);

      rv = libc_epoll_ctl (libc_epfd, op, fd, event);
    }

done:
  return rv;
}

static inline int
ldp_epoll_pwait (int epfd, struct epoll_event *events, int maxevents,
		 int timeout, const sigset_t * sigmask)
{
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  double time_to_wait = (double) 0, time_out, now = 0;
  int libc_epfd, rv = 0;
  vls_handle_t ep_vlsh;

  if ((errno = -ldp_init ()))
    return -1;

  if (PREDICT_FALSE (!events || (timeout < -1)))
    {
      errno = EFAULT;
      return -1;
    }

  if (epfd == ldpw->vcl_mq_epfd)
    return libc_epoll_pwait (epfd, events, maxevents, timeout, sigmask);

  ep_vlsh = ldp_fd_to_vlsh (epfd);
  if (PREDICT_FALSE (ep_vlsh == VLS_INVALID_HANDLE))
    {
      LDBG (0, "epfd %d: bad ep_vlsh %d!", epfd, ep_vlsh);
      errno = EBADFD;
      return -1;
    }

  time_to_wait = ((timeout >= 0) ? (double) timeout / 1000 : 0);
  time_out = clib_time_now (&ldpw->clib_time) + time_to_wait;

  libc_epfd = vls_attr (ep_vlsh, VPPCOM_ATTR_GET_LIBC_EPFD, 0, 0);
  if (PREDICT_FALSE (libc_epfd < 0))
    {
      errno = -libc_epfd;
      rv = -1;
      goto done;
    }

  LDBG (2, "epfd %d: vep_idx %d, libc_epfd %d, events %p, maxevents %d, "
	"timeout %d, sigmask %p: time_to_wait %.02f", epfd, ep_vlsh,
	libc_epfd, events, maxevents, timeout, sigmask, time_to_wait,
	time_out);
  do
    {
      if (!ldpw->epoll_wait_vcl)
	{
	  rv = vls_epoll_wait (ep_vlsh, events, maxevents, 0);
	  if (rv > 0)
	    {
	      ldpw->epoll_wait_vcl = 1;
	      goto done;
	    }
	  else if (rv < 0)
	    {
	      errno = -rv;
	      rv = -1;
	      goto done;
	    }
	}
      else
	ldpw->epoll_wait_vcl = 0;

      if (libc_epfd > 0)
	{
	  rv = libc_epoll_pwait (libc_epfd, events, maxevents, 0, sigmask);
	  if (rv != 0)
	    goto done;
	}

      if (timeout != -1)
	now = clib_time_now (&ldpw->clib_time);
    }
  while (now < time_out);

done:
  return rv;
}

int
epoll_pwait (int epfd, struct epoll_event *events,
	     int maxevents, int timeout, const sigset_t * sigmask)
{
  return ldp_epoll_pwait (epfd, events, maxevents, timeout, sigmask);
}

int
epoll_wait (int epfd, struct epoll_event *events, int maxevents, int timeout)
{
  return ldp_epoll_pwait (epfd, events, maxevents, timeout, NULL);
}

int
poll (struct pollfd *fds, nfds_t nfds, int timeout)
{
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  int rv, i, n_revents = 0;
  vls_handle_t vlsh;
  vcl_poll_t *vp;
  double wait_for_time;

  LDBG (3, "fds %p, nfds %d, timeout %d", fds, nfds, timeout);

  if (timeout >= 0)
    wait_for_time = (f64) timeout / 1000;
  else
    wait_for_time = -1;

  for (i = 0; i < nfds; i++)
    {
      if (fds[i].fd < 0)
	continue;

      vlsh = ldp_fd_to_vlsh (fds[i].fd);
      if (vlsh != VLS_INVALID_HANDLE)
	{
	  fds[i].fd = -fds[i].fd;
	  vec_add2 (ldpw->vcl_poll, vp, 1);
	  vp->fds_ndx = i;
	  vp->sh = vlsh_to_sh (vlsh);
	  vp->events = fds[i].events;
#ifdef __USE_XOPEN2K
	  if (fds[i].events & POLLRDNORM)
	    vp->events |= POLLIN;
	  if (fds[i].events & POLLWRNORM)
	    vp->events |= POLLOUT;
#endif
	  vp->revents = fds[i].revents;
	}
      else
	{
	  vec_add1 (ldpw->libc_poll, fds[i]);
	  vec_add1 (ldpw->libc_poll_idxs, i);
	}
    }

  do
    {
      if (vec_len (ldpw->vcl_poll))
	{
	  rv = vppcom_poll (ldpw->vcl_poll, vec_len (ldpw->vcl_poll), 0);
	  if (rv < 0)
	    {
	      errno = -rv;
	      rv = -1;
	      goto done;
	    }
	  else
	    n_revents += rv;
	}

      if (vec_len (ldpw->libc_poll))
	{
	  rv = libc_poll (ldpw->libc_poll, vec_len (ldpw->libc_poll), 0);
	  if (rv < 0)
	    goto done;
	  else
	    n_revents += rv;
	}

      if (n_revents)
	{
	  rv = n_revents;
	  goto done;
	}
    }
  while ((wait_for_time == -1) ||
	 (clib_time_now (&ldpw->clib_time) < wait_for_time));
  rv = 0;

done:
  vec_foreach (vp, ldpw->vcl_poll)
  {
    fds[vp->fds_ndx].fd = -fds[vp->fds_ndx].fd;
    fds[vp->fds_ndx].revents = vp->revents;
#ifdef __USE_XOPEN2K
    if ((fds[vp->fds_ndx].revents & POLLIN) &&
	(fds[vp->fds_ndx].events & POLLRDNORM))
      fds[vp->fds_ndx].revents |= POLLRDNORM;
    if ((fds[vp->fds_ndx].revents & POLLOUT) &&
	(fds[vp->fds_ndx].events & POLLWRNORM))
      fds[vp->fds_ndx].revents |= POLLWRNORM;
#endif
  }
  vec_reset_length (ldpw->vcl_poll);

  for (i = 0; i < vec_len (ldpw->libc_poll); i++)
    {
      fds[ldpw->libc_poll_idxs[i]].revents = ldpw->libc_poll[i].revents;
    }
  vec_reset_length (ldpw->libc_poll_idxs);
  vec_reset_length (ldpw->libc_poll);

  return rv;
}

#ifdef USE_GNU
int
ppoll (struct pollfd *fds, nfds_t nfds,
       const struct timespec *timeout, const sigset_t * sigmask)
{
  if ((errno = -ldp_init ()))
    return -1;

  clib_warning ("LDP<%d>: LDP-TBD", getpid ());
  errno = ENOSYS;


  return -1;
}
#endif

void CONSTRUCTOR_ATTRIBUTE ldp_constructor (void);

void DESTRUCTOR_ATTRIBUTE ldp_destructor (void);

/*
 * This function is called when the library is loaded
 */
void
ldp_constructor (void)
{
  swrap_constructor ();
  if (ldp_init () != 0)
    fprintf (stderr, "\nLDP<%d>: ERROR: ldp_constructor: failed!\n",
	     getpid ());
  else if (LDP_DEBUG > 0)
    clib_warning ("LDP<%d>: LDP constructor: done!\n", getpid ());
}

/*
 * This function is called when the library is unloaded
 */
void
ldp_destructor (void)
{
  swrap_destructor ();
  if (ldp->init)
    ldp->init = 0;

  /* Don't use clib_warning() here because that calls writev()
   * which will call ldp_init().
   */
  if (LDP_DEBUG > 0)
    printf ("%s:%d: LDP<%d>: LDP destructor: done!\n",
	    __func__, __LINE__, getpid ());
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
