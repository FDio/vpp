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

#include <vcl/vppcom.h>
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

#define LDP_F_SHUT_RD	(1 << 0)
#define LDP_F_SHUT_WR	(1 << 1)

typedef struct ldp_fd_entry_
{
  u32 session_index;
  u32 worker_index;
  u32 fd;
  u32 fd_index;
  u32 flags;
  clib_spinlock_t lock;
} ldp_fd_entry_t;

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
  clib_bitmap_t *sid_rd_bitmap;
  clib_bitmap_t *sid_wr_bitmap;
  clib_bitmap_t *sid_ex_bitmap;
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

typedef struct
{
  ldp_worker_ctx_t *workers;
  int init;
  char app_name[LDP_APP_NAME_MAX];
  u32 sh_bit_val;
  u32 sid_bit_mask;
  u32 debug;
  ldp_fd_entry_t *fd_pool;
  clib_rwlock_t fd_table_lock;
  uword *session_index_to_fd_table;

  /** vcl needs next epoll_create to go to libc_epoll */
  u8 vcl_needs_real_epoll;
} ldp_main_t;

#define LDP_DEBUG ldp->debug

#define LDBG(_lvl, _fmt, _args...) 					\
  if (ldp->debug > _lvl)						\
    clib_warning ("ldp<%d>: " _fmt, getpid(), ##_args)

static ldp_main_t ldp_main = {
  .sh_bit_val = (1 << LDP_SID_BIT_MIN),
  .sid_bit_mask = (1 << LDP_SID_BIT_MIN) - 1,
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

static inline vcl_session_handle_t
ldp_fd_entry_sh (ldp_fd_entry_t * fde)
{
  return vppcom_session_handle (fde->session_index);
}

static int
ldp_fd_alloc (vcl_session_handle_t sh)
{
  ldp_fd_entry_t *fde;

  clib_rwlock_writer_lock (&ldp->fd_table_lock);
  if (pool_elts (ldp->fd_pool) >= (1ULL << 32) - ldp->sh_bit_val)
    {
      clib_rwlock_writer_unlock (&ldp->fd_table_lock);
      return -1;
    }
  pool_get (ldp->fd_pool, fde);
  fde->session_index = vppcom_session_index (sh);
  fde->worker_index = vppcom_session_worker (sh);
  fde->fd_index = fde - ldp->fd_pool;
  fde->fd = fde->fd_index + ldp->sh_bit_val;
  hash_set (ldp->session_index_to_fd_table, fde->session_index, fde->fd);
  clib_spinlock_init (&fde->lock);
  clib_rwlock_writer_unlock (&ldp->fd_table_lock);
  return fde->fd;
}

static ldp_fd_entry_t *
ldp_fd_entry_get (u32 fd_index)
{
  if (pool_is_free_index (ldp->fd_pool, fd_index))
    return 0;
  return pool_elt_at_index (ldp->fd_pool, fd_index);
}

static ldp_fd_entry_t *
ldp_fd_entry_lock (u32 fd_index)
{
  ldp_fd_entry_t *fe;
  clib_rwlock_reader_lock (&ldp->fd_table_lock);
  if (pool_is_free_index (ldp->fd_pool, fd_index))
    {
      clib_rwlock_reader_unlock (&ldp->fd_table_lock);
      return 0;
    }

  fe = pool_elt_at_index (ldp->fd_pool, fd_index);
  clib_spinlock_lock (&fe->lock);
  return fe;
}

static void
ldp_fd_entry_unlock (ldp_fd_entry_t * fde)
{
  clib_spinlock_unlock (&fde->lock);
  clib_rwlock_reader_unlock (&ldp->fd_table_lock);
}

static inline int
ldp_fd_from_sh (vcl_session_handle_t sh)
{
  uword *fdp;
  int fd;

  clib_rwlock_reader_lock (&ldp->fd_table_lock);
  fdp = hash_get (ldp->session_index_to_fd_table, vppcom_session_index (sh));
  fd = fdp ? *fdp : -EMFILE;
  clib_rwlock_reader_unlock (&ldp->fd_table_lock);

  return fd;
}

static inline int
ldp_fd_is_sh (int fd)
{
  return fd >= ldp->sh_bit_val;
}

static inline u32
ldp_sh_from_fd (int fd)
{
  u32 fd_index, session_index;
  ldp_fd_entry_t *fde;

  if (!ldp_fd_is_sh (fd))
    return INVALID_SESSION_ID;

  fd_index = fd - ldp->sh_bit_val;
  fde = ldp_fd_entry_lock (fd_index);
  if (!fde)
    {
      LDBG (0, "unknown fd %d", fd);
      return INVALID_SESSION_ID;
    }
  session_index = fde->session_index;
  ldp_fd_entry_unlock (fde);

  return vppcom_session_handle (session_index);
}

static ldp_fd_entry_t *
ldp_fd_entry_lock_w_fd (int fd)
{
  u32 fd_index;

  if (!ldp_fd_is_sh (fd))
    return 0;

  fd_index = fd - ldp->sh_bit_val;
  return ldp_fd_entry_lock (fd_index);
}

static void
ldp_fd_free_w_sh (vcl_session_handle_t sh)
{
  ldp_fd_entry_t *fde;
  u32 fd_index;
  int fd;

  fd = ldp_fd_from_sh (sh);
  if (!fd)
    return;

  fd_index = fd - ldp->sh_bit_val;
  clib_rwlock_writer_lock (&ldp->fd_table_lock);
  fde = ldp_fd_entry_get (fd_index);
  ASSERT (fde != 0);
  hash_unset (ldp->session_index_to_fd_table, fde->session_index);
  clib_spinlock_free (&fde->lock);
  pool_put (ldp->fd_pool, fde);
  clib_rwlock_writer_unlock (&ldp->fd_table_lock);
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
  rv = vppcom_app_create (ldp_get_app_name ());
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
	  clib_warning ("LDP<%d>: WARNING: Invalid LDP sid bit specified in"
			" the env var " LDP_ENV_SID_BIT " (%s)! sid bit "
			"value %d (0x%x)", getpid (), env_var_str,
			ldp->sh_bit_val, ldp->sh_bit_val);
	}
      else if (sb < LDP_SID_BIT_MIN)
	{
	  ldp->sh_bit_val = (1 << LDP_SID_BIT_MIN);
	  ldp->sid_bit_mask = ldp->sh_bit_val - 1;

	  clib_warning ("LDP<%d>: WARNING: LDP sid bit (%u) specified in the"
			" env var " LDP_ENV_SID_BIT " (%s) is too small. "
			"Using LDP_SID_BIT_MIN (%d)! sid bit value %d (0x%x)",
			getpid (), sb, env_var_str, LDP_SID_BIT_MIN,
			ldp->sh_bit_val, ldp->sh_bit_val);
	}
      else if (sb > LDP_SID_BIT_MAX)
	{
	  ldp->sh_bit_val = (1 << LDP_SID_BIT_MAX);
	  ldp->sid_bit_mask = ldp->sh_bit_val - 1;

	  clib_warning ("LDP<%d>: WARNING: LDP sid bit (%u) specified in the"
			" env var " LDP_ENV_SID_BIT " (%s) is too big. Using"
			" LDP_SID_BIT_MAX (%d)! sid bit value %d (0x%x)",
			getpid (), sb, env_var_str, LDP_SID_BIT_MAX,
			ldp->sh_bit_val, ldp->sh_bit_val);
	}
      else
	{
	  ldp->sh_bit_val = (1 << sb);
	  ldp->sid_bit_mask = ldp->sh_bit_val - 1;

	  LDBG (0, "configured LDP sid bit (%u) from "
		LDP_ENV_SID_BIT "!  sid bit value %d (0x%x)", sb,
		ldp->sh_bit_val, ldp->sh_bit_val);
	}
    }

  clib_time_init (&ldpw->clib_time);
  clib_rwlock_init (&ldp->fd_table_lock);
  LDBG (0, "LDP initialization: done!");

  return 0;
}

int
close (int fd)
{
  int rv, refcnt, epfd;
  ldp_fd_entry_t *fde;
  u32 sh;

  if ((errno = -ldp_init ()))
    return -1;

  fde = ldp_fd_entry_lock_w_fd (fd);
  if (fde)
    {
      sh = ldp_fd_entry_sh (fde);
      epfd = vppcom_session_attr (sh, VPPCOM_ATTR_GET_LIBC_EPFD, 0, 0);
      if (epfd > 0)
	{
	  LDBG (0, "fd %d (0x%x): calling libc_close: epfd %u (0x%x)",
		fd, fd, epfd, epfd);

	  rv = libc_close (epfd);
	  if (rv < 0)
	    {
	      u32 size = sizeof (epfd);
	      epfd = 0;

	      (void) vppcom_session_attr (sh, VPPCOM_ATTR_SET_LIBC_EPFD,
					  &epfd, &size);
	    }
	}
      else if (PREDICT_FALSE (epfd < 0))
	{
	  errno = -epfd;
	  rv = -1;
	  ldp_fd_entry_unlock (fde);
	  goto done;
	}

      LDBG (0, "fd %d (0x%x): calling vppcom_session_close: sid %u (0x%x)",
	    fd, fd, sh, sh);

      refcnt = vppcom_session_attr (sh, VPPCOM_ATTR_GET_REFCNT, 0, 0);
      rv = vppcom_session_close (sh);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}

      ldp_fd_entry_unlock (fde);
      if (refcnt <= 1)
	ldp_fd_free_w_sh (sh);
    }
  else
    {
      LDBG (0, "fd %d (0x%x): calling libc_close", fd, fd);
      rv = libc_close (fd);
    }

done:

  LDBG (1, "fd %d (0x%x): returning %d (0x%x)", fd, fd, rv, rv);
  return rv;
}

ssize_t
read (int fd, void *buf, size_t nbytes)
{
  vcl_session_handle_t sh;
  ldp_fd_entry_t *fde;
  ssize_t size;

  if ((errno = -ldp_init ()))
    return -1;

  fde = ldp_fd_entry_lock_w_fd (fd);
  if (fde)
    {
      sh = ldp_fd_entry_sh (fde);
      LDBG (2, "fd %d (0x%x): calling vppcom_session_read(): sid %u (0x%x),"
	    " buf %p, nbytes %u", fd, fd, sh, sh, buf, nbytes);

      size = vppcom_session_read (sh, buf, nbytes);
      if (size < 0)
	{
	  errno = -size;
	  size = -1;
	}
      ldp_fd_entry_unlock (fde);
    }
  else
    {
      LDBG (2, "fd %d (0x%x): calling libc_read(): buf %p, nbytes %u",
	    fd, fd, buf, nbytes);

      size = libc_read (fd, buf, nbytes);
    }

  LDBG (2, "fd %d (0x%x): returning %d (0x%x)", fd, fd, size, size);
  return size;
}

ssize_t
readv (int fd, const struct iovec * iov, int iovcnt)
{
  ssize_t size = 0;
  u32 sid = ldp_sh_from_fd (fd);
  int rv = 0, i, total = 0;

  if ((errno = -ldp_init ()))
    return -1;

  if (sid != INVALID_SESSION_ID)
    {
      do
	{
	  for (i = 0; i < iovcnt; ++i)
	    {
	      LDBG (2, "fd %d (0x%x): calling vppcom_session_read() [%d]:"
		    " sid %u (0x%x), iov %p, iovcnt %d, total %d", fd, fd, i,
		    sid, sid, iov, iovcnt, total);

	      rv = vppcom_session_read (sid, iov[i].iov_base, iov[i].iov_len);
	      if (rv < 0)
		break;
	      else
		{
		  total += rv;
		  if (rv < iov[i].iov_len)
		    {
		      LDBG (2, "fd %d (0x%x): rv (%d) < iov[%d].iov_len (%d)",
			    fd, fd, rv, i, iov[i].iov_len);
		      break;
		    }
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
      LDBG (2, "fd %d (0x%x): calling libc_readv(): iov %p, iovcnt %d", fd,
	    fd, iov, iovcnt);

      size = libc_readv (fd, iov, iovcnt);
    }


  LDBG (2, "fd %d (0x%x): returning %d (0x%x)", fd, fd, size, size);
  return size;
}

ssize_t
write (int fd, const void *buf, size_t nbytes)
{
  vcl_session_handle_t sh;
  ldp_fd_entry_t *fde;
  ssize_t size = 0;

  if ((errno = -ldp_init ()))
    return -1;

  fde = ldp_fd_entry_lock_w_fd (fd);
  if (fde)
    {
      sh = ldp_fd_entry_sh (fde);
      LDBG (2, "fd %d (0x%x): calling vppcom_session_write(): sid %u (0x%x), "
	    "buf %p, nbytes %u", fd, fd, sh, sh, buf, nbytes);

      size = vppcom_session_write_msg (sh, (void *) buf, nbytes);
      if (size < 0)
	{
	  errno = -size;
	  size = -1;
	}
      ldp_fd_entry_unlock (fde);
    }
  else
    {
      LDBG (2, "fd %d (0x%x): calling libc_write(): buf %p, nbytes %u",
	    fd, fd, buf, nbytes);

      size = libc_write (fd, buf, nbytes);
    }

  LDBG (2, "fd %d (0x%x): returning %d (0x%x)", fd, fd, size, size);
  return size;
}

ssize_t
writev (int fd, const struct iovec * iov, int iovcnt)
{
  ssize_t size = 0, total = 0;
  u32 sid = ldp_sh_from_fd (fd);
  int i, rv = 0;

  /*
   * Use [f]printf() instead of clib_warning() to prevent recursion SIGSEGV.
   */

  if ((errno = -ldp_init ()))
    return -1;

  if (sid != INVALID_SESSION_ID)
    {
      do
	{
	  for (i = 0; i < iovcnt; ++i)
	    {
	      rv = vppcom_session_write_msg (sid, iov[i].iov_base,
					     iov[i].iov_len);
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
  const char *func_str = __func__;
  int rv = 0;
  va_list ap;
  u32 sid = ldp_sh_from_fd (fd);

  if ((errno = -ldp_init ()))
    return -1;

  va_start (ap, cmd);
  if (sid != INVALID_SESSION_ID)
    {
      int flags = va_arg (ap, int);
      u32 size;

      size = sizeof (flags);
      rv = -EOPNOTSUPP;
      switch (cmd)
	{
	case F_SETFL:
	  func_str = "vppcom_session_attr[SET_FLAGS]";
	  LDBG (2, "fd %d (0x%x): calling %s(): sid %u (0x%x) "
		"flags %d (0x%x), size %d", fd, fd, func_str, sid,
		sid, flags, flags, size);

	  rv = vppcom_session_attr (sid, VPPCOM_ATTR_SET_FLAGS, &flags,
				    &size);
	  break;

	case F_GETFL:
	  func_str = "vppcom_session_attr[GET_FLAGS]";
	  LDBG (2, "fd %d (0x%x): calling %s(): sid %u (0x%x), "
		"flags %d (0x%x), size %d", fd, fd, func_str, sid,
		sid, flags, flags, size);

	  rv = vppcom_session_attr (sid, VPPCOM_ATTR_GET_FLAGS, &flags,
				    &size);
	  if (rv == VPPCOM_OK)
	    {
	      LDBG (2, "fd %d (0x%x), cmd %d (F_GETFL): %s() "
		    "returned flags %d (0x%x)", fd, fd, cmd,
		    func_str, flags, flags);
	      rv = flags;
	    }
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
      func_str = "libc_vfcntl";

      LDBG (2, "fd %d (0x%x): calling %s(): cmd %d", fd, fd, func_str, cmd);

      rv = libc_vfcntl (fd, cmd, ap);
    }

  va_end (ap);

  if (LDP_DEBUG > 2)
    {
      if (rv < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: fd %d (0x%x): %s() failed! "
			"rv %d, errno = %d", getpid (), fd, fd,
			func_str, rv, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: fd %d (0x%x): returning %d (0x%x)",
		      getpid (), fd, fd, rv, rv);
    }
  return rv;
}

int
ioctl (int fd, unsigned long int cmd, ...)
{
  const char *func_str;
  int rv;
  va_list ap;
  u32 sid = ldp_sh_from_fd (fd);

  if ((errno = -ldp_init ()))
    return -1;

  va_start (ap, cmd);
  if (sid != INVALID_SESSION_ID)
    {
      func_str = "vppcom_session_attr[GET_NREAD]";

      switch (cmd)
	{
	case FIONREAD:
	  if (LDP_DEBUG > 2)
	    clib_warning
	      ("LDP<%d>: fd %d (0x%x): calling  %s(): sid %u (0x%x)",
	       getpid (), fd, fd, func_str, sid, sid);

	  rv = vppcom_session_attr (sid, VPPCOM_ATTR_GET_NREAD, 0, 0);
	  break;

	case FIONBIO:
	  {
	    u32 flags = va_arg (ap, int) ? O_NONBLOCK : 0;
	    u32 size = sizeof (flags);

	    /* TBD: When VPPCOM_ATTR_[GS]ET_FLAGS supports flags other than
	     *      non-blocking, the flags should be read here and merged
	     *      with O_NONBLOCK.
	     */
	    if (LDP_DEBUG > 2)
	      clib_warning ("LDP<%d>: fd %d (0x%x): calling %s(): "
			    "sid %u (0x%x), flags %d (0x%x), size %d",
			    getpid (), fd, fd, func_str, sid, sid,
			    flags, flags, size);

	    rv = vppcom_session_attr (sid, VPPCOM_ATTR_SET_FLAGS, &flags,
				      &size);
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
      func_str = "libc_vioctl";

      if (LDP_DEBUG > 2)
	clib_warning ("LDP<%d>: fd %d (0x%x): calling %s(): cmd %d",
		      getpid (), fd, fd, func_str, cmd);

      rv = libc_vioctl (fd, cmd, ap);
    }

  if (LDP_DEBUG > 2)
    {
      if (rv < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: fd %d (0x%x): %s() failed! "
			"rv %d, errno = %d", getpid (), fd, fd,
			func_str, rv, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: fd %d (0x%x): returning %d (0x%x)",
		      getpid (), fd, fd, rv, rv);
    }
  va_end (ap);
  return rv;
}

int
ldp_pselect (int nfds, fd_set * __restrict readfds,
	     fd_set * __restrict writefds,
	     fd_set * __restrict exceptfds,
	     const struct timespec *__restrict timeout,
	     const __sigset_t * __restrict sigmask)
{
  uword sid_bits, sid_bits_set, libc_bits, libc_bits_set;
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  u32 minbits = clib_max (nfds, BITS (uword)), sid;
  char *func_str = "##";
  f64 time_out;
  int rv, fd;

  if (nfds < 0)
    {
      errno = EINVAL;
      return -1;
    }

  if (timeout)
    {
      time_out = (timeout->tv_sec == 0 && timeout->tv_nsec == 0) ?
	(f64) 0 : (f64) timeout->tv_sec +
	(f64) timeout->tv_nsec / (f64) 1000000000;

      /* select as fine grained sleep */
      if (!nfds)
	{
	  LDBG (3, "sleeping for %.02f seconds", time_out);

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


  if (nfds <= ldp->sh_bit_val)
    {
      func_str = "libc_pselect";

      LDBG (3, "calling %s(): nfds %d, readfds %p, writefds %p, "
	    "exceptfds %p, timeout %p, sigmask %p", func_str, nfds,
	    readfds, writefds, exceptfds, timeout, sigmask);

      rv = libc_pselect (nfds, readfds, writefds, exceptfds,
			 timeout, sigmask);
      goto done;
    }

  if (PREDICT_FALSE (ldp->sh_bit_val > FD_SETSIZE / 2))
    {
      clib_warning ("LDP<%d>: ERROR: LDP sid bit value %d (0x%x) > "
		    "FD_SETSIZE/2 %d (0x%x)!", getpid (),
		    ldp->sh_bit_val, ldp->sh_bit_val,
		    FD_SETSIZE / 2, FD_SETSIZE / 2);
      errno = EOVERFLOW;
      return -1;
    }

  sid_bits = libc_bits = 0;
  u32 n_bytes = nfds / 8 + ((nfds % 8) ? 1 : 0);
  if (readfds)
    {
      clib_bitmap_validate (ldpw->sid_rd_bitmap, minbits);
      clib_bitmap_validate (ldpw->libc_rd_bitmap, minbits);
      clib_bitmap_validate (ldpw->rd_bitmap, minbits);
      clib_memcpy_fast (ldpw->rd_bitmap, readfds, n_bytes);
      memset (readfds, 0, n_bytes);

      /* *INDENT-OFF* */
      clib_bitmap_foreach (fd, ldpw->rd_bitmap, ({
	if (fd > nfds)
	  break;
        sid = ldp_sh_from_fd (fd);
        LDBG (3, "readfds: fd %d (0x%x), sid %u (0x%x)", fd, fd, sid, sid);
        if (sid == INVALID_SESSION_ID)
          clib_bitmap_set_no_check (ldpw->libc_rd_bitmap, fd, 1);
        else
          clib_bitmap_set_no_check (ldpw->sid_rd_bitmap,
                                    vppcom_session_index (sid), 1);
      }));
      /* *INDENT-ON* */

      sid_bits_set = clib_bitmap_last_set (ldpw->sid_rd_bitmap) + 1;
      sid_bits = (sid_bits_set > sid_bits) ? sid_bits_set : sid_bits;

      libc_bits_set = clib_bitmap_last_set (ldpw->libc_rd_bitmap) + 1;
      libc_bits = (libc_bits_set > libc_bits) ? libc_bits_set : libc_bits;

      LDBG (3, "readfds: sid_bits_set %d, sid_bits %d, "
	    "libc_bits_set %d, libc_bits %d", sid_bits_set,
	    sid_bits, libc_bits_set, libc_bits);
    }
  if (writefds)
    {
      clib_bitmap_validate (ldpw->sid_wr_bitmap, minbits);
      clib_bitmap_validate (ldpw->libc_wr_bitmap, minbits);
      clib_bitmap_validate (ldpw->wr_bitmap, minbits);
      clib_memcpy_fast (ldpw->wr_bitmap, writefds, n_bytes);
      memset (writefds, 0, n_bytes);

      /* *INDENT-OFF* */
      clib_bitmap_foreach (fd, ldpw->wr_bitmap, ({
	if (fd > nfds)
	  break;
        sid = ldp_sh_from_fd (fd);
        LDBG (3, "writefds: fd %d (0x%x), sid %u (0x%x)", fd, fd, sid, sid);
        if (sid == INVALID_SESSION_ID)
          clib_bitmap_set_no_check (ldpw->libc_wr_bitmap, fd, 1);
        else
          clib_bitmap_set_no_check (ldpw->sid_wr_bitmap,
                                    vppcom_session_index (sid), 1);
      }));
      /* *INDENT-ON* */

      sid_bits_set = clib_bitmap_last_set (ldpw->sid_wr_bitmap) + 1;
      sid_bits = (sid_bits_set > sid_bits) ? sid_bits_set : sid_bits;

      libc_bits_set = clib_bitmap_last_set (ldpw->libc_wr_bitmap) + 1;
      libc_bits = (libc_bits_set > libc_bits) ? libc_bits_set : libc_bits;

      LDBG (3, "writefds: sid_bits_set %d, sid_bits %d, "
	    "libc_bits_set %d, libc_bits %d",
	    sid_bits_set, sid_bits, libc_bits_set, libc_bits);
    }
  if (exceptfds)
    {
      clib_bitmap_validate (ldpw->sid_ex_bitmap, minbits);
      clib_bitmap_validate (ldpw->libc_ex_bitmap, minbits);
      clib_bitmap_validate (ldpw->ex_bitmap, minbits);
      clib_memcpy_fast (ldpw->ex_bitmap, exceptfds, n_bytes);
      memset (exceptfds, 0, n_bytes);

      /* *INDENT-OFF* */
      clib_bitmap_foreach (fd, ldpw->ex_bitmap, ({
	if (fd > nfds)
	  break;
        sid = ldp_sh_from_fd (fd);
        LDBG (3, "exceptfds: fd %d (0x%x), sid %u (0x%x)", fd, fd, sid, sid);
        if (sid == INVALID_SESSION_ID)
          clib_bitmap_set_no_check (ldpw->libc_ex_bitmap, fd, 1);
        else
          clib_bitmap_set_no_check (ldpw->sid_ex_bitmap,
                                    vppcom_session_index (sid), 1);
      }));
      /* *INDENT-ON* */

      sid_bits_set = clib_bitmap_last_set (ldpw->sid_ex_bitmap) + 1;
      sid_bits = (sid_bits_set > sid_bits) ? sid_bits_set : sid_bits;

      libc_bits_set = clib_bitmap_last_set (ldpw->libc_ex_bitmap) + 1;
      libc_bits = (libc_bits_set > libc_bits) ? libc_bits_set : libc_bits;

      LDBG (3, "exceptfds: sid_bits_set %d, sid_bits %d, "
	    "libc_bits_set %d, libc_bits %d",
	    sid_bits_set, sid_bits, libc_bits_set, libc_bits);
    }

  if (PREDICT_FALSE (!sid_bits && !libc_bits))
    {
      errno = EINVAL;
      rv = -1;
      goto done;
    }

  do
    {
      if (sid_bits)
	{
	  if (!ldpw->select_vcl)
	    {
	      func_str = "vppcom_select";

	      if (readfds)
		clib_memcpy_fast (ldpw->rd_bitmap, ldpw->sid_rd_bitmap,
				  vec_len (ldpw->rd_bitmap) *
				  sizeof (clib_bitmap_t));
	      if (writefds)
		clib_memcpy_fast (ldpw->wr_bitmap, ldpw->sid_wr_bitmap,
				  vec_len (ldpw->wr_bitmap) *
				  sizeof (clib_bitmap_t));
	      if (exceptfds)
		clib_memcpy_fast (ldpw->ex_bitmap, ldpw->sid_ex_bitmap,
				  vec_len (ldpw->ex_bitmap) *
				  sizeof (clib_bitmap_t));

	      rv = vppcom_select (sid_bits,
				  readfds ? (unsigned long *) ldpw->rd_bitmap
				  : NULL,
				  writefds ? (unsigned long *) ldpw->wr_bitmap
				  : NULL,
				  exceptfds ? (unsigned long *)
				  ldpw->ex_bitmap : NULL, 0);
	      if (rv < 0)
		{
		  errno = -rv;
		  rv = -1;
		}
	      else if (rv > 0)
		{
		  if (readfds)
		    {
                      /* *INDENT-OFF* */
                      clib_bitmap_foreach (sid, ldpw->rd_bitmap,
                        ({
                          fd = ldp_fd_from_sh (vppcom_session_handle (sid));
                          if (PREDICT_FALSE (fd < 0))
                            {
                              errno = EBADFD;
                              rv = -1;
                              goto done;
                            }
                          FD_SET (fd, readfds);
                        }));
                      /* *INDENT-ON* */
		    }
		  if (writefds)
		    {
                      /* *INDENT-OFF* */
                      clib_bitmap_foreach (sid, ldpw->wr_bitmap,
                        ({
                          fd = ldp_fd_from_sh (vppcom_session_handle (sid));
                          if (PREDICT_FALSE (fd < 0))
                            {
                              errno = EBADFD;
                              rv = -1;
                              goto done;
                            }
                          FD_SET (fd, writefds);
                        }));
                      /* *INDENT-ON* */
		    }
		  if (exceptfds)
		    {
                      /* *INDENT-OFF* */
                      clib_bitmap_foreach (sid, ldpw->ex_bitmap,
                        ({
                          fd = ldp_fd_from_sh (vppcom_session_handle (sid));
                          if (PREDICT_FALSE (fd < 0))
                            {
                              errno = EBADFD;
                              rv = -1;
                              goto done;
                            }
                          FD_SET (fd, exceptfds);
                        }));
                      /* *INDENT-ON* */
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
	  struct timespec tspec;

	  func_str = "libc_pselect";

	  if (readfds)
	    clib_memcpy_fast (readfds, ldpw->libc_rd_bitmap,
			      vec_len (ldpw->rd_bitmap) *
			      sizeof (clib_bitmap_t));
	  if (writefds)
	    clib_memcpy_fast (writefds, ldpw->libc_wr_bitmap,
			      vec_len (ldpw->wr_bitmap) *
			      sizeof (clib_bitmap_t));
	  if (exceptfds)
	    clib_memcpy_fast (exceptfds, ldpw->libc_ex_bitmap,
			      vec_len (ldpw->ex_bitmap) *
			      sizeof (clib_bitmap_t));
	  tspec.tv_sec = tspec.tv_nsec = 0;
	  rv = libc_pselect (libc_bits,
			     readfds ? readfds : NULL,
			     writefds ? writefds : NULL,
			     exceptfds ? exceptfds : NULL, &tspec, sigmask);
	  if (rv != 0)
	    goto done;
	}
    }
  while ((time_out == -1) || (clib_time_now (&ldpw->clib_time) < time_out));
  rv = 0;

done:
  /* TBD: set timeout to amount of time left */
  clib_bitmap_zero (ldpw->rd_bitmap);
  clib_bitmap_zero (ldpw->sid_rd_bitmap);
  clib_bitmap_zero (ldpw->libc_rd_bitmap);
  clib_bitmap_zero (ldpw->wr_bitmap);
  clib_bitmap_zero (ldpw->sid_wr_bitmap);
  clib_bitmap_zero (ldpw->libc_wr_bitmap);
  clib_bitmap_zero (ldpw->ex_bitmap);
  clib_bitmap_zero (ldpw->sid_ex_bitmap);
  clib_bitmap_zero (ldpw->libc_ex_bitmap);

  if (LDP_DEBUG > 3)
    {
      if (rv < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: %s() failed! "
			"rv %d, errno = %d", getpid (),
			func_str, rv, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: returning %d (0x%x)", getpid (), rv, rv);
    }
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

  if ((errno = -ldp_init ()))
    return -1;

  if (((domain == AF_INET) || (domain == AF_INET6)) &&
      ((sock_type == SOCK_STREAM) || (sock_type == SOCK_DGRAM)))
    {
      u8 proto = ((sock_type == SOCK_DGRAM) ?
		  VPPCOM_PROTO_UDP : VPPCOM_PROTO_TCP);

      LDBG (0, "calling vls_create: proto %u (%s), is_nonblocking %u",
	    proto, vppcom_proto_str (proto), is_nonblocking);

      rv = vls_create (proto, is_nonblocking);
      if (rv)
	{
	  errno = -rv;
	  rv = -1;
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

  vlsh = ldp_sh_from_fd (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;

      switch (addr->sa_family)
	{
	case AF_INET:
	  if (len != sizeof (struct sockaddr_in))
	    {
	      LDBG (0, "ERROR: fd %d (0x%x): sid %u (0x%x): Invalid "
		    "AF_INET addr len %u!", fd, fd, vlsh, vlsh, len);
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
	      LDBG (0, "ERROR: fd %d (0x%x): sid %u (0x%x): Invalid "
		    "AF_INET6 addr len %u!", fd, fd, vlsh, vlsh, len);
	      errno = EINVAL;
	      rv = -1;
	      goto done;
	    }
	  ep.is_ip4 = VPPCOM_IS_IP6;
	  ep.ip = (u8 *) & ((const struct sockaddr_in6 *) addr)->sin6_addr;
	  ep.port = (u16) ((const struct sockaddr_in6 *) addr)->sin6_port;
	  break;

	default:
	  LDBG (0, "ERROR: fd %d (0x%x): sid %u (0x%x): Unsupported address"
		" family %u!", fd, fd, vlsh, vlsh, addr->sa_family);
	  errno = EAFNOSUPPORT;
	  rv = -1;
	  goto done;
	}
      LDBG (0, "fd %d (0x%x): calling vls_bind(): sid %u (0x%x), addr %p,"
	    " len %u", fd, fd, vlsh, vlsh, addr, len);

      rv = vls_bind (vlsh, &ep);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      LDBG (0, "fd %d (0x%x): calling libc_bind(): addr %p, len %u",
	    fd, fd, addr, len);

      rv = libc_bind (fd, addr, len);
    }

done:
  LDBG (1, "fd %d (0x%x): returning %d", fd, fd, rv);

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
  int rv;
  const char *func_str;
  u32 sid = ldp_sh_from_fd (fd);

  if ((errno = -ldp_init ()))
    return -1;

  if (sid != INVALID_SESSION_ID)
    {
      vppcom_endpt_t ep;
      u8 addr_buf[sizeof (struct in6_addr)];
      u32 size = sizeof (ep);

      ep.ip = addr_buf;
      func_str = "vppcom_session_attr[GET_LCL_ADDR]";

      if (LDP_DEBUG > 2)
	clib_warning ("LDP<%d>: fd %d (0x%x): calling %s(): sid %u (0x%x), "
		      "addr %p, len %u",
		      getpid (), fd, fd, func_str, sid, sid, addr, len);

      rv = vppcom_session_attr (sid, VPPCOM_ATTR_GET_LCL_ADDR, &ep, &size);
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
      func_str = "libc_getsockname";

      if (LDP_DEBUG > 2)
	clib_warning ("LDP<%d>: fd %d (0x%x): calling %s(): "
		      "addr %p, len %u",
		      getpid (), fd, fd, func_str, addr, len);

      rv = libc_getsockname (fd, addr, len);
    }

  if (LDP_DEBUG > 2)
    {
      if (rv < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: fd %d (0x%x): %s() failed! "
			"rv %d, errno = %d", getpid (), fd, fd,
			func_str, rv, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: fd %d (0x%x): returning %d (0x%x)",
		      getpid (), fd, fd, rv, rv);
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
      LDBG (0, "ERROR: fd %d (0x%x): NULL addr, len %u", fd, fd, len);
      errno = EINVAL;
      rv = -1;
      goto done;
    }

  vlsh = ldp_sh_from_fd (fd);
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
      LDBG (0, "fd %d: calling vppcom_session_connect(): vlsh %u"
	    " addr %p len %u", fd, vlsh, addr, len);

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

  vlsh = ldp_sh_from_fd (fd);
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
  vls_handle_t vlsh = ldp_sh_from_fd (fd);
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

  vlsh = ldp_sh_from_fd (out_fd);
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

  vlsh = ldp_sh_from_fd (fd);
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

  vlsh = ldp_sh_from_fd (fd);
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

  sid = ldp_sh_from_fd (fd);
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

  vlsh = ldp_sh_from_fd (fd);
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
  u32 sid = ldp_sh_from_fd (fd);

  if ((errno = -ldp_init ()))
    return -1;

  if (sid != INVALID_SESSION_ID)
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

  vlsh = ldp_sh_from_fd (fd);
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
  u32 sid = ldp_sh_from_fd (fd);

  if ((errno = -ldp_init ()))
    return -1;

  if (sid != INVALID_SESSION_ID)
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

  vlsh = ldp_sh_from_fd (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      rv = -EOPNOTSUPP;

      switch (level)
	{
	case SOL_TCP:
	  switch (optname)
	    {
	    case TCP_NODELAY:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_TCP_NODELAY,
					optval, optlen);
	      break;
	    case TCP_MAXSEG:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_TCP_USER_MSS,
					optval, optlen);
	      break;
	    case TCP_KEEPIDLE:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_TCP_KEEPIDLE,
					optval, optlen);
	      break;
	    case TCP_KEEPINTVL:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_TCP_KEEPINTVL,
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
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_V6ONLY,
					optval, optlen);
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
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_LISTEN,
					optval, optlen);
	      break;
	    case SO_KEEPALIVE:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_KEEPALIVE,
					optval, optlen);
	      break;
	    case SO_PROTOCOL:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_PROTOCOL,
					optval, optlen);
	      *(int *) optval = *(int *) optval ? SOCK_DGRAM : SOCK_STREAM;
	      break;
	    case SO_SNDBUF:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_TX_FIFO_LEN,
					optval, optlen);
	      break;
	    case SO_RCVBUF:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_RX_FIFO_LEN,
					optval, optlen);
	      break;
	    case SO_REUSEADDR:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_REUSEADDR,
					optval, optlen);
	      break;
	    case SO_BROADCAST:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_BROADCAST,
					optval, optlen);
	      break;
	    case SO_ERROR:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_GET_ERROR,
					optval, optlen);
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

  vlsh = ldp_sh_from_fd (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      rv = -EOPNOTSUPP;

      switch (level)
	{
	case SOL_TCP:
	  switch (optname)
	    {
	    case TCP_NODELAY:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_TCP_NODELAY,
					(void *) optval, &optlen);
	      break;
	    case TCP_MAXSEG:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_TCP_USER_MSS,
					(void *) optval, &optlen);
	      break;
	    case TCP_KEEPIDLE:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_TCP_KEEPIDLE,
					(void *) optval, &optlen);
	      break;
	    case TCP_KEEPINTVL:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_TCP_KEEPINTVL,
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
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_V6ONLY,
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
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_KEEPALIVE,
					(void *) optval, &optlen);
	      break;
	    case SO_REUSEADDR:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_REUSEADDR,
					(void *) optval, &optlen);
	      break;
	    case SO_BROADCAST:
	      rv = vppcom_session_attr (vlsh, VPPCOM_ATTR_SET_BROADCAST,
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

  vlsh = ldp_sh_from_fd (fd);
  if (vlsh != VLS_INVALID_HANDLE)
    {
      LDBG (0, "fd %d (0x%x): calling vls_listen: sid %u (0x%x), n %d",
	    fd, fd, vlsh, vlsh, n);

      rv = vppcom_session_listen (vlsh, n);
      if (rv != VPPCOM_OK)
	{
	  errno = -rv;
	  rv = -1;
	}
    }
  else
    {
      LDBG (0, "fd %d (0x%x): calling libc_listen(): n %d", fd, fd, n);
      rv = libc_listen (fd, n);
    }

  LDBG (1, "fd %d (0x%x): returning %d (0x%x)", fd, fd, rv, rv);
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

  listen_vlsh = ldp_sh_from_fd (listen_fd);
  if (listen_vlsh != VLS_INVALID_HANDLE)
    {
      vppcom_endpt_t ep;
      u8 src_addr[sizeof (struct sockaddr_in6)];
      memset (&ep, 0, sizeof (ep));
      ep.ip = src_addr;

      LDBG (0, "listen fd %d (0x%x): calling vppcom_session_accept:"
	    " listen sid %u (0x%x), ep %p, flags 0x%x", listen_fd,
	    listen_fd, listen_vlsh, listen_vlsh, ep, flags);

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
	      (void) vls_close ((u32) accept_vlsh);
	      errno = -rv;
	      rv = -1;
	    }
	  else
	    {
	      rv = ldp_fd_alloc ((u32) accept_vlsh);
	      if (rv < 0)
		{
		  (void) vls_close ((u32) accept_vlsh);
		  errno = -rv;
		  rv = -1;
		}
	    }
	}
    }
  else
    {
      LDBG (0, "listen fd %d (0x%x): calling libc_accept4(): "
	    "addr %p, addr_len %p, flags 0x%x", listen_fd,
	    listen_fd, addr, addr_len, flags);

      rv = libc_accept4 (listen_fd, addr, addr_len, flags);
    }

  LDBG (1, "listen fd %d (0x%x): returning %d (0x%x)", listen_fd, listen_fd,
	rv, rv);

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

  vlsh = ldp_sh_from_fd (fd);
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
      LDBG (1, "fd %d (0x%x): calling libc_shutdown: how %d", fd, fd, how);
      rv = libc_shutdown (fd, how);
    }

  return rv;
}

int
epoll_create1 (int flags)
{
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
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

  rv = vls_epoll_create ();
  if (PREDICT_FALSE (rv < 0))
    {
      errno = -rv;
      rv = -1;
    }

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
  u32 vep_idx = ldp_sh_from_fd (epfd), sid;
  const char *func_str;
  int rv;

  if ((errno = -ldp_init ()))
    return -1;

  if (PREDICT_FALSE (vep_idx == INVALID_SESSION_ID))
    {
      /* The LDP epoll_create1 always creates VCL epfd's.
       * The app should never have a kernel base epoll fd unless it
       * was acquired outside of the LD_PRELOAD process context.
       * In any case, if we get one, punt it to libc_epoll_ctl.
       */
      func_str = "libc_epoll_ctl";

      LDBG (1, "epfd %d (0x%x): calling %s(): op %d, fd %d (0x%x),"
	    " event %p", epfd, epfd, func_str, op, fd, fd, event);

      rv = libc_epoll_ctl (epfd, op, fd, event);
      goto done;
    }

  sid = ldp_sh_from_fd (fd);

  LDBG (0, "epfd %d (0x%x), vep_idx %d (0x%x), sid %d (0x%x)",
	epfd, epfd, vep_idx, vep_idx, sid, sid);

  if (sid != INVALID_SESSION_ID)
    {
      func_str = "vppcom_epoll_ctl";

      LDBG (1, "epfd %d (0x%x): calling %s(): vep_idx %d (0x%x),"
	    " op %d, sid %u (0x%x), event %p", epfd, epfd,
	    func_str, vep_idx, vep_idx, sid, sid, event);

      rv = vppcom_epoll_ctl (vep_idx, op, sid, event);
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

      func_str = "vppcom_session_attr[GET_LIBC_EPFD]";
      libc_epfd = vppcom_session_attr (vep_idx, VPPCOM_ATTR_GET_LIBC_EPFD, 0,
				       0);
      LDBG (1, "epfd %d (0x%x), vep_idx %d (0x%x): %s() "
	    "returned libc_epfd %d (0x%x)", epfd, epfd,
	    vep_idx, vep_idx, func_str, libc_epfd, libc_epfd);

      if (!libc_epfd)
	{
	  func_str = "libc_epoll_create1";

	  LDBG (1, "epfd %d (0x%x), vep_idx %d (0x%x): "
		"calling %s(): EPOLL_CLOEXEC", epfd, epfd,
		vep_idx, vep_idx, func_str);

	  libc_epfd = libc_epoll_create1 (EPOLL_CLOEXEC);
	  if (libc_epfd < 0)
	    {
	      rv = libc_epfd;
	      goto done;
	    }

	  func_str = "vppcom_session_attr[SET_LIBC_EPFD]";
	  LDBG (1, "epfd %d (0x%x): calling %s(): vep_idx %d (0x%x),"
		" VPPCOM_ATTR_SET_LIBC_EPFD, libc_epfd %d (0x%x), size %d",
		epfd, epfd, func_str, vep_idx, vep_idx, libc_epfd,
		libc_epfd, size);

	  rv = vppcom_session_attr (vep_idx, VPPCOM_ATTR_SET_LIBC_EPFD,
				    &libc_epfd, &size);
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

      func_str = "libc_epoll_ctl";

      LDBG (1, "epfd %d (0x%x): calling %s(): libc_epfd %d (0x%x), "
	    "op %d, fd %d (0x%x), event %p", epfd, epfd, func_str,
	    libc_epfd, libc_epfd, op, fd, fd, event);

      rv = libc_epoll_ctl (libc_epfd, op, fd, event);
    }

done:
  if (LDP_DEBUG > 1)
    {
      if (rv < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: fd %d (0x%x): %s() failed! "
			"rv %d, errno = %d", getpid (), fd, fd,
			func_str, rv, errno_val);
	  errno = errno_val;
	}
      else
	clib_warning ("LDP<%d>: fd %d (0x%x): returning %d (0x%x)",
		      getpid (), fd, fd, rv, rv);
    }
  return rv;
}

static inline int
ldp_epoll_pwait (int epfd, struct epoll_event *events, int maxevents,
		 int timeout, const sigset_t * sigmask)
{
  ldp_worker_ctx_t *ldpw = ldp_worker_get_current ();
  double time_to_wait = (double) 0, time_out, now = 0;
  u32 vep_idx = ldp_sh_from_fd (epfd);
  int libc_epfd, rv = 0;

  if ((errno = -ldp_init ()))
    return -1;

  if (PREDICT_FALSE (!events || (timeout < -1)))
    {
      errno = EFAULT;
      return -1;
    }

  if (epfd == ldpw->vcl_mq_epfd)
    return libc_epoll_pwait (epfd, events, maxevents, timeout, sigmask);

  if (PREDICT_FALSE (vep_idx == INVALID_SESSION_ID))
    {
      LDBG (0, "epfd %d (0x%x): bad vep_idx %d (0x%x)!", epfd, epfd, vep_idx,
	    vep_idx);
      errno = EBADFD;
      return -1;
    }

  time_to_wait = ((timeout >= 0) ? (double) timeout / 1000 : 0);
  time_out = clib_time_now (&ldpw->clib_time) + time_to_wait;

  libc_epfd = vppcom_session_attr (vep_idx, VPPCOM_ATTR_GET_LIBC_EPFD, 0, 0);
  if (PREDICT_FALSE (libc_epfd < 0))
    {
      errno = -libc_epfd;
      rv = -1;
      goto done;
    }

  LDBG (2, "epfd %d (0x%x): vep_idx %d (0x%x), libc_epfd %d (0x%x), "
	"events %p, maxevents %d, timeout %d, sigmask %p: time_to_wait %.02f",
	epfd, epfd, vep_idx, vep_idx, libc_epfd, libc_epfd, events,
	maxevents, timeout, sigmask, time_to_wait, time_out);
  do
    {
      if (!ldpw->epoll_wait_vcl)
	{
	  LDBG (3, "epfd %d (0x%x): calling vcl_epoll_wait: vep_idx %d (0x%x)"
		" events %p, maxevents %d", epfd, epfd, vep_idx, vep_idx,
		events, maxevents);

	  rv = vppcom_epoll_wait (vep_idx, events, maxevents, 0);
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
	  LDBG (3, "epfd %d (0x%x): calling libc_epoll_wait: libc_epfd %d "
		"(0x%x), events %p, maxevents %d, sigmask %p", epfd, epfd,
		libc_epfd, libc_epfd, events, maxevents, sigmask);

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
  const char *func_str = __func__;
  int rv, i, n_revents = 0;
  u32 sid;
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

      LDBG (3, "fds[%d] fd %d (0x%0x) events = 0x%x revents = 0x%x",
	    i, fds[i].fd, fds[i].fd, fds[i].events, fds[i].revents);

      sid = ldp_sh_from_fd (fds[i].fd);
      if (sid != INVALID_SESSION_ID)
	{
	  fds[i].fd = -fds[i].fd;
	  vec_add2 (ldpw->vcl_poll, vp, 1);
	  vp->fds_ndx = i;
	  vp->sid = sid;
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
	  func_str = "vppcom_poll";

	  LDBG (3, "calling %s(): vcl_poll %p, n_sids %u (0x%x): "
		"n_libc_fds %u", func_str, ldpw->vcl_poll,
		vec_len (ldpw->vcl_poll), vec_len (ldpw->vcl_poll),
		vec_len (ldpw->libc_poll));

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
	  func_str = "libc_poll";

	  LDBG (3, "calling %s(): fds %p, nfds %u: n_sids %u",
		fds, nfds, vec_len (ldpw->vcl_poll));

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

  if (LDP_DEBUG > 3)
    {
      if (rv < 0)
	{
	  int errno_val = errno;
	  perror (func_str);
	  clib_warning ("LDP<%d>: ERROR: %s() failed! "
			"rv %d, errno = %d", getpid (),
			func_str, rv, errno_val);
	  errno = errno_val;
	}
      else
	{
	  clib_warning ("LDP<%d>: returning %d (0x%x): n_sids %u, "
			"n_libc_fds %d", getpid (), rv, rv,
			vec_len (ldpw->vcl_poll), vec_len (ldpw->libc_poll));

	  for (i = 0; i < nfds; i++)
	    {
	      if (fds[i].fd >= 0)
		{
		  if (LDP_DEBUG > 3)
		    clib_warning ("LDP<%d>: fds[%d].fd %d (0x%0x), "
				  ".events = 0x%x, .revents = 0x%x",
				  getpid (), i, fds[i].fd, fds[i].fd,
				  fds[i].events, fds[i].revents);
		}
	    }
	}
    }

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
