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
#include <sys/uio.h>
#include <limits.h>
#define __need_IOV_MAX
#include <bits/stdio_lim.h>
#include <netinet/tcp.h>

#include <vppinfra/types.h>
#include <vppinfra/time.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>

#include <vcl/vcom_socket.h>
#include <vcl/vcom_socket_wrapper.h>
#include <vcl/vcom.h>

#include <vcl/vppcom.h>

#ifndef IOV_MAX
#define IOV_MAX __IOV_MAX
#endif

/*
 * VCOM_SOCKET Private definitions and functions.
 */

typedef struct vcom_socket_main_t_
{
  u8 init;
  clib_time_t clib_time;
  pid_t my_pid;

  /* vcom_socket pool */
  vcom_socket_t *vsockets;

  /* Hash table for socketidx to fd mapping */
  uword *sockidx_by_fd;

  /* vcom_epoll pool */
  vcom_epoll_t *vepolls;

  /* Hash table for epollidx to epfd mapping */
  uword *epollidx_by_epfd;

  /* common epitem poll for all epfd */
  /* TBD: epitem poll per epfd */
  /* vcom_epitem pool */
  vcom_epitem_t *vepitems;

  /* Hash table for epitemidx to epfdfd mapping */
  uword *epitemidx_by_epfdfd;

  /* Hash table - key:epfd, value:vec of epitemidx */
  uword *epitemidxs_by_epfd;
  /* Hash table - key:fd, value:vec of epitemidx */
  uword *epitemidxs_by_fd;

  u8 *io_buffer;
} vcom_socket_main_t;

vcom_socket_main_t vcom_socket_main;


static int
vcom_socket_open_socket (int domain, int type, int protocol)
{
  int rv = -1;

  /* handle domains implemented by vpp */
  switch (domain)
    {
    case AF_INET:
    case AF_INET6:
      /* get socket type and
       * handle the socket types supported by vpp */
      switch (type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
	{
	case SOCK_STREAM:
	case SOCK_DGRAM:
	  /* the type argument serves a second purpose,
	   * in addition to specifying a socket type,
	   * it may include the bitwise OR of any of
	   * SOCK_NONBLOCK and SOCK_CLOEXEC, to modify
	   * the behavior of socket. */
	  rv = libc_socket (domain, type, protocol);
	  if (rv == -1)
	    rv = -errno;
	  break;

	default:
	  break;
	}

      break;

    default:
      break;
    }

  return rv;
}

static int
vcom_socket_open_epoll (int flags)
{
  int rv = -1;

  if (flags < 0)
    {
      return -EINVAL;
    }
  if (flags && (flags & ~EPOLL_CLOEXEC))
    {
      return -EINVAL;
    }

  /* flags can be either zero or EPOLL_CLOEXEC */
  rv = libc_epoll_create1 (flags);
  if (rv == -1)
    rv = -errno;

  return rv;
}

static int
vcom_socket_close_socket (int fd)
{
  int rv;

  rv = libc_close (fd);
  if (rv == -1)
    rv = -errno;

  return rv;
}

static int
vcom_socket_close_epoll (int epfd)
{
  int rv;

  rv = libc_close (epfd);
  if (rv == -1)
    rv = -errno;

  return rv;
}

/*
 * Public API functions
 */


int
vcom_socket_is_vcom_fd (int fd)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, fd);

  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);
      if (vsock && vsock->type == SOCKET_TYPE_VPPCOM_BOUND)
	return 1;
    }
  return 0;
}

int
vcom_socket_is_vcom_epfd (int epfd)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_epoll_t *vepoll;

  p = hash_get (vsm->epollidx_by_epfd, epfd);

  if (p)
    {
      vepoll = pool_elt_at_index (vsm->vepolls, p[0]);
      if (vepoll && vepoll->type == EPOLL_TYPE_VPPCOM_BOUND)
	return 1;
    }
  return 0;
}

static inline int
vcom_socket_get_sid (int fd)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, fd);

  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);
      if (vsock && vsock->type == SOCKET_TYPE_VPPCOM_BOUND)
	return vsock->sid;
    }
  return INVALID_SESSION_ID;
}

static inline int
vcom_socket_get_vep_idx (int epfd)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_epoll_t *vepoll;

  p = hash_get (vsm->epollidx_by_epfd, epfd);

  if (p)
    {
      vepoll = pool_elt_at_index (vsm->vepolls, p[0]);
      if (vepoll && vepoll->type == EPOLL_TYPE_VPPCOM_BOUND)
	return vepoll->vep_idx;
    }
  return INVALID_VEP_IDX;
}

static inline int
vcom_socket_get_sid_and_vsock (int fd, vcom_socket_t ** vsockp)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, fd);

  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);
      if (vsock && vsock->type == SOCKET_TYPE_VPPCOM_BOUND)
	{
	  *vsockp = vsock;
	  return vsock->sid;
	}
    }
  return INVALID_SESSION_ID;
}

static inline int
vcom_socket_get_vep_idx_and_vepoll (int epfd, vcom_epoll_t ** vepollp)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_epoll_t *vepoll;

  p = hash_get (vsm->epollidx_by_epfd, epfd);

  if (p)
    {
      vepoll = pool_elt_at_index (vsm->vepolls, p[0]);
      if (vepoll && vepoll->type == EPOLL_TYPE_VPPCOM_BOUND)
	{
	  *vepollp = vepoll;
	  return vepoll->vep_idx;
	}
    }
  return INVALID_VEP_IDX;
}


static int
vcom_socket_close_vepoll (int epfd)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_epoll_t *vepoll;

  p = hash_get (vsm->epollidx_by_epfd, epfd);
  if (!p)
    return -EBADF;

  vepoll = pool_elt_at_index (vsm->vepolls, p[0]);
  if (!vepoll)
    return -EBADF;

  if (vepoll->type != EPOLL_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (vepoll->count)
    {
      if (!vepoll->close)
	{
	  vepoll->close = 1;
	  return 0;
	}
      else
	{
	  return -EBADF;
	}
    }

  /* count is zero */
  rv = vppcom_session_close (vepoll->vep_idx);
  rv = vcom_socket_close_epoll (vepoll->epfd);

  vepoll_init (vepoll);
  hash_unset (vsm->epollidx_by_epfd, epfd);
  pool_put (vsm->vepolls, vepoll);

  return rv;
}

static int
vcom_socket_close_vsock (int fd)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  vcom_epitem_t *vepitem;

  i32 *vepitemidxs = 0;
  i32 *vepitemidxs_var = 0;

  p = hash_get (vsm->sockidx_by_fd, fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  rv = vppcom_session_close (vsock->sid);
  rv = vcom_socket_close_socket (vsock->fd);

  vsocket_init (vsock);
  hash_unset (vsm->sockidx_by_fd, fd);
  pool_put (vsm->vsockets, vsock);

  /*
   * NOTE:
   * Before calling close(), user should remove
   * this fd from the epoll-set of all epoll instances,
   * otherwise resource(epitems) leaks ensues.
   */

  /*
   * 00. close all epoll instances that are marked as "close"
   *     of which this fd is the "last" remaining member.
   * 01. epitems associated with this fd are intentionally
   *     not removed, see NOTE: above.
   * */

  /* does this fd participate in epoll */
  p = hash_get (vsm->epitemidxs_by_fd, fd);
  if (p)
    {
      vepitemidxs = *(i32 **) p;
      vec_foreach (vepitemidxs_var, vepitemidxs)
      {
	vepitem = pool_elt_at_index (vsm->vepitems, vepitemidxs_var[0]);
	if (vepitem && vepitem->fd == fd &&
	    vepitem->type == FD_TYPE_VCOM_SOCKET)
	  {
	    i32 vep_idx;
	    vcom_epoll_t *vepoll;
	    if ((vep_idx =
		 vcom_socket_get_vep_idx_and_vepoll (vepitem->epfd,
						     &vepoll)) !=
		INVALID_VEP_IDX)
	      {
		if (vepoll->close)
		  {
		    if (vepoll->count == 1)
		      {
			/*
			 * force count to zero and
			 * close this epoll instance
			 * */
			vepoll->count = 0;
			vcom_socket_close_vepoll (vepoll->epfd);
		      }
		    else
		      {
			vepoll->count -= 1;
		      }
		  }
	      }
	  }

      }
    }

  return rv;
}

int
vcom_socket_close (int __fd)
{
  int rv;

  if (vcom_socket_is_vcom_fd (__fd))
    {
      rv = vcom_socket_close_vsock (__fd);
    }
  else if (vcom_socket_is_vcom_epfd (__fd))
    {
      rv = vcom_socket_close_vepoll (__fd);
    }
  else
    {
      rv = -EBADF;
    }

  return rv;
}

ssize_t
vcom_socket_read (int __fd, void *__buf, size_t __nbytes)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (!__buf)
    {
      return -EINVAL;
    }

  rv = vcom_fcntl (__fd, F_GETFL, 0);
  if (rv < 0)
    {
      return rv;

    }

  /* is blocking */
  if (!(rv & O_NONBLOCK))
    {
      do
	{
	  rv = vppcom_session_read (vsock->sid, __buf, __nbytes);
	}
      /* coverity[CONSTANT_EXPRESSION_RESULT] */
      while (rv == -EAGAIN || rv == -EWOULDBLOCK);
      return rv;
    }
  /* The file descriptor refers to a socket and has been
   * marked nonblocking(O_NONBLOCK) and the read would
   * block.
   * */
  /* is non blocking */
  rv = vppcom_session_read (vsock->sid, __buf, __nbytes);
  return rv;
}

ssize_t
vcom_socket_readv (int __fd, const struct iovec * __iov, int __iovcnt)
{
  int rv;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;
  ssize_t total = 0, len = 0;
  int i;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (__iov == 0 || __iovcnt == 0 || __iovcnt > IOV_MAX)
    return -EINVAL;

  /* Sanity check */
  for (i = 0; i < __iovcnt; ++i)
    {
      if (SSIZE_MAX - len < __iov[i].iov_len)
	return -EINVAL;
      len += __iov[i].iov_len;
    }

  rv = vcom_fcntl (__fd, F_GETFL, 0);
  if (rv < 0)
    {
      return rv;
    }

  /* is blocking */
  if (!(rv & O_NONBLOCK))
    {
      do
	{
	  for (i = 0; i < __iovcnt; ++i)
	    {
	      rv = vppcom_session_read (vsock->sid, __iov[i].iov_base,
					__iov[i].iov_len);
	      if (rv < 0)
		break;
	      else
		{
		  total += rv;
		  if (rv < __iov[i].iov_len)
		    /* Read less than buffer provided, no point to continue */
		    break;
		}
	    }
	}
      /* coverity[CONSTANT_EXPRESSION_RESULT] */
      while ((rv == -EAGAIN || rv == -EWOULDBLOCK) && total == 0);
      return total;
    }

  /* is non blocking */
  for (i = 0; i < __iovcnt; ++i)
    {
      rv = vppcom_session_read (vsock->sid, __iov[i].iov_base,
				__iov[i].iov_len);
      if (rv < 0)
	{
	  if (total > 0)
	    break;
	  else
	    {
	      errno = rv;
	      return rv;
	    }
	}
      else
	{
	  total += rv;
	  if (rv < __iov[i].iov_len)
	    /* Read less than buffer provided, no point to continue */
	    break;
	}
    }
  return total;
}

ssize_t
vcom_socket_write (int __fd, const void *__buf, size_t __n)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  if (!__buf)
    {
      return -EINVAL;
    }

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  rv = vppcom_session_write (vsock->sid, (void *) __buf, __n);
  return rv;
}

ssize_t
vcom_socket_writev (int __fd, const struct iovec * __iov, int __iovcnt)
{
  int rv = -1;
  ssize_t total = 0;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;
  int i;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (__iov == 0 || __iovcnt == 0 || __iovcnt > IOV_MAX)
    return -EINVAL;

  for (i = 0; i < __iovcnt; ++i)
    {
      rv = vppcom_session_write (vsock->sid, __iov[i].iov_base,
				 __iov[i].iov_len);
      if (rv < 0)
	{
	  if (total > 0)
	    break;
	  else
	    return rv;
	}
      else
	total += rv;
    }
  return total;
}

/*
 * RETURN:  0 - invalid cmd
 *          1 - cmd not handled by vcom and vppcom
 *          2 - cmd handled by vcom socket resource
 *          3 - cmd handled by vppcom
 * */
/* TBD: incomplete list of cmd */
static int
vcom_socket_check_fcntl_cmd (int __cmd)
{
  switch (__cmd)
    {
      /*cmd not handled by vcom and vppcom */
      /* Fallthrough */
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
      return 1;

      /* cmd handled by vcom socket resource */
      /* Fallthrough */
    case F_GETFD:
    case F_SETFD:
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW:
    case F_GETOWN:
    case F_SETOWN:
      return 2;

      /* cmd handled by vcom and vppcom */
    case F_SETFL:
    case F_GETFL:
      return 3;

      /* cmd not handled by vcom and vppcom */
    default:
      return 1;
    }
  return 0;
}

static inline int
vcom_session_fcntl_va (int __sid, int __cmd, va_list __ap)
{
  int flags = va_arg (__ap, int);
  int rv = -EOPNOTSUPP;
  uint32_t size;

  size = sizeof (flags);
  if (__cmd == F_SETFL)
    {
      rv = vppcom_session_attr (__sid, VPPCOM_ATTR_SET_FLAGS, &flags, &size);
    }
  else if (__cmd == F_GETFL)
    {
      rv = vppcom_session_attr (__sid, VPPCOM_ATTR_GET_FLAGS, &flags, &size);
      if (rv == VPPCOM_OK)
	rv = flags;
    }

  return rv;
}

int
vcom_socket_fcntl_va (int __fd, int __cmd, va_list __ap)
{
  int rv = -EBADF;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  switch (vcom_socket_check_fcntl_cmd (__cmd))
    {
      /* invalid cmd */
    case 0:
      rv = -EBADF;
      break;
      /*cmd not handled by vcom and vppcom */
    case 1:
      rv = libc_vfcntl (vsock->fd, __cmd, __ap);
      break;
      /* cmd handled by vcom socket resource */
    case 2:
      rv = libc_vfcntl (vsock->fd, __cmd, __ap);
      break;
      /* cmd handled by vppcom */
    case 3:
      rv = vcom_session_fcntl_va (vsock->sid, __cmd, __ap);
      break;

    default:
      rv = -EINVAL;
      break;
    }

  return rv;
}

/*
 * RETURN:  0 - invalid cmd
 *          1 - cmd not handled by vcom and vppcom
 *          2 - cmd handled by vcom socket resource
 *          3 - cmd handled by vppcom
 */
static int
vcom_socket_check_ioctl_cmd (unsigned long int __cmd)
{
  int rc;

  switch (__cmd)
    {
      /* cmd handled by vppcom */
    case FIONREAD:
      rc = 3;
      break;

      /* cmd not handled by vcom and vppcom */
    default:
      rc = 1;
      break;
    }
  return rc;
}

static inline int
vcom_session_ioctl_va (int __sid, int __cmd, va_list __ap)
{
  int rv;

  switch (__cmd)
    {
    case FIONREAD:
      rv = vppcom_session_attr (__sid, VPPCOM_ATTR_GET_NREAD, 0, 0);
      break;

    case FIONBIO:
      {
	u32 flags = va_arg (__ap, int) ? O_NONBLOCK : 0;
	u32 len = sizeof (flags);
	rv = vppcom_session_attr (__sid, VPPCOM_ATTR_SET_FLAGS, &flags, &len);
      }
      break;

    default:
      rv = -EOPNOTSUPP;
      break;
    }
  return rv;
}

int
vcom_socket_ioctl_va (int __fd, unsigned long int __cmd, va_list __ap)
{
  int rv = -EBADF;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  switch (vcom_socket_check_ioctl_cmd (__cmd))
    {
      /* Not supported cmd */
    case 0:
      rv = -EOPNOTSUPP;
      break;

      /* cmd not handled by vcom and vppcom */
    case 1:
      rv = libc_vioctl (vsock->fd, __cmd, __ap);
      break;

      /* cmd handled by vcom socket resource */
    case 2:
      rv = libc_vioctl (vsock->fd, __cmd, __ap);
      break;

      /* cmd handled by vppcom */
    case 3:
      rv = vcom_session_ioctl_va (vsock->sid, __cmd, __ap);
      break;

    default:
      rv = -EINVAL;
      break;
    }

  return rv;
}

static inline int
vcom_socket_fds_2_sid_fds (
			    /* dest */
			    int *vcom_nsid_fds,
			    fd_set * __restrict vcom_rd_sid_fds,
			    fd_set * __restrict vcom_wr_sid_fds,
			    fd_set * __restrict vcom_ex_sid_fds,
			    /* src */
			    int vcom_nfds,
			    fd_set * __restrict vcom_readfds,
			    fd_set * __restrict vcom_writefds,
			    fd_set * __restrict vcom_exceptfds)
{
  int rv = 0;
  int fd;
  int sid;
  /* invalid max_sid is -1 */
  int max_sid = -1;
  int nsid = 0;

  /*
   *  set sid in sid sets corresponding to fd's in fd sets
   *  compute nsid and vcom_nsid_fds from sid sets
   */

  for (fd = 0; fd < vcom_nfds; fd++)
    {
      /*
       * F fd set, src
       * S sid set, dest
       */
#define _(S,F)                              \
      if ((F) && (S) && FD_ISSET (fd, (F))) \
        {                                   \
          sid = vcom_socket_get_sid (fd);   \
          if (sid != INVALID_SESSION_ID)    \
            {                               \
              FD_SET (sid, (S));            \
              if (sid > max_sid)            \
                {                           \
                  max_sid = sid;            \
                }                           \
              ++nsid;                       \
            }                               \
          else                              \
            {                               \
              rv = -EBADFD;                 \
              goto done;                    \
            }                               \
        }


      _(vcom_rd_sid_fds, vcom_readfds);
      _(vcom_wr_sid_fds, vcom_writefds);
      _(vcom_ex_sid_fds, vcom_exceptfds);
#undef _
    }

  *vcom_nsid_fds = max_sid != -1 ? max_sid + 1 : 0;
  rv = nsid;

done:
  return rv;
}

/*
 * PRE: 00. sid sets were derived from fd sets
 *      01. sid sets were updated with sids that actually changed
 *          status
 *      02. fd sets still has watched fds
 *
 * This function will modify in place fd sets to indicate which fd's
 * actually changed status(inferred from sid sets)
 */
static inline int
vcom_socket_sid_fds_2_fds (
			    /* dest */
			    int *new_vcom_nfds,
			    int vcom_nfds,
			    fd_set * __restrict vcom_readfds,
			    fd_set * __restrict vcom_writefds,
			    fd_set * __restrict vcom_exceptfds,
			    /* src */
			    int vcom_nsid_fds,
			    fd_set * __restrict vcom_rd_sid_fds,
			    fd_set * __restrict vcom_wr_sid_fds,
			    fd_set * __restrict vcom_ex_sid_fds)
{
  int rv = 0;
  int fd;
  int sid;
  /* invalid max_fd is -1 */
  int max_fd = -1;
  int nfd = 0;


  /*
   *  modify in place fd sets to indicate which fd's
   * actually changed status(inferred from sid sets)
   */
  for (fd = 0; fd < vcom_nfds; fd++)
    {
      /*
       * F fd set, dest
       * S sid set, src
       */
#define _(S,F)                              \
      if ((F) && (S) && FD_ISSET (fd, (F))) \
        {                                   \
          sid = vcom_socket_get_sid (fd);   \
          if (sid != INVALID_SESSION_ID)    \
            {                               \
              if (!FD_ISSET (sid, (S)))     \
                {                           \
                   FD_CLR(fd, (F));         \
                }                           \
            }                               \
          else                              \
            {                               \
              rv = -EBADFD;                 \
              goto done;                    \
            }                               \
        }


      _(vcom_rd_sid_fds, vcom_readfds);
      _(vcom_wr_sid_fds, vcom_writefds);
      _(vcom_ex_sid_fds, vcom_exceptfds);
#undef _
    }

  /*
   *  compute nfd and new_vcom_nfds from fd sets
   */
  for (fd = 0; fd < vcom_nfds; fd++)
    {

#define _(F)                                \
      if ((F) && FD_ISSET (fd, (F)))        \
        {                                   \
          if (fd > max_fd)                  \
            {                               \
              max_fd = fd;                  \
            }                               \
          ++nfd;                            \
        }


      _(vcom_readfds);
      _(vcom_writefds);
      _(vcom_exceptfds);
#undef _

    }

  *new_vcom_nfds = max_fd != -1 ? max_fd + 1 : 0;
  rv = nfd;

done:
  return rv;
}

/*
 * PRE:
 * vom_socket_select is always called with
 * timeout->tv_sec and timeout->tv_usec set to zero.
 * hence vppcom_select return immediately.
 */
/*
 * TBD: do{body;} while(timeout conditional); timeout loop
 */
int
vcom_socket_select (int vcom_nfds, fd_set * __restrict vcom_readfds,
		    fd_set * __restrict vcom_writefds,
		    fd_set * __restrict vcom_exceptfds,
		    struct timeval *__restrict timeout)
{
  static unsigned long vcom_nsid_fds = 0;
  int vcom_nsid = 0;
  int rv = -EBADF;

  int new_vcom_nfds = 0;
  int new_vcom_nfd = 0;

  /* vcom sid fds */
  fd_set vcom_rd_sid_fds;
  fd_set vcom_wr_sid_fds;
  fd_set vcom_ex_sid_fds;

  /* in seconds eg. 3.123456789 seconds */
  double time_to_wait = (double) 0;

  /* validate inputs */
  if (vcom_nfds < 0)
    {
      return -EINVAL;
    }

  /* convert timeval timeout to double time_to_wait */
  if (timeout)
    {
      if (timeout->tv_sec == 0 && timeout->tv_usec == 0)
	{
	  /* polling: vppcom_select returns immediately */
	  time_to_wait = (double) 0;
	}
      else
	{
	  /*TBD:  use timeval api */
	  time_to_wait = (double) timeout->tv_sec +
	    (double) timeout->tv_usec / (double) 1000000 +
	    (double) (timeout->tv_usec % 1000000) / (double) 1000000;
	}
    }
  else
    {
      /*
       * no timeout: vppcom_select can block indefinitely
       * waiting for a file descriptor to become ready
       * */
      /* set to a phantom value */
      time_to_wait = ~0;
    }

  /* zero the sid_sets */
  /*
   * F fd set
   * S sid set
   */
#define _(S,F)                          \
  if ((F))                              \
    {                                   \
      FD_ZERO ((S));                    \
    }


  _(&vcom_rd_sid_fds, vcom_readfds);
  _(&vcom_wr_sid_fds, vcom_writefds);
  _(&vcom_ex_sid_fds, vcom_exceptfds);
#undef _

  if (vcom_nfds == 0)
    {
      if (time_to_wait > 0)
	{
	  if (VCOM_DEBUG > 0)
	    fprintf (stderr,
		     "[%d] vcom_socket_select called to "
		     "emulate delay_ns()!\n", getpid ());
	  rv = vppcom_select (0, NULL, NULL, NULL, time_to_wait);
	}
      else
	{
	  fprintf (stderr, "[%d] vcom_socket_select called vcom_nfds = 0 "
		   "and invalid time_to_wait (%f)!\n",
		   getpid (), time_to_wait);
	}
      return 0;
    }

  /* populate read, write and except sid_sets */
  vcom_nsid = vcom_socket_fds_2_sid_fds (
					  /* dest */
					  vcom_readfds || vcom_writefds
					  || vcom_exceptfds ? (int *)
					  &vcom_nsid_fds : NULL,
					  vcom_readfds ? &vcom_rd_sid_fds :
					  NULL,
					  vcom_writefds ? &vcom_wr_sid_fds :
					  NULL,
					  vcom_exceptfds ? &vcom_ex_sid_fds :
					  NULL,
					  /* src */
					  vcom_nfds,
					  vcom_readfds,
					  vcom_writefds, vcom_exceptfds);
  if (vcom_nsid < 0)
    {
      return vcom_nsid;
    }

  rv = vppcom_select (vcom_nsid_fds,
		      vcom_readfds ? (unsigned long *) &vcom_rd_sid_fds :
		      NULL,
		      vcom_writefds ? (unsigned long *) &vcom_wr_sid_fds :
		      NULL,
		      vcom_exceptfds ? (unsigned long *) &vcom_ex_sid_fds :
		      NULL, time_to_wait);
  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] called vppcom_select(): "
	     "'%04d'='%04d'\n", getpid (), rv, (int) vcom_nsid_fds);

  /* check if any file descriptors changed status */
  if (rv > 0)
    {
      /*
       * on exit, sets are modified in place to indicate which
       * file descriptors actually changed status
       * */

      /*
       * comply with pre-condition
       * do not clear vcom fd sets befor calling
       * vcom_socket_sid_fds_2_fds
       */
      new_vcom_nfd = vcom_socket_sid_fds_2_fds (
						 /* dest */
						 &new_vcom_nfds,
						 vcom_nfds,
						 vcom_readfds,
						 vcom_writefds,
						 vcom_exceptfds,
						 /* src */
						 vcom_nsid_fds,
						 vcom_readfds ?
						 &vcom_rd_sid_fds : NULL,
						 vcom_writefds ?
						 &vcom_wr_sid_fds : NULL,
						 vcom_exceptfds ?
						 &vcom_ex_sid_fds : NULL);
      if (new_vcom_nfd < 0)
	{
	  return new_vcom_nfd;
	}
      if (new_vcom_nfds < 0)
	{
	  return -EINVAL;
	}
      rv = new_vcom_nfd;
    }
  return rv;
}


int
vcom_socket_socket (int __domain, int __type, int __protocol)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  vcom_socket_t *vsock;

  i32 fd;
  i32 sid;
  i32 sockidx;
  u8 is_nonblocking = __type & SOCK_NONBLOCK ? 1 : 0;
  int type = __type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

  fd = vcom_socket_open_socket (__domain, __type, __protocol);
  if (fd < 0)
    {
      rv = fd;
      goto out;
    }

  sid = vppcom_session_create (VPPCOM_VRF_DEFAULT,
			       (type == SOCK_DGRAM) ?
			       VPPCOM_PROTO_UDP : VPPCOM_PROTO_TCP,
			       is_nonblocking);
  if (sid < 0)
    {
      rv = sid;
      goto out_close_socket;
    }

  pool_get (vsm->vsockets, vsock);
  vsocket_init (vsock);

  sockidx = vsock - vsm->vsockets;
  hash_set (vsm->sockidx_by_fd, fd, sockidx);

  vsocket_set (vsock, fd, sid, SOCKET_TYPE_VPPCOM_BOUND);
  return fd;

out_close_socket:
  vcom_socket_close_socket (fd);
out:
  return rv;
}

int
vcom_socket_socketpair (int __domain, int __type, int __protocol,
			int __fds[2])
{
/* TBD: */
  return 0;
}

int
vcom_socket_bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  vppcom_endpt_t ep;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (!__addr)
    {
      return -EINVAL;
    }

  ep.vrf = VPPCOM_VRF_DEFAULT;
  switch (__addr->sa_family)
    {
    case AF_INET:
      if (__len != sizeof (struct sockaddr_in))
	{
	  return -EINVAL;
	}
      ep.is_ip4 = VPPCOM_IS_IP4;
      ep.ip = (u8 *) & ((const struct sockaddr_in *) __addr)->sin_addr;
      ep.port = (u16) ((const struct sockaddr_in *) __addr)->sin_port;
      break;

    case AF_INET6:
      if (__len != sizeof (struct sockaddr_in6))
	{
	  return -EINVAL;
	}
      ep.is_ip4 = VPPCOM_IS_IP6;
      ep.ip = (u8 *) & ((const struct sockaddr_in6 *) __addr)->sin6_addr;
      ep.port = (u16) ((const struct sockaddr_in6 *) __addr)->sin6_port;
      break;

    default:
      return -1;
      break;
    }

  rv = vppcom_session_bind (vsock->sid, &ep);
  return rv;
}

static inline int
vcom_session_getsockname (int sid, vppcom_endpt_t * ep)
{
  int rv;
  uint32_t size = sizeof (*ep);

  rv = vppcom_session_attr (sid, VPPCOM_ATTR_GET_LCL_ADDR, ep, &size);
  return rv;
}

int
vcom_socket_getsockname (int __fd, __SOCKADDR_ARG __addr,
			 socklen_t * __restrict __len)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;


  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (!__addr || !__len)
    return -EFAULT;

  vppcom_endpt_t ep;
  ep.ip = (u8 *) & ((const struct sockaddr_in *) __addr)->sin_addr;
  rv = vcom_session_getsockname (vsock->sid, &ep);
  if (rv == 0)
    {
      if (ep.vrf == VPPCOM_VRF_DEFAULT)
	{
	  __addr->sa_family = ep.is_ip4 == VPPCOM_IS_IP4 ? AF_INET : AF_INET6;
	  switch (__addr->sa_family)
	    {
	    case AF_INET:
	      ((struct sockaddr_in *) __addr)->sin_port = ep.port;
	      *__len = sizeof (struct sockaddr_in);
	      break;

	    case AF_INET6:
	      ((struct sockaddr_in6 *) __addr)->sin6_port = ep.port;
	      *__len = sizeof (struct sockaddr_in6);
	      break;

	    default:
	      break;
	    }
	}
    }

  return rv;
}

int
vcom_socket_connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  vppcom_endpt_t ep;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);

      ep.vrf = VPPCOM_VRF_DEFAULT;
      switch (__addr->sa_family)
	{
	case AF_INET:
	  ep.is_ip4 = VPPCOM_IS_IP4;
	  ep.ip =
	    (uint8_t *) & ((const struct sockaddr_in *) __addr)->sin_addr;
	  ep.port =
	    (uint16_t) ((const struct sockaddr_in *) __addr)->sin_port;
	  break;

	case AF_INET6:
	  ep.is_ip4 = VPPCOM_IS_IP6;
	  ep.ip =
	    (uint8_t *) & ((const struct sockaddr_in6 *) __addr)->sin6_addr;
	  ep.port =
	    (uint16_t) ((const struct sockaddr_in6 *) __addr)->sin6_port;
	  break;

	default:
	  return -1;
	  break;
	}

      rv = vppcom_session_connect (vsock->sid, &ep);
    }
  return rv;
}

static inline int
vcom_session_getpeername (int sid, vppcom_endpt_t * ep)
{
  int rv;
  uint32_t size = sizeof (*ep);

  rv = vppcom_session_attr (sid, VPPCOM_ATTR_GET_PEER_ADDR, ep, &size);
  return rv;
}

static inline int
vcom_socket_copy_ep_to_sockaddr (__SOCKADDR_ARG __addr,
				 socklen_t * __restrict __len,
				 vppcom_endpt_t * ep)
{
  int rv = 0;
  int sa_len, copy_len;

  __addr->sa_family = (ep->is_ip4 == VPPCOM_IS_IP4) ? AF_INET : AF_INET6;
  switch (__addr->sa_family)
    {
    case AF_INET:
      ((struct sockaddr_in *) __addr)->sin_port = ep->port;
      if (*__len > sizeof (struct sockaddr_in))
	*__len = sizeof (struct sockaddr_in);
      sa_len = sizeof (struct sockaddr_in) - sizeof (struct in_addr);
      copy_len = *__len - sa_len;
      if (copy_len > 0)
	memcpy (&((struct sockaddr_in *) __addr)->sin_addr, ep->ip, copy_len);
      break;

    case AF_INET6:
      ((struct sockaddr_in6 *) __addr)->sin6_port = ep->port;
      if (*__len > sizeof (struct sockaddr_in6))
	*__len = sizeof (struct sockaddr_in6);
      sa_len = sizeof (struct sockaddr_in6) - sizeof (struct in6_addr);
      copy_len = *__len - sa_len;
      if (copy_len > 0)
	memcpy (((struct sockaddr_in6 *) __addr)->sin6_addr.
		__in6_u.__u6_addr8, ep->ip, copy_len);
      break;

    default:
      /* Not possible */
      rv = -EAFNOSUPPORT;
      break;
    }

  return rv;
}

int
vcom_socket_getpeername (int __fd, __SOCKADDR_ARG __addr,
			 socklen_t * __restrict __len)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;
  u8 src_addr[sizeof (struct sockaddr_in6)];
  vppcom_endpt_t ep;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (!__addr || !__len)
    return -EFAULT;

  ep.ip = src_addr;
  rv = vcom_session_getpeername (vsock->sid, &ep);
  if (rv == 0)
    rv = vcom_socket_copy_ep_to_sockaddr (__addr, __len, &ep);

  return rv;
}

ssize_t
vcom_socket_send (int __fd, const void *__buf, size_t __n, int __flags)
{
  return vcom_socket_sendto (__fd, __buf, __n, __flags, NULL, 0);
}

/* NOTE: this function is not thread safe or 32-bit friendly */
ssize_t
vcom_socket_sendfile (int __out_fd, int __in_fd, off_t * __offset,
		      size_t __len)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;
  size_t n_bytes_left = __len;
  u32 out_sockidx, out_sid = ~0;
  size_t bytes_to_read;
  int nbytes;
  int rv, errno_val;
  ssize_t results = 0;
  u8 eagain = 0;

  if (VCOM_DEBUG > 2)
    clib_warning ("[%d] __out_fd %d, __in_fd %d, __offset %p, __len %lu",
		  getpid (), __out_fd, __in_fd, __offset, __len);

  p = hash_get (vsm->sockidx_by_fd, __out_fd);
  if (!p)
    {
      clib_warning ("[%d] ERROR: invalid __out_fd (%d), fd lookup failed!",
		    getpid (), __len);
      return -EBADF;
    }
  out_sockidx = p[0];
  vsock = pool_elt_at_index (vsm->vsockets, out_sockidx);
  if (!vsock)
    {
      clib_warning ("[%d] ERROR: invalid __out_fd (%d) / out_sockidx %u, "
		    "missing vsock pool element!",
		    getpid (), __len, out_sockidx);
      return -ENOTSOCK;
    }
  out_sid = vsock->sid;
  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    {
      clib_warning ("[%d] ERROR: __out_fd (%d), socket (sid %u) "
		    "is not VCL bound!", getpid (), __out_fd, out_sid);
      return -EINVAL;
    }

  if (__offset)
    {
      off_t offset = lseek (__in_fd, *__offset, SEEK_SET);
      if (offset == -1)
	{
	  errno_val = errno;
	  perror ("lseek()");
	  clib_warning ("[%d] ERROR: lseek SEEK_SET failed: "
			"in_fd %d, offset %p (%ld), rv %ld, errno %d",
			getpid (), __in_fd, __offset, *__offset, offset,
			errno_val);
	  return -errno_val;
	}

      ASSERT (offset == *__offset);
    }

  do
    {
      rv = vppcom_session_attr (out_sid, VPPCOM_ATTR_GET_NWRITE, 0, 0);
      if (rv < 0)
	{
	  clib_warning ("[%d] ERROR: vppcom_session_attr (out_sid (%u), "
			"VPPCOM_ATTR_GET_NWRITE, 0, 0) returned %d (%s)!",
			getpid (), out_sid, rv, vppcom_retval_str (rv));
	  vec_reset_length (vsm->io_buffer);
	  return rv;
	}

      bytes_to_read = (size_t) rv;
      if (VCOM_DEBUG > 2)
	clib_warning ("[%d] results %ld, n_bytes_left %lu, "
		      "bytes_to_read %lu", getpid (), results,
		      n_bytes_left, bytes_to_read);
      if (bytes_to_read == 0)
	{
	  u32 flags, flags_len = sizeof (flags);
	  rv = vppcom_session_attr (out_sid, VPPCOM_ATTR_GET_FLAGS, &flags,
				    &flags_len);
	  ASSERT (rv == VPPCOM_OK);

	  if (flags & O_NONBLOCK)
	    {
	      if (!results)
		{
		  if (VCOM_DEBUG > 2)
		    clib_warning ("[%d] EAGAIN", getpid ());
		  eagain = 1;
		}
	      goto update_offset;
	    }
	  else
	    continue;
	}
      bytes_to_read = clib_min (n_bytes_left, bytes_to_read);
      vec_validate (vsm->io_buffer, bytes_to_read);
      nbytes = libc_read (__in_fd, vsm->io_buffer, bytes_to_read);
      if (nbytes < 0)
	{
	  errno_val = errno;
	  perror ("read()");
	  clib_warning ("[%d] ERROR: libc_read (__in_fd (%d), "
			"io_buffer %p, bytes_to_read %lu) returned "
			"errno %d",
			getpid (), __in_fd, vsm->io_buffer,
			bytes_to_read, errno_val);
	  if (results == 0)
	    {
	      vec_reset_length (vsm->io_buffer);
	      return -errno_val;
	    }
	  goto update_offset;
	}
      rv = vppcom_session_write (out_sid, vsm->io_buffer, nbytes);
      if (rv < 0)
	{
	  clib_warning ("[%d] ERROR: vppcom_session_write ("
			"out_sid %u, io_buffer %p, nbytes %d) "
			"returned %d (%s)",
			getpid (), out_sid, vsm->io_buffer, nbytes,
			rv, vppcom_retval_str (rv));
	  if (results == 0)
	    {
	      vec_reset_length (vsm->io_buffer);
	      return rv;
	    }
	  goto update_offset;
	}

      results += nbytes;
      ASSERT (n_bytes_left >= nbytes);
      n_bytes_left = n_bytes_left - nbytes;
    }
  while (n_bytes_left > 0);

update_offset:
  if (__offset)
    {
      off_t offset = lseek (__in_fd, *__offset, SEEK_SET);
      if (offset == -1)
	{
	  errno_val = errno;
	  perror ("lseek()");
	  clib_warning ("[%d] ERROR: lseek (__in_fd %d, __offset %p "
			"(%ld), SEEK_SET) returned errno %d",
			getpid (), __in_fd, __offset, *__offset, errno_val);
	  vec_reset_length (vsm->io_buffer);
	  return -errno_val;
	}

      *__offset += results + 1;
    }

  vec_reset_length (vsm->io_buffer);
  return eagain ? -EAGAIN : results;
}

ssize_t
vcom_socket_recv (int __fd, void *__buf, size_t __n, int __flags)
{
  int rv = -1;
  rv = vcom_socket_recvfrom (__fd, __buf, __n, __flags, NULL, 0);
  return rv;
}

/*
 * RETURN   1 if __fd is (SOCK_STREAM, SOCK_SEQPACKET),
 * 0 otherwise
 * */
int
vcom_socket_is_connection_mode_socket (int __fd)
{
  int rv = -1;
  /* TBD define new vppcom api */
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  int type;
  socklen_t optlen;

  p = hash_get (vsm->sockidx_by_fd, __fd);

  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);
      if (vsock && vsock->type == SOCKET_TYPE_VPPCOM_BOUND)
	{
	  optlen = sizeof (type);
	  rv = libc_getsockopt (__fd, SOL_SOCKET, SO_TYPE, &type, &optlen);
	  if (rv != 0)
	    {
	      return 0;
	    }
	  /* get socket type */
	  switch (type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
	    {
	    case SOCK_STREAM:
	    case SOCK_SEQPACKET:
	      return 1;
	      break;

	    default:
	      return 0;
	      break;
	    }
	}
    }
  return 0;
}

static inline ssize_t
vcom_session_sendto (int __sid, void *__buf, size_t __n,
		     int __flags, __CONST_SOCKADDR_ARG __addr,
		     socklen_t __addr_len)
{
  vppcom_endpt_t *ep = 0;
  vppcom_endpt_t _ep;

  if (__addr)
    {
      ep = &_ep;
      ep->vrf = VPPCOM_VRF_DEFAULT;
      switch (__addr->sa_family)
	{
	case AF_INET:
	  ep->is_ip4 = VPPCOM_IS_IP4;
	  ep->ip =
	    (uint8_t *) & ((const struct sockaddr_in *) __addr)->sin_addr;
	  ep->port =
	    (uint16_t) ((const struct sockaddr_in *) __addr)->sin_port;
	  break;

	case AF_INET6:
	  ep->is_ip4 = VPPCOM_IS_IP6;
	  ep->ip =
	    (uint8_t *) & ((const struct sockaddr_in6 *) __addr)->sin6_addr;
	  ep->port =
	    (uint16_t) ((const struct sockaddr_in6 *) __addr)->sin6_port;
	  break;

	default:
	  return -EAFNOSUPPORT;
	}
    }

  return vppcom_session_sendto (__sid, __buf, __n, __flags, ep);;
}

ssize_t
vcom_socket_sendto (int __fd, const void *__buf, size_t __n,
		    int __flags, __CONST_SOCKADDR_ARG __addr,
		    socklen_t __addr_len)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  if (!__buf)
    {
      return -EINVAL;
    }

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    {
      return -EINVAL;
    }

  if (vcom_socket_is_connection_mode_socket (__fd))
    {
      /* ignore __addr and _addr_len */
      /* and EISCONN may be returned when they are not NULL and 0 */
      if ((__addr != NULL) || (__addr_len != 0))
	{
	  return -EISCONN;
	}
    }
  else
    {
      if (!__addr)
	{
	  return -EDESTADDRREQ;
	}
      /* not a vppcom supported address family */
      if (!((__addr->sa_family == AF_INET) ||
	    (__addr->sa_family == AF_INET6)))
	{
	  return -EINVAL;
	}
    }

  return vcom_session_sendto (vsock->sid, (void *) __buf, (int) __n,
			      __flags, __addr, __addr_len);
}

static inline ssize_t
vcom_session_recvfrom (int __sid, void *__restrict __buf, size_t __n,
		       int __flags, __SOCKADDR_ARG __addr,
		       socklen_t * __restrict __addr_len)
{
  int rv;
  vppcom_endpt_t ep;
  u8 src_addr[sizeof (struct sockaddr_in6)];

  if (__addr)
    {
      ep.ip = src_addr;
      rv = vppcom_session_recvfrom (__sid, __buf, __n, __flags, &ep);

      if (rv > 0)
	rv = vcom_socket_copy_ep_to_sockaddr (__addr, __addr_len, &ep);
    }
  else
    rv = vppcom_session_recvfrom (__sid, __buf, __n, __flags, NULL);

  return rv;
}

ssize_t
vcom_socket_recvfrom (int __fd, void *__restrict __buf, size_t __n,
		      int __flags, __SOCKADDR_ARG __addr,
		      socklen_t * __restrict __addr_len)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  if (__addr && !__addr_len)
    return -EINVAL;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    {
      return -EINVAL;
    }

  rv = vcom_session_recvfrom (vsock->sid, __buf, __n,
			      __flags, __addr, __addr_len);
  return rv;
}

/* TBD: move it to vppcom */
static inline ssize_t
vcom_session_sendmsg (int __sid, const struct msghdr *__message, int __flags)
{
  int rv = -1;
  /* rv = vppcom_session_write (__sid, (void *) __message->__buf,
     (int)__n); */
  return rv;
}

ssize_t
vcom_socket_sendmsg (int __fd, const struct msghdr * __message, int __flags)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vcom_socket_is_connection_mode_socket (__fd))
    {
      /* ignore __addr and _addr_len */
      /* and EISCONN may be returned when they are not NULL and 0 */
      if ((__message->msg_name != NULL) || (__message->msg_namelen != 0))
	{
	  return -EISCONN;
	}
    }
  else
    {
      /* TBD: validate __message->msg_name and __message->msg_namelen
       * and return -EINVAL on validation error
       * */
      ;
    }

  rv = vcom_session_sendmsg (vsock->sid, __message, __flags);

  return rv;
}

#ifdef __USE_GNU
int
vcom_socket_sendmmsg (int __fd, struct mmsghdr *__vmessages,
		      unsigned int __vlen, int __flags)
{

  /* TBD: define a new vppcom api */
  return 0;
}
#endif

/* TBD: move it to vppcom */
static inline ssize_t
vcom_session_recvmsg (int __sid, struct msghdr *__message, int __flags)
{
  int rv = -1;
  /* rv = vppcom_session_read (__sid, (void *) __message->__buf,
     (int)__n); */
  rv = -EOPNOTSUPP;
  return rv;
}

ssize_t
vcom_socket_recvmsg (int __fd, struct msghdr * __message, int __flags)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  if (!__message)
    {
      return -EINVAL;
    }

  /* validate __flags */

  rv = vcom_session_recvmsg (vsock->sid, __message, __flags);
  return rv;
}

#ifdef __USE_GNU
int
vcom_socket_recvmmsg (int __fd, struct mmsghdr *__vmessages,
		      unsigned int __vlen, int __flags,
		      struct timespec *__tmo)
{
  /* TBD: define a new vppcom api */
  return 0;
}
#endif

/* TBD: move it to vppcom */
static inline int
vcom_session_get_sockopt (int __sid, int __level, int __optname,
			  void *__restrict __optval,
			  socklen_t * __restrict __optlen)
{
  int rv = 0;

  /* 1. for socket level options that are NOT socket attributes
   *    and that has corresponding vpp options get from vppcom */
  switch (__level)
    {
    case SOL_SOCKET:
      switch (__optname)
	{
	case SO_ERROR:
	  *(int *) __optval = 0;
	  break;
	default:
	  break;
	}
    default:
      break;
    }
  /* 2. unhandled options */
  return rv;
}

int
vcom_socket_getsockopt (int __fd, int __level, int __optname,
			void *__restrict __optval,
			socklen_t * __restrict __optlen)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  if (!__optval || !__optlen)
    return -EINVAL;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  switch (__level)
    {
    case SOL_SOCKET:
      switch (__optname)
	{
/*
 *  1. for socket level options that are socket attributes,
 *     get from libc_getsockopt.
 *  2. for socket level options that are NOT socket
 *     attributes and that has corresponding vpp options
 *     get from vppcom.
 *  3. for socket level options unimplemented
 *     return -ENOPROTOOPT */
	case SO_DEBUG:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_SNDBUF:
	case SO_RCVBUF:
	case SO_REUSEADDR:
	case SO_REUSEPORT:
	case SO_KEEPALIVE:
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_OOBINLINE:
	case SO_NO_CHECK:
	case SO_PRIORITY:
	case SO_LINGER:
	case SO_BSDCOMPAT:
	case SO_TIMESTAMP:
	case SO_TIMESTAMPNS:
	case SO_TIMESTAMPING:
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
	case SO_PASSCRED:
	case SO_PEERCRED:
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
	case SO_MARK:
	case SO_RXQ_OVFL:
	case SO_WIFI_STATUS:
	case SO_PEEK_OFF:
	case SO_NOFCS:
	case SO_BINDTODEVICE:
	case SO_GET_FILTER:
	case SO_LOCK_FILTER:
	case SO_BPF_EXTENSIONS:
	case SO_SELECT_ERR_QUEUE:
#ifdef CONFIG_NET_RX_BUSY_POLL
	case SO_BUSY_POLL:
#endif
	case SO_MAX_PACING_RATE:
#ifdef SO_INCOMING_CPU
	case SO_INCOMING_CPU:
#endif
	  rv = libc_getsockopt (__fd, __level, __optname, __optval, __optlen);
	  if (rv != 0)
	    {
	      rv = -errno;
	      return rv;
	    }
	  break;

	case SO_ERROR:
	  rv = vcom_session_get_sockopt (vsock->sid, __level, __optname,
					 __optval, __optlen);
	  break;

	default:
	  /* We implement the SO_SNDLOWAT etc to not be settable
	   * (1003.1g 7).
	   */
	  return -ENOPROTOOPT;
	}

      break;

    default:
      /* 1. handle options that are NOT socket level options,
       *    but have corresponding vpp otions. */
      rv = vcom_session_get_sockopt (vsock->sid, __level, __optname,
				     __optval, __optlen);
      break;
    }

  return rv;
}

/* TBD: move it to vppcom */
static inline int
vcom_session_setsockopt (int __sid, int __level, int __optname,
			 const void *__optval, socklen_t __optlen)
{
  int rv = -EOPNOTSUPP;

  switch (__level)
    {
    case SOL_TCP:
      switch (__optname)
	{
	case TCP_KEEPIDLE:
	  rv =
	    vppcom_session_attr (__sid, VPPCOM_ATTR_SET_TCP_KEEPIDLE, 0, 0);
	  break;
	case TCP_KEEPINTVL:
	  rv =
	    vppcom_session_attr (__sid, VPPCOM_ATTR_SET_TCP_KEEPINTVL, 0, 0);
	  break;
	default:
	  break;
	}
      break;
    case SOL_IPV6:
      switch (__optname)
	{
	case IPV6_V6ONLY:
	  rv = vppcom_session_attr (__sid, VPPCOM_ATTR_SET_V6ONLY, 0, 0);
	  break;
	default:
	  break;
	}
      break;
    case SOL_SOCKET:
      switch (__optname)
	{
	case SO_KEEPALIVE:
	  rv = vppcom_session_attr (__sid, VPPCOM_ATTR_SET_KEEPALIVE, 0, 0);
	  break;
	case SO_REUSEADDR:
	  rv = vppcom_session_attr (__sid, VPPCOM_ATTR_SET_REUSEADDR, 0, 0);
	  break;
	case SO_BROADCAST:
	  rv = vppcom_session_attr (__sid, VPPCOM_ATTR_SET_BROADCAST, 0, 0);
	  break;
	default:
	  break;
	}
      break;
    default:
      break;
    }

  return rv;
}

int
vcom_socket_setsockopt (int __fd, int __level, int __optname,
			const void *__optval, socklen_t __optlen)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (!p)
    return -EBADF;

  vsock = pool_elt_at_index (vsm->vsockets, p[0]);
  if (!vsock)
    return -ENOTSOCK;

  if (vsock->type != SOCKET_TYPE_VPPCOM_BOUND)
    return -EINVAL;

  /*
   *      Options without arguments
   */

  if (__optname == SO_BINDTODEVICE)
    {
      rv = libc_setsockopt (__fd, __level, __optname, __optval, __optlen);
      if (rv != 0)
	{
	  rv = -errno;
	}
      return rv;
    }

  if (!__optval)
    return -EFAULT;

  if (__optlen < sizeof (int))
    return -EINVAL;

  switch (__level)
    {
    case SOL_IPV6:
      switch (__optname)
	{
	case IPV6_V6ONLY:
	  rv = vcom_session_setsockopt (vsock->sid, __level, __optname,
					__optval, __optlen);
	  break;
	default:
	  return -EOPNOTSUPP;
	}
      break;
    case SOL_TCP:
      switch (__optname)
	{
	case TCP_NODELAY:
	  return 0;
	case TCP_KEEPIDLE:
	case TCP_KEEPINTVL:
	  rv = vcom_session_setsockopt (vsock->sid, __level, __optname,
					__optval, __optlen);
	  break;
	default:
	  return -EOPNOTSUPP;
	}
      break;
      /* handle options at socket level */
    case SOL_SOCKET:
      switch (__optname)
	{
	case SO_REUSEADDR:
	case SO_BROADCAST:
	case SO_KEEPALIVE:
	  rv = vcom_session_setsockopt (vsock->sid, __level, __optname,
					__optval, __optlen);
	  break;

	  /*
	   * 1. for socket level options that are socket attributes,
	   *    set it from libc_getsockopt
	   * 2. for socket level options that are NOT socket
	   *    attributes and that has corresponding vpp options
	   *    set it from vppcom
	   * 3. for socket level options unimplemented
	   *    return -ENOPROTOOPT */
	case SO_DEBUG:
	case SO_DONTROUTE:
	case SO_SNDBUF:
	case SO_RCVBUF:
	case SO_REUSEPORT:
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
	case SO_OOBINLINE:
	case SO_NO_CHECK:
	case SO_PRIORITY:
	case SO_LINGER:
	case SO_BSDCOMPAT:
	case SO_TIMESTAMP:
	case SO_TIMESTAMPNS:
	case SO_TIMESTAMPING:
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
	case SO_PASSCRED:
	case SO_PEERCRED:
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
	case SO_MARK:
	case SO_RXQ_OVFL:
	case SO_WIFI_STATUS:
	case SO_PEEK_OFF:
	case SO_NOFCS:
	  /*
	   * SO_BINDTODEVICE already handled as
	   * "Options without arguments" */
	  /* case SO_BINDTODEVICE: */
	case SO_GET_FILTER:
	case SO_LOCK_FILTER:
	case SO_BPF_EXTENSIONS:
	case SO_SELECT_ERR_QUEUE:
#ifdef CONFIG_NET_RX_BUSY_POLL
	case SO_BUSY_POLL:
#endif
	case SO_MAX_PACING_RATE:
#ifdef SO_INCOMING_CPU
	case SO_INCOMING_CPU:
#endif
	  rv = libc_setsockopt (__fd, __level, __optname, __optval, __optlen);
	  if (rv != 0)
	    {
	      rv = -errno;
	      return rv;
	    }
	  break;

	default:
	  /* We implement the SO_SNDLOWAT etc to not be settable
	   * (1003.1g 7).
	   */
	  return -ENOPROTOOPT;
	}

      break;

    default:
      return -ENOPROTOOPT;
    }

  return rv;
}

int
vcom_socket_listen (int __fd, int __n)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);

      /* TBD vppcom to accept __n parameter */
      rv = vppcom_session_listen (vsock->sid, __n);
    }

  return rv;
}

static int
vcom_socket_connected_socket (int __fd, int __sid,
			      int *__domain,
			      int *__type, int *__protocol, int flags)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  vcom_socket_t *vsock;

  i32 fd;
  i32 sockidx;

  socklen_t optlen;

  optlen = sizeof (*__domain);
  rv = libc_getsockopt (__fd, SOL_SOCKET, SO_DOMAIN, __domain, &optlen);
  if (rv != 0)
    {
      rv = -errno;
      goto out;
    }

  optlen = sizeof (*__type);
  rv = libc_getsockopt (__fd, SOL_SOCKET, SO_TYPE, __type, &optlen);
  if (rv != 0)
    {
      rv = -errno;
      goto out;
    }

  optlen = sizeof (*__protocol);
  rv = libc_getsockopt (__fd, SOL_SOCKET, SO_PROTOCOL, __protocol, &optlen);
  if (rv != 0)
    {
      rv = -errno;
      goto out;
    }

  fd = vcom_socket_open_socket (*__domain, *__type | flags, *__protocol);
  if (fd < 0)
    {
      rv = fd;
      goto out;
    }

  pool_get (vsm->vsockets, vsock);
  vsocket_init (vsock);

  sockidx = vsock - vsm->vsockets;
  hash_set (vsm->sockidx_by_fd, fd, sockidx);

  vsocket_set (vsock, fd, __sid, SOCKET_TYPE_VPPCOM_BOUND);
  return fd;

out:
  return rv;
}

/* If flag is 0, then accept4() is the same as accept().
 * SOCK_NONBLOCK and SOCK_CLOEXEC can be bitwise ORed in flags
 */
static int
vcom_socket_accept_flags (int __fd, __SOCKADDR_ARG __addr,
			  socklen_t * __restrict __addr_len, int flags)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  int fd;
  int sid;
  int domain;
  int type;
  int protocol;

  uint8_t addr8[sizeof (struct in6_addr)];
  vppcom_endpt_t ep;

  ep.ip = addr8;

  /* validate flags */

  /*
   * for documentation
   *  switch (flags)
   *   {
   *   case 0:
   *   case SOCK_NONBLOCK:
   *   case SOCK_CLOEXEC:
   *   case SOCK_NONBLOCK | SOCK_CLOEXEC:
   *     break;
   *
   *   default:
   *     return -1;
   *   }
   */
  /* flags can be 0 or can be bitwise OR
   * of any of SOCK_NONBLOCK and SOCK_CLOEXEC */

  if (VCOM_DEBUG > 2)
    fprintf (stderr, "[%d] vcom_socket_accept_flags: "
	     "fd = %d, __addr = %p, __addr_len = %p  flags = %d (0x%x)\n",
	     getpid (), __fd, __addr, __addr_len, flags, flags);

  if (!(!flags || (flags & (SOCK_NONBLOCK | SOCK_CLOEXEC))))
    {
      /* TBD: return proper error code */
      fprintf (stderr, "[%d] ERROR: vcom_socket_accept_flags: "
	       "invalid flags = %d (0x%x)\n", getpid (), flags, flags);

      return -1;
    }

  /* TBD: return proper error code */

  if (!vcom_socket_is_connection_mode_socket (__fd))
    {
      fprintf (stderr, "[%d] ERROR: vcom_socket_accept_flags: "
	       "connection mode socket support TBD!\n", getpid ());
      return -EOPNOTSUPP;
    }

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);


      rv = vcom_fcntl (vsock->fd, F_GETFL, 0);
      if (rv < 0)
	{
	  fprintf (stderr, "[%d] ERROR: vcom_socket_accept_flags: "
		   "vcom_fcnt() returned %d!\n", getpid (), rv);
	  return rv;
	}

      /* is blocking */
      if (!(rv & O_NONBLOCK))
	{
	  /* socket is not marked as nonblocking
	   * and no pending connections are present
	   * on the queue, accept () blocks the caller
	   * until a connection is present.
	   */
	  rv = vppcom_session_accept (vsock->sid, &ep, flags,
				      -1.0 /* wait forever */ );
	}
      else
	{
	  /* The file descriptor refers to a socket and has been
	   * marked nonblocking(O_NONBLOCK) and the accept would
	   * block.
	   * */
	  /* is non blocking */
	  rv = vppcom_session_accept (vsock->sid, &ep, flags, 0);
	  /* If the socket is marked nonblocking and
	   * no pending connections are present on the
	   * queue, accept fails with the error
	   * EAGAIN or EWOULDBLOCK
	   */
	  if (rv == VPPCOM_ETIMEDOUT)
	    {
	      rv = VPPCOM_EAGAIN;
	    }
	}
      if (rv < 0)
	{
	  if (rv != VPPCOM_EAGAIN)
	    fprintf (stderr, "[%d] ERROR: vcom_socket_accept_flags: "
		     "vppcom_session_accept() returned %d!", getpid (), rv);
	  return rv;
	}

      sid = rv;

      /* create a new connected socket resource and set flags
       * on the new file descriptor.
       * update vsockets and sockidx_by_fd table
       * */
      fd = vcom_socket_connected_socket (__fd, sid,
					 &domain, &type, &protocol, flags);
      if (fd < 0)
	{
	  fprintf (stderr, "[%d] ERROR: vcom_socket_accept_flags: "
		   "vcom_socket_connected_socket() returned %d!",
		   getpid (), rv);
	  return fd;
	}

      rv = fd;

      /* TBD populate __addr and __addr_len */
      /* TBD: The returned address is truncated if the buffer
       * provided is too small, in this case, __addr_len will
       * return a value greater than was supplied to the call.*/
      if (__addr)
	{
	  if (ep.is_cut_thru)
	    {
	      /* TBD populate __addr and __addr_len */
	      switch (domain)
		{
		case AF_INET:
		  ((struct sockaddr_in *) __addr)->sin_family = AF_INET;
		  ((struct sockaddr_in *) __addr)->sin_port = ep.port;
		  memcpy (&((struct sockaddr_in *) __addr)->sin_addr,
			  addr8, sizeof (struct in_addr));
		  /* TBD: populate __addr_len */
		  if (__addr_len)
		    {
		      *__addr_len = sizeof (struct sockaddr_in);
		    }
		  break;

		case AF_INET6:
		  ((struct sockaddr_in6 *) __addr)->sin6_family = AF_INET6;
		  ((struct sockaddr_in6 *) __addr)->sin6_port = ep.port;
		  memcpy (((struct sockaddr_in6 *) __addr)->sin6_addr.
			  __in6_u.__u6_addr8, addr8,
			  sizeof (struct in6_addr));
		  /* TBD: populate __addr_len */
		  if (__addr_len)
		    {
		      *__addr_len = sizeof (struct sockaddr_in6);
		    }
		  break;

		default:
		  return -EAFNOSUPPORT;
		}
	    }
	  else
	    {
	      switch (ep.is_ip4)
		{
		case VPPCOM_IS_IP4:
		  ((struct sockaddr_in *) __addr)->sin_family = AF_INET;
		  ((struct sockaddr_in *) __addr)->sin_port = ep.port;
		  memcpy (&((struct sockaddr_in *) __addr)->sin_addr,
			  addr8, sizeof (struct in_addr));
		  /* TBD: populate __addr_len */
		  if (__addr_len)
		    {
		      *__addr_len = sizeof (struct sockaddr_in);
		    }
		  break;

		case VPPCOM_IS_IP6:
		  ((struct sockaddr_in6 *) __addr)->sin6_family = AF_INET6;
		  ((struct sockaddr_in6 *) __addr)->sin6_port = ep.port;
		  memcpy (((struct sockaddr_in6 *) __addr)->sin6_addr.
			  __in6_u.__u6_addr8, addr8,
			  sizeof (struct in6_addr));
		  /* TBD: populate __addr_len */
		  if (__addr_len)
		    {
		      *__addr_len = sizeof (struct sockaddr_in6);
		    }
		  break;

		default:
		  return -EAFNOSUPPORT;
		}
	    }
	}
    }

  return rv;
}

int
vcom_socket_accept (int __fd, __SOCKADDR_ARG __addr,
		    socklen_t * __restrict __addr_len)
{
  /* set flags to 0 for accept() */
  return vcom_socket_accept_flags (__fd, __addr, __addr_len, 0);
}

int
vcom_socket_accept4 (int __fd, __SOCKADDR_ARG __addr,
		     socklen_t * __restrict __addr_len, int __flags)
{
  /*  SOCK_NONBLOCK and SOCK_CLOEXEC can be bitwise ORed in flags */
  return vcom_socket_accept_flags (__fd, __addr, __addr_len, __flags);
}

/* TBD: move it to vppcom */
static inline int
vcom_session_shutdown (int __fd, int __how)
{
  return 0;
}

int
vcom_socket_shutdown (int __fd, int __how)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  uword *p;
  vcom_socket_t *vsock;

  p = hash_get (vsm->sockidx_by_fd, __fd);
  if (p)
    {
      vsock = pool_elt_at_index (vsm->vsockets, p[0]);
      switch (__how)
	{
	case SHUT_RD:
	case SHUT_WR:
	case SHUT_RDWR:
	  rv = vcom_session_shutdown (vsock->sid, __how);
	  return rv;
	  break;

	default:
	  return -EINVAL;
	  break;
	}
    }

  return rv;
}

int
vcom_socket_epoll_create1 (int __flags)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  vcom_epoll_t *vepoll;

  i32 epfd;
  i32 vep_idx;
  i32 epollidx;

  epfd = vcom_socket_open_epoll (__flags);
  if (epfd < 0)
    {
      rv = epfd;
      goto out;
    }

  vep_idx = vppcom_epoll_create ();
  if (vep_idx < 0)
    {
      rv = vep_idx;
      goto out_close_epoll;
    }

  pool_get (vsm->vepolls, vepoll);
  vepoll_init (vepoll);

  epollidx = vepoll - vsm->vepolls;
  hash_set (vsm->epollidx_by_epfd, epfd, epollidx);

  vepoll_set (vepoll, epfd, vep_idx, EPOLL_TYPE_VPPCOM_BOUND, __flags, 0, 0);

  return epfd;

out_close_epoll:
  vcom_socket_close_epoll (epfd);
out:
  return rv;
}

/*
 * PRE: vppcom_epoll_ctl() is successful
 * free_vepitem_on_del : 0 - no_pool_put, 1 - pool_put
 */
int
vcom_socket_ctl_vepitem (int __epfd, int __op, int __fd,
			 struct epoll_event *__event,
			 i32 vep_idx, vcom_epoll_t * vepoll,
			 i32 vfd_id, void *vfd, vcom_fd_type_t type,
			 int free_vepitem_on_del)
{
  int rv = -1;
  vcom_socket_main_t *vsm = &vcom_socket_main;
  vcom_epitem_t *vepitem;

  vcom_epitem_key_t epfdfd = {.epfd = __epfd,.fd = __fd };
  uword *p;
  i32 vepitemidx;

  i32 *vepitemidxs = 0;

  struct epoll_event revent = {.events = 0,.data.fd = INVALID_FD };

  i32 vec_idx;

  /* perform control operations on the epoll instance */
  switch (__op)
    {
    case EPOLL_CTL_ADD:
      /*
       * supplied file descriptor is already
       * registered with this epoll instance
       * */
      /* vepitem exists */
      p = hash_get (vsm->epitemidx_by_epfdfd, epfdfd.key);
      if (p)
	{
	  rv = -EEXIST;
	  goto out;
	}

      /* add a new vepitem */
      pool_get (vsm->vepitems, vepitem);
      vepitem_init (vepitem);

      vepitemidx = vepitem - vsm->vepitems;
      hash_set (vsm->epitemidx_by_epfdfd, epfdfd.key, vepitemidx);
      vepitem_set (vepitem, __epfd, __fd, __fd, __fd, type, *__event, revent);

      /* update epitemidxs */
      /* by_epfd */
      p = hash_get (vsm->epitemidxs_by_epfd, __epfd);
      if (!p)			/*  not exist */
	{
	  vepitemidxs = 0;
	  vec_add1 (vepitemidxs, vepitemidx);
	  hash_set (vsm->epitemidxs_by_epfd, __epfd, vepitemidxs);
	}
      else			/*  exists */
	{
	  vepitemidxs = *(i32 **) p;
	  vec_add1 (vepitemidxs, vepitemidx);
	  hash_set3 (vsm->epitemidxs_by_epfd, __epfd, vepitemidxs, 0);
	}
      /* update epitemidxs */
      /* by_fd */
      p = hash_get (vsm->epitemidxs_by_fd, __fd);
      if (!p)			/*  not exist */
	{
	  vepitemidxs = 0;
	  vec_add1 (vepitemidxs, vepitemidx);
	  hash_set (vsm->epitemidxs_by_fd, __fd, vepitemidxs);
	}
      else			/*  exists */
	{
	  vepitemidxs = *(i32 **) p;
	  vec_add1 (vepitemidxs, vepitemidx);
	  hash_set3 (vsm->epitemidxs_by_fd, __fd, vepitemidxs, 0);
	}

      /* increment vepoll fd count by 1 */
      vepoll->count += 1;

      rv = 0;
      goto out;
      break;

    case EPOLL_CTL_MOD:
      /*
       * supplied file descriptor is not
       * registered with this epoll instance
       * */
      /* vepitem not exist */
      p = hash_get (vsm->epitemidx_by_epfdfd, epfdfd.key);
      if (!p)
	{
	  rv = -ENOENT;
	  goto out;
	}
      vepitem = pool_elt_at_index (vsm->vepitems, p[0]);
      if (vepitem)
	{
	  vepitem->event = *__event;
	  vepitem->revent = revent;
	}

      rv = 0;
      goto out;
      break;

    case EPOLL_CTL_DEL:
      /*
       * supplied file descriptor is not
       * registered with this epoll instance
       * */
      /* vepitem not exist */
      p = hash_get (vsm->epitemidx_by_epfdfd, epfdfd.key);
      if (!p)
	{
	  rv = -ENOENT;
	  goto out;
	}
      vepitemidx = *(i32 *) p;
      hash_unset (vsm->epitemidx_by_epfdfd, epfdfd.key);

      /* update epitemidxs */
      /* by_epfd */
      p = hash_get (vsm->epitemidxs_by_epfd, __epfd);
      if (!p)			/*  not exist */
	{
	  rv = -ENOENT;
	  goto out;
	}
      else			/*  exists */
	{
	  vepitemidxs = *(i32 **) p;
	  vec_idx = vec_search (vepitemidxs, vepitemidx);
	  if (vec_idx != ~0)
	    {
	      vec_del1 (vepitemidxs, vec_idx);
	      if (!vec_len (vepitemidxs))
		{
		  vec_free (vepitemidxs);
		  hash_unset (vsm->epitemidxs_by_epfd, __epfd);
		}
	    }
	}

      /* update epitemidxs */
      /* by_fd */
      p = hash_get (vsm->epitemidxs_by_fd, __fd);
      if (!p)			/*  not exist */
	{
	  rv = -ENOENT;
	  goto out;
	}
      else			/*  exists */
	{
	  vepitemidxs = *(i32 **) p;
	  vec_idx = vec_search (vepitemidxs, vepitemidx);
	  if (vec_idx != ~0)
	    {
	      vec_del1 (vepitemidxs, vec_idx);
	      if (!vec_len (vepitemidxs))
		{
		  vec_free (vepitemidxs);
		  hash_unset (vsm->epitemidxs_by_fd, __fd);
		}
	    }
	}

      /* pool put vepitem */
      vepitem = pool_elt_at_index (vsm->vepitems, vepitemidx);
      if (free_vepitem_on_del)
	{
	  if (!vepitem)
	    {
	      rv = -ENOENT;
	      goto out;
	    }
	  vepitem_init (vepitem);
	  pool_put (vsm->vepitems, vepitem);
	}
      else
	{
	  if (!vepitem)
	    {
	      vepitem_init (vepitem);
	    }
	}

      /* decrement vepoll fd count by 1 */
      vepoll->count -= 1;

      rv = 0;
      goto out;
      break;

    default:
      rv = -EINVAL;
      goto out;
      break;
    }

out:
  return rv;
}

/*
 * PRE: 00. null pointer check on __event
 *      01. all other parameters are validated
 */

static int
vcom_socket_epoll_ctl_internal (int __epfd, int __op, int __fd,
				struct epoll_event *__event,
				int free_vepitem_on_del)
{
  int rv = -1;
  i32 cnt;
  vcom_epoll_t *vepoll;
  vcom_socket_t *vfd_vsock;
  i32 vep_idx;
  i32 sid;

  /* get vep_idx and vepoll */
  vep_idx = vcom_socket_get_vep_idx_and_vepoll (__epfd, &vepoll);
  if (vep_idx == INVALID_VEP_IDX)
    {
      return -EBADF;
    }

  /* get vcom fd type, vfd_id and vfd */
  sid = vcom_socket_get_sid_and_vsock (__fd, &vfd_vsock);
  if ((sid != INVALID_SESSION_ID) &&
      vcom_socket_type_is_vppcom_bound (vfd_vsock->type))
    {
      rv = vppcom_epoll_ctl (vep_idx, __op, sid, __event);
      if (rv == VPPCOM_OK)
	{
	  cnt = ((__op == EPOLL_CTL_ADD) ? 1 :
		 (__op == EPOLL_CTL_DEL) ? -1 : 0);
	  vepoll->count += cnt;
	  vepoll->vcl_cnt += cnt;
	}
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] vcom_socket_epoll_ctl_i: vppcom_epoll_ctl() "
		 "returned %d\n\tepfd %d, vep_idx %d, fd %d sid %d op %d"
		 "\n\tcount %d, vcl_cnt %d, libc_cnt %d\n",
		 getpid (), rv, __epfd, vep_idx, __fd, sid, __op,
		 vepoll->count, vepoll->vcl_cnt, vepoll->libc_cnt);
    }
  else
    {
      rv = libc_epoll_ctl (__epfd, __op, __fd, __event);
      if (rv == 0)
	{
	  cnt = ((__op == EPOLL_CTL_ADD) ? 1 :
		 (__op == EPOLL_CTL_DEL) ? -1 : 0);
	  vepoll->count += cnt;
	  vepoll->libc_cnt += cnt;
	}
      if (VCOM_DEBUG > 0)
	fprintf (stderr,
		 "[%d] vcom_socket_epoll_ctl_i: libc_epoll_ctl() "
		 "returned %d\n\tepfd %d, vep_idx %d, fd %d sid %d op %d"
		 "\n\tcount %d, vcl_cnt %d, libc_cnt %d\n",
		 getpid (), rv, __epfd, vep_idx, __fd, sid, __op,
		 vepoll->count, vepoll->vcl_cnt, vepoll->libc_cnt);
    }

  return rv;
}

int
vcom_socket_epoll_ctl (int __epfd, int __op, int __fd,
		       struct epoll_event *__event)
{
  int rv = -1;

  rv = vcom_socket_epoll_ctl_internal (__epfd, __op, __fd, __event, 1);
  return rv;
}

static int
vcom_socket_epoll_ctl1 (int __epfd, int __op, int __fd,
			struct epoll_event *__event)
{
  int rv = -1;

  rv = vcom_socket_epoll_ctl_internal (__epfd, __op, __fd, __event, 0);
  return rv;
}

int
vcom_socket_epoll_pwait (int __epfd, struct epoll_event *__events,
			 int __maxevents, int __timeout,
			 const __sigset_t * __ss)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  int rv = -EBADF;
  double time_to_wait = (double) 0;
  double timeout, now = 0;
  vcom_epoll_t *vepoll;
  i32 vep_idx;

  /* validate __event */
  if (!__events || (__timeout < -1))
    {
      fprintf (stderr, "[%d] ERROR: vcom_socket_epoll_pwait: "
	       "Bad args __events %p, __timeout %d\n", getpid (),
	       __events, __timeout);
      rv = -EFAULT;
      goto out;
    }

  time_to_wait = ((__timeout >= 0) ? (double) __timeout / (double) 1000 : 0);

  vep_idx = vcom_socket_get_vep_idx_and_vepoll (__epfd, &vepoll);
  if (vep_idx == INVALID_VEP_IDX)
    {
      fprintf (stderr, "[%d] ERROR: vcom_socket_epoll_pwait: "
	       "Bad epoll fd %d\n", getpid (), __epfd);
      return -EBADF;
    }

  if (vepoll->count <= 0)
    {
      fprintf (stderr, "[%d] ERROR: vcom_socket_epoll_pwait: No events"
	       " in epfd!\n\tcount %d, vcl_cnt %d, libc_cnt %d\n",
	       getpid (), vepoll->count, vepoll->vcl_cnt, vepoll->libc_cnt);
      rv = -EINVAL;
      goto out;
    }

  if (vepoll->libc_cnt == 0)
    {
      if (VCOM_DEBUG > 2)
	fprintf (stderr, "[%d] vcom_socket_epoll_pwait: libc_cnt = 0, "
		 "calling vppcom_epoll_wait() time_to_wait = %f\n",
		 getpid (), time_to_wait);
      rv = vppcom_epoll_wait (vep_idx, __events, __maxevents, time_to_wait);
    }
  else if (vepoll->vcl_cnt == 0)
    {
      if (VCOM_DEBUG > 2)
	fprintf (stderr, "[%d] vcom_socket_epoll_pwait: vcl_cnt = 0, "
		 "calling libc_epoll_pwait()\n", getpid ());
      rv = libc_epoll_pwait (__epfd, __events, __maxevents, __timeout, __ss);
    }
  else
    {
      if (VCOM_DEBUG > 2)
	fprintf (stderr, "[%d] vcom_socket_epoll_pwait: vcl_cnt = %d, "
		 "libc_cnt = %d -> mixed polling (time_to_wait = %f, "
		 "__timeout = %d)\n",
		 getpid (), vepoll->vcl_cnt, vepoll->libc_cnt,
		 time_to_wait, __timeout);
      timeout = clib_time_now (&vsm->clib_time) + time_to_wait;
      do
	{
	  rv = vppcom_epoll_wait (vep_idx, __events, __maxevents, 0);
	  if (rv > 0)
	    {
	      if (VCOM_DEBUG > 2)
		fprintf (stderr, "[%d] vcom_socket_epoll_pwait: "
			 "vppcom_epoll_wait() returned %d\n", getpid (), rv);
	      goto out;
	    }
	  else if (rv < 0)
	    {
	      if (VCOM_DEBUG > 2)
		fprintf (stderr, "[%d] ERROR: vcom_socket_epoll_pwait: "
			 "vppcom_epoll_wait() returned %d\n", getpid (), rv);

	      goto out;
	    }
	  rv = libc_epoll_pwait (__epfd, __events, __maxevents, 1, __ss);
	  if (rv > 0)
	    {
	      if (VCOM_DEBUG > 2)
		fprintf (stderr, "[%d] vcom_socket_epoll_pwait: "
			 "libc_epoll_pwait() returned %d\n", getpid (), rv);
	      goto out;
	    }
	  else if (rv < 0)
	    {
	      int errno_val = errno;
	      perror ("libc_epoll_wait");
	      fprintf (stderr, "[%d]  vcom_socket_epoll_pwait: "
		       "libc_epoll_wait() failed, errno %d\n",
		       getpid (), errno_val);
	      goto out;
	    }
	  if (__timeout != -1)
	    now = clib_time_now (&vsm->clib_time);
	}
      while (now < timeout);
    }
out:
  return rv;
}

static inline void
vcom_pollfds_2_selectfds (
			   /* src */
			   struct pollfd *__fds, nfds_t __nfds,
			   /* dest */
			   int vcom_nfds,
			   fd_set * __restrict vcom_readfds,
			   fd_set * __restrict vcom_writefds,
			   fd_set * __restrict vcom_exceptfds)
{
  nfds_t fds_idx = 0;

  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds */
      if (__fds[fds_idx].fd < 0)
	{
	  continue;
	}

      /* for POLLRDHUP, POLLERR, POLLHUP and  POLLNVAL */
      FD_SET (__fds[fds_idx].fd, vcom_exceptfds);

      /* requested events */
      if (__fds[fds_idx].events)
	{
	  if (__fds[fds_idx].events & POLLIN)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_readfds);
	    }
	  if (__fds[fds_idx].events & POLLPRI)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_readfds);
	    }
	  if (__fds[fds_idx].events & POLLOUT)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_writefds);
	    }
#if defined __USE_XOPEN || defined __USE_XOPEN2K8
	  if (__fds[fds_idx].events & POLLRDNORM)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_readfds);
	    }
	  if (__fds[fds_idx].events & POLLRDBAND)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_readfds);
	    }
	  if (__fds[fds_idx].events & POLLWRNORM)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_writefds);
	    }
	  if (__fds[fds_idx].events & POLLWRBAND)
	    {
	      FD_SET (__fds[fds_idx].fd, vcom_writefds);
	    }
#endif
	}
    }				/* for (fds_idx = 0; fds_idx < __nfds; fds_idx++) */
}

static inline void
vcom_selectfds_2_pollfds (
			   /* dest */
			   struct pollfd *__fds, nfds_t __nfds, int *nfd,
			   /* src */
			   int vcom_nfds,
			   fd_set * __restrict vcom_readfds,
			   fd_set * __restrict vcom_writefds,
			   fd_set * __restrict vcom_exceptfds)
{
  nfds_t fds_idx = 0;


  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds */
      if (__fds[fds_idx].fd < 0)
	{
	  __fds[fds_idx].revents = 0;
	}

      /* for POLLRDHUP, POLLERR, POLLHUP and  POLLNVAL */
      if (FD_ISSET (__fds[fds_idx].fd, vcom_exceptfds))
	{
	  /*
	   * TBD: for now any select exception
	   *      is flagged as POLLERR
	   * */
	  __fds[fds_idx].revents |= POLLERR;
	}

      /* requested events */
      if (__fds[fds_idx].events & POLLIN)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_readfds))
	    {
	      __fds[fds_idx].revents |= POLLIN;
	    }
	}
      if (__fds[fds_idx].events & POLLPRI)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_readfds))
	    {
	      __fds[fds_idx].revents |= POLLIN;
	    }
	}
      if (__fds[fds_idx].events & POLLOUT)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_writefds))
	    {
	      __fds[fds_idx].revents |= POLLOUT;
	    }
	}
#if defined __USE_XOPEN || defined __USE_XOPEN2K8
      if (__fds[fds_idx].events & POLLRDNORM)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_readfds))
	    {
	      __fds[fds_idx].revents |= POLLRDNORM;
	    }
	}
      if (__fds[fds_idx].events & POLLRDBAND)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_readfds))
	    {
	      __fds[fds_idx].revents |= POLLRDBAND;
	    }
	}
      if (__fds[fds_idx].events & POLLWRNORM)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_writefds))
	    {
	      __fds[fds_idx].revents |= POLLWRNORM;
	    }
	}
      if (__fds[fds_idx].events & POLLWRBAND)
	{
	  if (FD_ISSET (__fds[fds_idx].fd, vcom_writefds))
	    {
	      __fds[fds_idx].revents |= POLLWRBAND;
	    }
	}
#endif
    }				/* for (fds_idx = 0; fds_idx < __nfds; fds_idx++) */

  /*
   * nfd:
   * the number of structures which have nonzero revents  fields
   * (in  other  words,  those  descriptors  with events or
   * errors reported)
   * */
  *nfd = 0;
  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds */
      if (__fds[fds_idx].fd < 0)
	{
	  continue;
	}

      if (__fds[fds_idx].revents)
	{
	  (*nfd)++;
	}
    }
}

/*
 * PRE: parameters are validated,
 *      vcom_socket_poll is always called with __timeout set to zero
 *      hence returns immediately
 *
 * ACTION: handle non negative validated vcom fds and ignore rest
 */

/*
 * implements vcom_socket_poll () interface
 *
 * internally uses vcom_socket_select ()
 * to realize the behavior
 * */
int
vcom_socket_poll_select_impl (struct pollfd *__fds, nfds_t __nfds,
			      int __timeout)
{
  int rv;

  nfds_t fds_idx = 0;
  int nfd = 0;

  /* vcom */
  int vcom_nfds = 0;
  fd_set vcom_readfds;
  fd_set vcom_writefds;
  fd_set vcom_exceptfds;
  int vcom_nfd = -1;
  /* invalid max_vcom_fd is -1 */
  int max_vcom_fd = -1;

  /* __timeout is zero to get ready events and return immediately */
  struct timeval tv = {.tv_sec = 0,.tv_usec = 0 };

  /* validate __nfds from select perspective */
  if (__nfds > FD_SETSIZE)
    {
      rv = -EINVAL;
      goto poll_done;
    }

  /* zero vcom fd sets */
  /*
   * V vcom fd set
   */
#define _(V)      \
    FD_ZERO ((V))

  _(&vcom_readfds);
  _(&vcom_writefds);
  _(&vcom_exceptfds);
#undef _

  vcom_nfds = 0;
  vcom_nfd = -1;


  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds */
      if (__fds[fds_idx].fd < 0)
	{
	  continue;
	}

      /* non negative validated vcom fds */
      if (__fds[fds_idx].fd > FD_SETSIZE)
	{
	  rv = -EINVAL;
	  goto poll_done;
	}

      /* max_vcom_fd and vcom_nfd */
      if (__fds[fds_idx].fd > max_vcom_fd)
	{
	  /* requested events */
	  if (__fds[fds_idx].events)
	    {
	      max_vcom_fd = __fds[fds_idx].fd;
	    }
	}
      ++vcom_nfd;
    }

  vcom_nfds = max_vcom_fd != -1 ? max_vcom_fd + 1 : 0;

  if (!vcom_nfds)
    {
      rv = vcom_nfds;
      goto poll_done;
    }

  vcom_pollfds_2_selectfds (
			     /* src */
			     __fds, __nfds,
			     /* dest */
			     vcom_nfds,
			     &vcom_readfds, &vcom_writefds, &vcom_exceptfds);

  /* select on vcom fds */
  vcom_nfd = vcom_socket_select (vcom_nfds,
				 &vcom_readfds,
				 &vcom_writefds, &vcom_exceptfds, &tv);
  if (VCOM_DEBUG > 2)
    fprintf (stderr,
	     "[%d] vcom_socket_select: "
	     "'%04d'='%04d'\n", getpid (), vcom_nfd, vcom_nfds);

  if (vcom_nfd < 0)
    {
      rv = vcom_nfd;
      goto poll_done;
    }

  vcom_selectfds_2_pollfds (
			     /* dest */
			     __fds, __nfds, &nfd,
			     /* src */
			     vcom_nfds,
			     &vcom_readfds, &vcom_writefds, &vcom_exceptfds);

  rv = nfd;

poll_done:
  return rv;
}

/*
 * TBD: remove this static function once vppcom
 *      has an implementation in place
 *
 * ACTION:
 */
static int
vppcom_poll (struct pollfd *__fds, nfds_t __nfds, double time_to_wait)
{
  return -EOPNOTSUPP;
}

int
vcom_socket_poll_vppcom_impl (struct pollfd *__fds, nfds_t __nfds,
			      int __timeout)
{
  nfds_t fds_idx = 0;

  /* in seconds eg. 3.123456789 seconds */
  double time_to_wait = (double) 0;

  i32 sid;
  i32 vep_idx;

  /* replace vcom fd with session idx */
  for (fds_idx = 0; fds_idx < __nfds; fds_idx++)
    {
      /* ignore negative fds */
      if (__fds[fds_idx].fd < 0)
	{
	  continue;
	}

      /* non negative validated vcom fds */
      sid = vcom_socket_get_sid (__fds[fds_idx].fd);
      if (sid != INVALID_SESSION_ID)
	{
	  __fds[fds_idx].fd = sid;
	}
      else
	{
	  /* get vep_idx */
	  vep_idx = vcom_socket_get_vep_idx (__fds[fds_idx].fd);
	  if (vep_idx != INVALID_VEP_IDX)
	    {
	      __fds[fds_idx].fd = vep_idx;
	    }
	  else
	    {
	      return -EBADF;
	    }
	}
    }

  /* validate __timeout */
  if (__timeout > 0)
    {
      time_to_wait = (double) __timeout / (double) 1000;
    }
  else if (__timeout == 0)
    {
      time_to_wait = (double) 0;
    }
  else
    {
      time_to_wait = ~0;
    }

  return vppcom_poll (__fds, __nfds, time_to_wait);
}

int
vcom_socket_poll (struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
  /* select an implementation */

  /* return vcom_socket_poll_vppcom_impl (__fds, __nfds, __timeout); */
  return vcom_socket_poll_select_impl (__fds, __nfds, __timeout);
}

#ifdef __USE_GNU
int
vcom_socket_ppoll (struct pollfd *__fds, nfds_t __nfds,
		   const struct timespec *__timeout, const __sigset_t * __ss)
{
  return -EOPNOTSUPP;
}
#endif

int
vcom_socket_main_init (void)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;

  if (VCOM_DEBUG > 0)
    printf ("vcom_socket_main_init\n");

  if (!vsm->init)
    {
      /* TBD: define FD_MAXSIZE and use it here */
      pool_alloc (vsm->vsockets, FD_SETSIZE);
      vsm->sockidx_by_fd = hash_create (0, sizeof (i32));

      pool_alloc (vsm->vepolls, FD_SETSIZE);
      vsm->epollidx_by_epfd = hash_create (0, sizeof (i32));

      pool_alloc (vsm->vepitems, FD_SETSIZE);
      vsm->epitemidx_by_epfdfd = hash_create (0, sizeof (i32));

      vsm->epitemidxs_by_epfd = hash_create (0, sizeof (i32 *));
      vsm->epitemidxs_by_fd = hash_create (0, sizeof (i32 *));

      clib_time_init (&vsm->clib_time);

      vsm->init = 1;
    }

  return 0;
}


void
vcom_socket_main_show (void)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  vcom_socket_t *vsock;

  vcom_epoll_t *vepoll;

  vcom_epitem_t *vepitem;

  i32 epfd;
  i32 fd;
  i32 *vepitemidxs, *vepitemidxs_var;

  if (vsm->init)
    {
      /* from active list of vsockets show vsock */

      /* *INDENT-OFF* */
      pool_foreach (vsock, vsm->vsockets,
        ({
          printf(
                 "fd='%04d', sid='%08x',type='%-30s'\n",
                 vsock->fd, vsock->sid,
                 vcom_socket_type_str (vsock->type));
        }));
      /* *INDENT-ON* */

      /* from active list of vepolls, show vepoll */

      /* *INDENT-OFF* */
      pool_foreach (vepoll, vsm->vepolls,
        ({
          printf(
                 "epfd='%04d', vep_idx='%08x', "
                 "type='%-30s', "
                 "flags='%d', count='%d', close='%d'\n",
                 vepoll->epfd, vepoll->vep_idx,
                 vcom_socket_epoll_type_str (vepoll->type),
                 vepoll->flags, vepoll->count, vepoll->close);
        }));
      /* *INDENT-ON* */

      /* from active list of vepitems, show vepitem */

      /* *INDENT-OFF* */
      pool_foreach (vepitem, vsm->vepitems,
        ({
          printf(
                 "epfd='%04d', fd='%04d', "
                 "next_fd='%04d', prev_fd='%04d', "
                 "type='%-30s', "
                 "events='%04x', revents='%04x'\n",
                 vepitem->epfd, vepitem->fd,
                 vepitem->next_fd, vepitem->prev_fd,
                 vcom_socket_vcom_fd_type_str (vepitem->type),
                 vepitem->event.events, vepitem->revent.events);
        }));

      /* *INDENT-ON* */

      /* show epitemidxs for epfd */
      /* *INDENT-OFF* */
      hash_foreach (epfd, vepitemidxs,
                    vsm->epitemidxs_by_epfd,
      ({
        printf("\n[ '%04d': ", epfd);
        vec_foreach (vepitemidxs_var,vepitemidxs)
        {
          printf("'%04d' ", (int)vepitemidxs_var[0]);
        }
        printf("]\n");
      }));
      /* *INDENT-ON* */

      /* show epitemidxs for fd */
      /* *INDENT-OFF* */
      hash_foreach (fd, vepitemidxs,
                    vsm->epitemidxs_by_fd,
      ({
        printf("\n{ '%04d': ", fd);
        vec_foreach (vepitemidxs_var,vepitemidxs)
        {
          printf("'%04d' ", (int)vepitemidxs_var[0]);
        }
        printf("}\n");
      }));
      /* *INDENT-ON* */

    }
}

void
vcom_socket_main_destroy (void)
{
  vcom_socket_main_t *vsm = &vcom_socket_main;
  vcom_socket_t *vsock;

  vcom_epoll_t *vepoll;

  vcom_epitem_t *vepitem;

  i32 epfd;
  i32 fd;
  i32 *vepitemidxs;


  if (VCOM_DEBUG > 0)
    printf ("vcom_socket_main_destroy\n");

  if (vsm->init)
    {

      /*
       * from active list of vepitems,
       * remove all "vepitem" elements from the pool in a safe way
       * */

      /* *INDENT-OFF* */
      pool_flush (vepitem, vsm->vepitems,
        ({
          if ((vepitem->type == FD_TYPE_EPOLL) ||
              (vepitem->type == FD_TYPE_VCOM_SOCKET))
          {
             vcom_socket_epoll_ctl1 (vepitem->epfd, EPOLL_CTL_DEL,
                                     vepitem->fd, NULL);
             vepitem_init (vepitem);
          }
        }));
      /* *INDENT-ON* */

      pool_free (vsm->vepitems);
      hash_free (vsm->epitemidx_by_epfdfd);

      /* free vepitemidxs for each epfd */
      /* *INDENT-OFF* */
      hash_foreach (epfd, vepitemidxs,
                    vsm->epitemidxs_by_epfd,
      ({
        vec_free (vepitemidxs);
      }));
      /* *INDENT-ON* */
      hash_free (vsm->epitemidxs_by_epfd);

      /* free vepitemidxs for each fd */
      /* *INDENT-OFF* */
      hash_foreach (fd, vepitemidxs,
                    vsm->epitemidxs_by_fd,
      ({
        vec_free (vepitemidxs);
      }));
      /* *INDENT-ON* */
      hash_free (vsm->epitemidxs_by_fd);


      /*
       * from active list of vsockets,
       * close socket and vppcom session
       * */

      /* *INDENT-OFF* */
      pool_foreach (vsock, vsm->vsockets,
        ({
          if (vsock->type == SOCKET_TYPE_VPPCOM_BOUND)
            {
              vppcom_session_close (vsock->sid);
              vcom_socket_close_socket (vsock->fd);
              vsocket_init (vsock);
            }
        }));
      /* *INDENT-ON* */

      /*
       * return vsocket element to the pool
       * */

      /* *INDENT-OFF* */
      pool_flush (vsock, vsm->vsockets,
        ({
          // vsocket_init(vsock);
          ;
        }));
      /* *INDENT-ON* */

      pool_free (vsm->vsockets);
      hash_free (vsm->sockidx_by_fd);

      /*
       * from active list of vepolls,
       * close epoll and vppcom_epoll
       * */

      /* *INDENT-OFF* */
      pool_foreach (vepoll, vsm->vepolls,
        ({
          if (vepoll->type == EPOLL_TYPE_VPPCOM_BOUND)
            {
              vppcom_session_close (vepoll->vep_idx);
              vcom_socket_close_epoll (vepoll->epfd); /* TBD: */
              vepoll_init (vepoll);
            }
        }));
      /* *INDENT-ON* */

      /*
       * return vepoll element to the pool
       * */

      /* *INDENT-OFF* */
      pool_flush (vepoll, vsm->vepolls,
        ({
          // vepoll_init(vepoll);
          ;
        }));
      /* *INDENT-ON* */

      pool_free (vsm->vepolls);
      hash_free (vsm->epollidx_by_epfd);

      vsm->init = 0;
    }
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
