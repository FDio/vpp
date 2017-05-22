#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#include "memif_lib.h"

#define MEMIF_DEBUG 1

#if MEMIF_DEBUG == 1
#define DEBUG_LOG(...) printf("DEBUG_LOG: %s:%d: ", __func__, __LINE__); \
                       printf(__VA_ARGS__);                              \
                       printf("\n")
#define DEBUG_UNIX_LOG(...) printf("DEBUG_UNIX_LOG: %s:%d: ", __func__, __LINE__); \
                            printf(__VA_ARGS__);                                   \
                            printf("\n");
#endif

#define SIZEOF_SIGSET (_NSIG / 8)

memif_main_t memif_main;
int epfd;

memif_main_t *
dump_memif_main ()
{
    return &memif_main;
}

memif_if_t *
memif_dump (uword if_index)
{
    memif_main_t *mm = &memif_main;
    return (memif_if_t *) vec_get_at_index (if_index, mm->interfaces);
}

int
memif_file_add (memif_file_t *mf)
{
    memif_main_t *mm = &memif_main;
    struct epoll_event evt[2];
    memif_file_t *n_mf = (memif_file_t *) vec_get ((void **) &mm->files);
    memcpy (n_mf, mf, sizeof (memif_file_t));
    n_mf->index = n_mf - mm->files;
    memset (evt, 0, sizeof (evt));
    evt[0].data.u64 = n_mf->index;
    evt[0].events = EPOLLIN;
    evt[1].data.u64 = n_mf->index;
    evt[1].events = EPOLLOUT;
    if (epoll_ctl (epfd, EPOLL_CTL_ADD, n_mf->fd, evt) < 0)
    {
        int er = errno;
        DEBUG_LOG ("EPOLL_CTL_ADD: %s", strerror (er));
    }
    return n_mf->index;
}

void
memif_file_del (memif_file_t *mf)
{
    memif_main_t *mm = &memif_main;
    if (epoll_ctl (epfd, EPOLL_CTL_DEL, mf->fd, NULL) < 0)
    {
        int er = errno;
        DEBUG_LOG ("EPOLL_CTL_DEL: %s", strerror (er));
    }
    close (mf->fd);
    vec_free_at_index (mf->index, mm->files);
}

memif_if_t *
get_if_by_key (u64 key)
{
    memif_main_t *mm = &memif_main;
    if (mm->interfaces == NULL)
        return NULL;
    memif_if_t *mif;
    int i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
        if (mif->key == key)
            return mif;
    }
    return NULL;
}

void
memif_connect (memif_if_t *mif)
{
    u16 num_rings = mif->num_s2m_rings + mif->num_m2s_rings;
    memif_ring_data_t *rd;
    u16 i;
    for (i = 0; i < num_rings; i++)
    {
        rd = (memif_ring_data_t *) vec_get ((void **) &mif->ring_data);
        rd->last_head = 0;
    }

    mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
    mif->flags |= MEMIF_IF_FLAG_CONNECTED;
    (&memif_main)->on_connect (mif);
}

static void
memif_remove_pending_conn (memif_pending_conn_t * pending_conn)
{
  memif_main_t *mm = &memif_main;

  memif_file_del (&mm->files[pending_conn->connection.index]);
  vec_free_at_index (pending_conn->index, mm->pending_conns);
}

void
memif_disconnect (memif_if_t *mif)
{
    memif_main_t *mm = &memif_main;
    mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
    if (mif->interrupt_line.index != ~0)
        {
            memif_file_del (&mm->files[mif->interrupt_line.index]);
            mif->interrupt_line.index = ~0;
            mif->interrupt_line.fd = -1;
        }
    if (mif->connection.index != ~0)
        {
            memif_file_del (&mm->files[mif->connection.index]);
            mif->connection.index = ~0;
            mif->connection.fd = -1;
        }
    /*TODO: unmap shared memory file*/
    /*
    u64 buffer_offset = sizeof (memif_shm_t) +
        (mif->num_s2m_rings + mif->num_m2s_rings) *
        (sizeof (memif_ring_t) +
        sizeof (memif_desc_t) * (1 << mif->log2_ring_size));
    size_t shared_mem_size = buffer_offset + (mif->buffer_size *
        (mif->num_s2m_rings + mif->num_m2s_rings));
    munmap (*mif->regions, shared_mem_size);
    */
    /*free (mif->regions);*/
    (&memif_main)->on_disconnect (mif);
}

void
memif_close_if (memif_main_t *mm, memif_if_t *mif)
{
    memif_pending_conn_t *pending_conn = 0;
    memif_listener_t *listener = 0;
    memif_disconnect (mif);
    
    if (mif->listener_index != (uword) ~ 0)
        {
            listener = (memif_listener_t *) vec_get_at_index (
                            mif->listener_index, mm->listeners);
            if (--listener->usage_counter == 0)
                {
                    /* not used anymore -> remove the socket and pending connections */
                    /* *INDENT-OFF* */
                    int i = -1;
                    while ((pending_conn = (memif_pending_conn_t *) vec_get_next (
                                                &i, mm->pending_conns)) != NULL )
                    {
                            if (pending_conn->listener_index == 
                                        mif->listener_index)
                                {
                                    memif_remove_pending_conn (pending_conn);
                                }
                    }
                    /* *INDENT-ON* */
                    memif_file_del ((memif_file_t *) vec_get_at_index (
                                        listener->socket.index, mm->files));
                    vec_free_at_index (listener->index, mm->listeners);
                    unlink ((char *) mif->socket_filename);
                }
        }


  /*
  if (mif->socket_filename != NULL)
    {
      free (mif->socket_filename);
      mif->socket_filename = NULL;
    }
  */
  vec_free (mif->ring_data);
  mif->ring_data = NULL;

  vec_free_at_index (mif->if_index, mm->interfaces);
  memset (mif, 0, sizeof (*mif));
}

int memif_delete (uword if_index)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    if ((mif = memif_dump (if_index)) == NULL)
        return -1;
    memif_msg_t msg = { 0 };
    msg.version = MEMIF_VERSION;
    msg.type = MEMIF_MSG_TYPE_DISCONNECT;
    if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
    {
        if (send (mif->connection.fd, &msg, sizeof (msg), 0) < 0)
          *DEBUG_LOG ("%s", strerror(errno));
    }
    mif->flags |= MEMIF_IF_FLAG_DELETING;
    memif_close_if (mm, mif);
    /*MEMIF_PROCESS_EVENT_STOP*/
    return 0;
}

void
memif_bring_up (uword if_index)
{
    memif_if_t *mif = { 0 };
    if ((mif = memif_dump (if_index)) != NULL)
        {
            mif->flags |= MEMIF_IF_FLAG_ADMIN_UP;
            return;
        }
}

void
memif_bring_down (uword if_index)
{
    memif_if_t *mif = { 0 };
    if ((mif = memif_dump (if_index)) != NULL)
        {
            mif->flags = ~MEMIF_IF_FLAG_ADMIN_UP;
            return;
        }
}

void
memif_set_mode (u16 flags)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    mm->flags = flags;
    memif_msg_t msg = { 0 };
    
    int i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
        if ((mif->flags & MEMIF_IF_FLAG_CONNECTED) == 0)
            continue;
        msg.version = MEMIF_VERSION;
        msg.type = MEMIF_MSG_TYPE_IF_MOD;
        msg.flags = mm->flags;

        ssize_t rv = send (mif->connection.fd, &msg, sizeof (msg), 0);
        if (rv < 0)
            {
                DEBUG_UNIX_LOG ("Failed to send memif modification request");
            }
    }
}

memif_main_t *
memif_init (u16 flags, memif_function_t *on_connect,
                memif_function_t *on_disconnect, memif_function_data_t *on_incoming_data,
                memif_function_t *on_interrupt)
{
    memif_main_t *mm = &memif_main;
    memset (mm, 0, sizeof (memif_main_t));

    mm->interfaces = vec_init (sizeof (memif_if_t));
    mm->listeners = vec_init (sizeof (memif_listener_t));
    mm->pending_conns = vec_init (sizeof (memif_pending_conn_t));
    mm->files = vec_init (sizeof (memif_file_t));
    mm->int_if = vec_init (sizeof (u16));

    mm->default_socket_filename = malloc (strlen(MEMIF_DEFAULT_SOCKET_FILENAME));
    strncpy ((char *)mm->default_socket_filename,
             MEMIF_DEFAULT_SOCKET_FILENAME, strlen(MEMIF_DEFAULT_SOCKET_FILENAME));

    mm->flags = flags;
    mm->on_connect = on_connect;
    mm->on_disconnect = on_disconnect;
    mm->on_interrupt = on_interrupt;
    mm->on_incoming_data = on_incoming_data;
    return mm;
}

void *
memif_on_interrupt (memif_if_t *mif)
{
    memif_main_t *mm = &memif_main;

    u16 *int_if = (u16 *) vec_get ((void **) &mm->int_if);
    *int_if = mif->if_index;

    return 0;
}

void *
memif_int_fd_read_ready (memif_file_t *mf)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif = &mm->interfaces[mf->data];
    u8 b;
    ssize_t size;

    size = read (mf->fd, &b, sizeof (b));
    if (0 == size)
        {
            /* interrupt line was disconnected */
            memif_file_del (&mm->files[mif->interrupt_line.index]);
            mif->interrupt_line.index = ~0;
            mif->interrupt_line.fd = -1;
            return 0;
        }
    u8 c[CACHE_LINE_BYTES];
    while (1)
      {
        size = read (mf->fd, &c, sizeof (c));
        if (size < 0){
          if ((errno != EWOULDBLOCK) && (errno != EAGAIN))
            {
                int er = errno;
                DEBUG_LOG("recv error! Error: %s", strerror(er));
            }
        break;
        }
      }
    mm->on_interrupt (mif);
    return 0;
}

static void *
memif_process_connect_req (memif_pending_conn_t * pending_conn,
                            memif_msg_t * req, struct ucred *slave_cr,
                            int shm_fd, int int_fd)
{
    memif_main_t *mm = &memif_main;
    int fd = pending_conn->connection.fd;
    memif_file_t *mf = 0;
    memif_if_t *mif = 0;
    memif_msg_t resp = { 0 };
    memif_file_t template = { 0 };
    void *shm;
    u8 retval = 0;

    if (shm_fd == -1)
        {
            DEBUG_LOG
            ("Connection request is missing shared memory file descriptor");
            retval = 1;
            goto response;
        }

    if (int_fd == -1)
        {
            DEBUG_LOG
            ("Connection request is missing interrupt line file descriptor");
            retval = 2;
            goto response;
        }

    if (slave_cr == NULL)
        {
            DEBUG_LOG ("Connection request is missing slave credentials");
            retval = 3;
            goto response;
        }

    mif = get_if_by_key (req->key);
    if (!mif)
        {
            DEBUG_LOG ("mif: %p", mif);
            DEBUG_LOG
            ("Connection request with unmatched key (0x%" PRIx64 ")", req->key);
            retval = 4;
            goto response;
        }

    if (mif->listener_index != pending_conn->listener_index)
        {
            DEBUG_LOG
            ("Connection request with non-matching listener (%d vs. %d)",
            pending_conn->listener_index, mif->listener_index);
            retval = 5;
            goto response;
        }

    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        {
            DEBUG_LOG ("Memif slave does not accept connection requests");
            retval = 6;
            goto response;
        }

    if (mif->connection.fd != -1)
        {
            DEBUG_LOG
            ("Memif with key 0x%" PRIx64 " is already connected", mif->key);
            retval = 7;
            goto response;
        }

    if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
        {
            /* just silently decline the request */
            retval = 8;
            goto response;
        }

    if (req->shared_mem_size < sizeof (memif_shm_t))
        {
            DEBUG_LOG
            ("Unexpectedly small shared memory segment received from slave.");
            retval = 9;
            goto response;
        }

    if ((shm =
        mmap (NULL, req->shared_mem_size, PROT_READ | PROT_WRITE, MAP_SHARED,
            shm_fd, 0)) == MAP_FAILED)
        {
            DEBUG_UNIX_LOG
            ("Failed to map shared memory segment received from slave memif");
            retval = 10;
            goto response;
        }

    if (((memif_shm_t *) shm)->cookie != 0xdeadbeef)
        {
            DEBUG_LOG
        ("Possibly corrupted shared memory segment received from slave memif");
        munmap (shm, req->shared_mem_size);
        retval = 11;
        goto response;
        }

    if (req->flags & MEMIF_MM_FLAG_IS_INT)
        mif->flags |= MEMIF_IF_FLAG_PEER_INT;
    else
        mif->flags &= ~MEMIF_IF_FLAG_PEER_INT;
    mif->log2_ring_size = req->log2_ring_size;
    mif->num_s2m_rings = req->num_s2m_rings;
    mif->num_m2s_rings = req->num_m2s_rings;
    mif->buffer_size = req->buffer_size;
    mif->remote_pid = slave_cr->pid;
    mif->remote_uid = slave_cr->uid;
    (*mif->regions) = shm;

    /* register interrupt line */
    mif->interrupt_line.fd = int_fd;
    template.read_function = memif_int_fd_read_ready;
    template.fd = int_fd;
    template.data = mif->if_index;
    mif->interrupt_line.index = memif_file_add (&template);

    /* change context for future messages */
    mf = (memif_file_t *) vec_get_at_index (pending_conn->connection.index, mm->files);
    mf->data = mif->if_index << 1;
    mif->connection = pending_conn->connection;
    vec_free_at_index (pending_conn->index, mm->pending_conns);
    pending_conn = 0;

    memif_connect (mif);

response:
  resp.version = MEMIF_VERSION;
  resp.type = MEMIF_MSG_TYPE_CONNECT_RESP;
  resp.retval = retval;
  resp.flags = mm->flags;
  if ((send (fd, &resp, sizeof (resp), 0)) < 0)
    {
        int er = errno;
        DEBUG_LOG ("%s", strerror (er));
    if (pending_conn)
        memif_remove_pending_conn (pending_conn);
    else
      {
        memif_disconnect (mif);
      }
    }
  if (retval > 0)
    {
      if (shm_fd >= 0)
    {
      close (shm_fd);
      shm_fd = -1;
    }
      if (int_fd >= 0)
    {
      close (int_fd);
      int_fd = -1;
    }
    }
  return NULL;
}

static void *
memif_process_connect_resp (memif_if_t *mif, memif_msg_t *resp)
{
    if ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) == 0)
        {
            DEBUG_LOG ("Memif master does not accept connection responses");
            return 0;
        }

    if ((mif->flags & MEMIF_IF_FLAG_CONNECTING) == 0)
        {
            DEBUG_LOG ("Unexpected connection response");
            return 0;
        }

    if (resp->retval == 0)
    {
        if (resp->flags & MEMIF_MM_FLAG_IS_INT)
            mif->flags |= MEMIF_IF_FLAG_PEER_INT;
        else
            mif->flags &= ~MEMIF_IF_FLAG_PEER_INT;
        memif_connect (mif);
    }
    else
    {
        memif_disconnect (mif);
    }

    return 0;
}

void *
memif_conn_fd_read_ready (memif_file_t * mf)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif = 0;
    memif_pending_conn_t *pending_conn = 0;
    int fd_array[2] = { -1, -1 };
    char ctl[CMSG_SPACE (sizeof (fd_array)) +
       CMSG_SPACE (sizeof (struct ucred))] = { 0 };
    struct msghdr mh = { 0 };
    struct iovec iov[1];
    struct ucred *cr = 0;
    memif_msg_t msg = { 0 };
    struct cmsghdr *cmsg;
    ssize_t size;

    iov[0].iov_base = (void *) &msg;
    iov[0].iov_len = sizeof (memif_msg_t);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctl;
    mh.msg_controllen = sizeof (ctl);

    /* grab the appropriate context */
    if (mf->data & 1)
        pending_conn = (memif_pending_conn_t *) vec_get_at_index (
                            mf->data >> 1, mm->pending_conns);
    else
        mif = (memif_if_t *) vec_get_at_index (mf->data >> 1, mm->interfaces);

    /* receive the incoming message */
    size = recvmsg (mf->fd, &mh, 0);
    if (size != sizeof (memif_msg_t))
        {
            if (size != 0)
                {
                    DEBUG_UNIX_LOG ("Malformed message received on fd %d",
                        mf->fd);
                }
            goto disconnect;
        }
    /* check version of the sender's memif plugin */
    if (msg.version != MEMIF_VERSION)
        {
            DEBUG_LOG ("Memif version mismatch");
            goto disconnect;
        }
    
    /* process the message based on its type */
    switch (msg.type)
        {
            case MEMIF_MSG_TYPE_CONNECT_REQ:
                if (pending_conn == 0)
                    {
                        DEBUG_LOG ("Received unexpected connection request");
                        return 0;
                    }

                /* Read anciliary data */
                cmsg = CMSG_FIRSTHDR (&mh);
                while (cmsg)
                    {
                        if (cmsg->cmsg_level == SOL_SOCKET
                            && cmsg->cmsg_type == SCM_CREDENTIALS)
                            {
                                cr = (struct ucred *) CMSG_DATA (cmsg);
                            }
                        else if (cmsg->cmsg_level == SOL_SOCKET
                            && cmsg->cmsg_type == SCM_RIGHTS)
                            {
                                memcpy (fd_array, CMSG_DATA (cmsg), sizeof (fd_array));
                            }
                        cmsg = CMSG_NXTHDR (&mh, cmsg);
                    }

                return memif_process_connect_req (pending_conn, &msg, cr,
                    fd_array[0], fd_array[1]);

            case MEMIF_MSG_TYPE_CONNECT_RESP:
                if (mif == 0)
                    {
                        DEBUG_LOG ("Received unexpected connection response");
                        return 0;
                    }
                return memif_process_connect_resp (mif, &msg);

            case MEMIF_MSG_TYPE_IF_MOD:
                {
                    if (msg.flags & MEMIF_MM_FLAG_IS_INT)
                    {
                        mif->flags |= MEMIF_IF_FLAG_PEER_INT;
                    }
                    else
                    {
                        mif->flags &= ~MEMIF_IF_FLAG_PEER_INT;
                    }
                    return 0;
                }

            case MEMIF_MSG_TYPE_DISCONNECT:
              {
                memif_disconnect (mif);
                return 0;
              }

            default:
            DEBUG_LOG ("Received unknown message type");
            goto disconnect;
        }
    return 0;

disconnect:
  if (pending_conn)
    memif_remove_pending_conn (pending_conn);
  else
    {
    memif_disconnect (mif);
    }
  return NULL;
}

void *
memif_conn_fd_accept_ready (memif_file_t * mf)
{
    memif_main_t *mm = &memif_main;
    memif_listener_t *listener = 0;
    memif_pending_conn_t *pending_conn = 0;
    int addr_len;
    struct sockaddr_un client;
    int conn_fd;
    memif_file_t template = { 0 };
    
    listener = &mm->listeners[mf->data];

    addr_len = sizeof (client);
    conn_fd = accept (mf->fd,
         (struct sockaddr *) &client, (socklen_t *) &addr_len);

    if (conn_fd < 0)
    {
        DEBUG_LOG ("accept fd %d", mf->fd);
        return NULL;
    }

    pending_conn = (memif_pending_conn_t *) vec_get ((void **) &mm->pending_conns); 
    pending_conn->index = pending_conn - mm->pending_conns;
    pending_conn->listener_index = listener->index;
    pending_conn->connection.fd = conn_fd;

    template.read_function = memif_conn_fd_read_ready;
    template.fd = conn_fd;
    template.data = (pending_conn->index << 1) | 1;
    pending_conn->connection.index = memif_file_add (&template);

    return 0;
}

void
epoll_init ()
{
    epfd = epoll_create(1);
}

void
poll_event (int timeout)
{
    memif_main_t *mm = &memif_main;
    struct epoll_event evt[2], *e;
    memset (&evt, 0, sizeof(evt));
    evt[0].events = EPOLLIN;
    evt[1].events = EPOLLOUT;
    static sigset_t uas;
    int rv = epoll_pwait (epfd, evt, 1, timeout, &uas);
    if (rv < 0)
    {
        DEBUG_LOG("epoll_pwait error: %s", strerror(errno));
        return;
    }
    if (rv > 0)
    {
        for (e = evt; e < evt + rv; e++)
        {
            if (e->events & EPOLLIN)
            {
                memif_file_t *f= (memif_file_t *) vec_get_at_index (
                    e->data.u64, mm->files);
                f->read_function (f);
            }
            if (e->events & EPOLLOUT)
            {
                memif_file_t *f = (memif_file_t *) vec_get_at_index (
                    e->data.u64, mm->files);
                f->write_function (f);
            }
        }
    }
}

int
memif_send_conn_req (memif_if_t *mif)
{
    memif_main_t *mm = &memif_main;
    memif_msg_t msg;
    struct msghdr mh = { 0 };
    struct iovec iov[1];
    struct cmsghdr *cmsg;
    int mfd = -1;
    int rv;
    int fd_array[2] = { -1, -1 };
    char ctl[CMSG_SPACE (sizeof (fd_array))];
    memif_ring_t *ring = NULL;
    int i, j;
    void *shm = 0;
    u64 buffer_offset;
    memif_file_t template = { 0 };

    msg.version = MEMIF_VERSION;
    msg.type = MEMIF_MSG_TYPE_CONNECT_REQ;
    msg.key = mif->key;
    msg.log2_ring_size = mif->log2_ring_size;
    msg.num_s2m_rings = mif->num_s2m_rings;
    msg.num_m2s_rings = mif->num_m2s_rings;
    msg.buffer_size = mif->buffer_size;
    msg.flags = mm->flags;

    buffer_offset = sizeof (memif_shm_t) +
        (mif->num_s2m_rings + mif->num_m2s_rings) *
        (sizeof (memif_ring_t) +
        sizeof (memif_desc_t) * (1 << mif->log2_ring_size));

    msg.shared_mem_size = buffer_offset + (mif->buffer_size *
        (mif->num_s2m_rings + mif->num_m2s_rings));

    if ((mfd = memfd_create ("shared mem", MFD_ALLOW_SEALING)) == -1)
        {
            DEBUG_LOG ("Failed to create anonymous file");
            goto error;
        }

    if ((fcntl (mfd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
        {
            DEBUG_UNIX_LOG ("Failed to seal an anonymous file off from truncating");
            goto error;
        }

    if ((ftruncate (mfd, msg.shared_mem_size)) == -1)
        {
            DEBUG_UNIX_LOG ("Failed to extend the size of an anonymous file");
            goto error;
        }

    if ((shm = mmap (NULL, msg.shared_mem_size, PROT_READ | PROT_WRITE,
           MAP_SHARED, mfd, 0)) == MAP_FAILED)
        {
            int er = errno;
            DEBUG_UNIX_LOG ("Failed to map anonymous file into memory. ERROR: %s",
                                strerror (er));
            goto error;
        }

    (*mif->regions) = shm;
    ((memif_shm_t *) mif->regions[0])->cookie = 0xdeadbeef;
    for (i = 0; i < mif->num_s2m_rings; i++)
        {
            ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
            ring->head_offset = ring->head = ring->tail = 0;
            ring->buffer_offset = buffer_offset;
            for (j = 0; j < (1 << mif->log2_ring_size); j++)
                {
                    ring->desc[j].region = 0;
                    ring->desc[j].offset = buffer_offset;
                    ring->desc[j].buffer_length = 0;
                }
        }
    for (i = 0; i < mif->num_m2s_rings; i++)
        {
            ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
            ring->head_offset = ring->head = ring->tail = 0;
            ring->buffer_offset = buffer_offset + mif->buffer_size;
            for (j = 0; j < (1 << mif->log2_ring_size); j++)
            {
                ring->desc[j].region = 0;
                ring->desc[j].offset = buffer_offset + mif->buffer_size;
                ring->desc[j].buffer_length = 0;
            }
        }

    iov[0].iov_base = (void *) &msg;
    iov[0].iov_len = sizeof (memif_msg_t);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;

    /* create interrupt socket */
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, fd_array) < 0)
        {
            int er = errno;
            DEBUG_UNIX_LOG ("Failed to create a pair of connected sockets. ERROR: %s",
                                strerror (er));
            goto error;
        }

    if (fcntl (fd_array[0], F_SETFL, O_NONBLOCK) < 0)
    {
        int er = errno;
      DEBUG_LOG("%s", strerror(er));
    }
    if (fcntl (fd_array[1], F_SETFL, O_NONBLOCK) < 0)
    {
        int er = errno;
      DEBUG_LOG("%s", strerror(er));
    }

    mif->interrupt_line.fd = fd_array[0];
    template.read_function = memif_int_fd_read_ready;
    template.fd = mif->interrupt_line.fd;
    template.data = mif->if_index;
    mif->interrupt_line.index = memif_file_add (&template);

    memset (&ctl, 0, sizeof (ctl));
    mh.msg_control = ctl;
    mh.msg_controllen = sizeof (ctl);
    cmsg = CMSG_FIRSTHDR (&mh);
    cmsg->cmsg_len = CMSG_LEN (sizeof (fd_array));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    fd_array[0] = mfd;
    memcpy (CMSG_DATA (cmsg), fd_array, sizeof (fd_array));

    mif->flags |= MEMIF_IF_FLAG_CONNECTING;
    rv = sendmsg (mif->connection.fd, &mh, 0);
    if (rv < 0)
        {
            DEBUG_UNIX_LOG ("Failed to send memif connection request");
        }

    /* No need to keep the descriptor open,
    * mmap creates an extra reference to the underlying file */
    close (mfd);
    mfd = -1;
    /* This FD is given to peer, so we can close it */
    close (fd_array[1]);
    fd_array[1] = -1;
    return 0;

error:
  if (mfd > -1)
    {
      close (mfd);
      mfd = -1;
    }
  if (fd_array[1] > -1)
    {
      close (fd_array[1]);
      fd_array[1] = -1;
    }
  munmap (shm, msg.shared_mem_size);
  memif_disconnect (mif);
  return -1;
}

void
memif_connect_master (memif_if_t *mif)
{
    struct sockaddr_un sun;
    sun.sun_family = AF_UNIX;
    strncpy (sun.sun_path, (char *) mif->socket_filename,
                sizeof (sun.sun_path) - 1);
    int sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0){
        DEBUG_LOG("socket () FAIL!\nError: %s", strerror(errno));
    }
    memif_file_t temp = { 0 };
    if (connect (sockfd, (struct sockaddr *) &sun, sizeof (struct sockaddr_un)) == 0)
        {
            mif->connection.fd = sockfd;
            temp.fd = sockfd;
            temp.read_function = memif_conn_fd_read_ready;
            temp.data = mif->if_index << 1;
            mif->connection.index = memif_file_add (&temp);
        }
    else
        {
            /*DEBUG_LOG ("connect() FAIL!\nError: %s\n", strerror(errno));*/
            close(sockfd);
            sockfd = -1;
            return;
        }
    if (memif_send_conn_req (mif) < 0)
        {
            close (sockfd);
            sockfd = -1;
        }
}

uword
memif_create (memif_create_args_t *args)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    int ret = 0;

    mif = get_if_by_key (args->key);
    if (mif) {
        DEBUG_LOG ("Memif with key 0x%" PRIx64 " already exists.", args->key);
        return ret;
    }

    mif = (memif_if_t *) vec_get ((void **) &mm->interfaces);
    memset (mif, 0, sizeof (*mif));
    mif->key = args->key;
    mif->if_index = mif - mm->interfaces;
    mif->listener_index = ~0;
    mif->connection.index = mif->interrupt_line.index = ~0;
    mif->connection.fd = mif->interrupt_line.fd = -1;
    mif->flags = 0;
    mif->regions = (void **) vec_init (sizeof (void *));
    mif->ring_data = (memif_ring_data_t *) vec_init (sizeof (memif_ring_data_t));


    mif->log2_ring_size = args->log2_ring_size;
    mif->buffer_size = args->buffer_size;

    /* TODO: make configurable */
    mif->num_s2m_rings = 1;
    mif->num_m2s_rings = 1;

    if (args->socket_filename != 0)
        mif->socket_filename = args->socket_filename;
    else
        mif->socket_filename = mm->default_socket_filename;

    if (args->is_master)
    {
        struct sockaddr_un un = { 0 };
        struct stat file_stat;
        int on = 1;
        memif_listener_t *listener = 0;

        if (stat ((char *) mif->socket_filename, &file_stat) == 0)
            {
                if (!S_ISSOCK (file_stat.st_mode))
                    {
                        errno = ENOTSOCK;
                        goto error;
                    }
                /* *INDENT-OFF* */
                int i = -1;
                while ((listener =
                        (memif_listener_t *) vec_get_next (&i, mm->listeners)) != NULL)
                {
                        if (listener->sock_dev == file_stat.st_dev &&
                                listener->sock_ino == file_stat.st_ino)
                        {
                            /* attach memif to the existing listener */
                            mif->listener_index = listener->index;
                            ++listener->usage_counter;
                            goto signal;
                        }
                }
                /* *INDENT-ON* */
                unlink ((char *) mif->socket_filename);
            }

        listener = (memif_listener_t *) vec_get ((void **) &mm->listeners);
        memset (listener, 0, sizeof (*listener));
        listener->socket.fd = -1;
        listener->socket.index = ~0;
        listener->index = listener - mm->listeners;
        listener->usage_counter = 1;

        if ((listener->socket.fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
            {
                goto error;
            }

        un.sun_family = AF_UNIX;
        strncpy ((char *) un.sun_path, (char *) mif->socket_filename, sizeof (un.sun_path) - 1);

        if (setsockopt (listener->socket.fd, SOL_SOCKET, SO_PASSCRED,
                        &on, sizeof (on)) < 0)
            {
                goto error;
            }
        if (bind (listener->socket.fd, (struct sockaddr *) &un,
                    sizeof (un)) == -1)
            {
                goto error;
            }
        if (listen (listener->socket.fd, 1) == -1)
            {
                goto error;
            }

        if (stat ((char *) mif->socket_filename, &file_stat) == -1)
            {
                goto error;
            }

        listener->sock_dev = file_stat.st_dev;
        listener->sock_ino = file_stat.st_ino;
        memif_file_t template = { 0 };
        template.read_function = memif_conn_fd_accept_ready;
        template.fd = listener->socket.fd;
        template.data = listener->index;
        listener->socket.index = memif_file_add (&template);
        mif->listener_index = listener->index;
    }
    else
        {
            mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;
        }

signal:
  return 0;

error:
  memif_close_if (mm, mif);
  return ret;
}

static void *
memif_int_fd_write_ready (memif_file_t * mf)
{
  u8 b;
  ssize_t size = write (mf->fd, &b, sizeof (b));
  if (size < 0)
    {
      if (errno != EWOULDBLOCK)
    {
      DEBUG_LOG ("write interrupt ready fail!");                  
      memif_file_del (mf);
    }
      return 0;
    }
  memif_file_del (mf);
  return 0;
}

int
memif_send (uword if_index)
{
    memif_ring_type_t type;
    memif_if_t *mif = memif_dump(if_index);
    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        type = MEMIF_RING_S2M;
    else
        type = MEMIF_RING_M2S;
    u8 rid = 0;
    memif_ring_t *ring = memif_get_ring (mif, type, rid);
    u16 ring_size = 1 << mif->log2_ring_size;
    u16 mask = ring_size - 1;
    u16 head;
    int rv;    

    head = ring->head;
 
    head = (head + ring->head_offset) & mask;
    rv = ring->head_offset;
    ring->head_offset = 0;

    if (mif->flags & MEMIF_IF_FLAG_PEER_INT)
    {
        u8 b = rid;
        int res = write (mif->interrupt_line.fd, &b, sizeof (b));
        if (res < 0)
        {
            if (errno == EWOULDBLOCK)
        {
            /* if write would block add file descriptor to epoll_fd */
            memif_file_t template = { 0 };
            template.fd = mif->interrupt_line.fd;
            template.data = mif->if_index << 1;
            template.write_function = memif_int_fd_write_ready;
            memif_file_add (&template);
        }
        else
        {
            int er = errno;
            DEBUG_LOG ("ERROR: %s", strerror (er));
        }
        }
    }
    ring->head = head;
    return rv;
}

int
memif_recv (uword if_index, struct iovec **iov, u32 iov_arr_len)
{
    memif_if_t *mif = memif_dump(if_index);
    memif_ring_type_t type;
    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        type = MEMIF_RING_M2S;
    else
        type = MEMIF_RING_S2M;
    u8 rid = 0;           /* Ring id */
    memif_ring_t *ring = memif_get_ring (mif, type, rid);
    memif_ring_data_t *rd = (memif_ring_data_t *) vec_get_at_index (
                                rid + type * mif->num_s2m_rings, mif->ring_data);
    u16 head;
    u16 ring_size = 1 << mif->log2_ring_size;
    u16 mask = ring_size - 1;
    u16 num_slots;
    u32 rx = 0;


    head = ring->head;
    if (head == rd->last_head)
        return 0;

    if (head > rd->last_head)
        num_slots = head - rd->last_head;
    else
        num_slots = ring_size - rd->last_head + head;

    while (num_slots && iov_arr_len)
    {
        while (num_slots > 2 && iov_arr_len > 2)
        {
            (*iov + rx)->iov_base = memif_get_buffer (mif, ring, rd->last_head);
            (*iov + rx)->iov_len = ring->desc[rd->last_head].buffer_length;
            rd->last_head = (rd->last_head + 1) & mask;
            
            (*iov + rx + 1)->iov_base = memif_get_buffer (mif, ring, rd->last_head);
            (*iov + rx + 1)->iov_len = ring->desc[(rd->last_head + 1) & mask].buffer_length;
            rd->last_head = (rd->last_head + 1) & mask;
            
            num_slots -= 2;
            rx += 2;
            iov_arr_len -= 2;
        }
        
        (*iov + rx)->iov_base = memif_get_buffer (mif, ring, rd->last_head);
        (*iov + rx)->iov_len = ring->desc[rd->last_head].buffer_length;
        rd->last_head = (rd->last_head + 1) & mask;
        
        num_slots--;
        rx++;
        iov_arr_len--;
    }
    (&memif_main)->on_incoming_data (mif, iov, rx);
    return rx;
}

void
memif_update_ring (memif_if_t *mif)
{
    memif_ring_t *ring;
    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        ring = memif_get_ring (mif, MEMIF_RING_M2S, 0);
    else
        ring = memif_get_ring (mif, MEMIF_RING_S2M, 0);

    ring->tail = ring->head;
}

int
memif_loop_run (int timeout)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    int iov_arr_len = 255, rx = 0, ret = 0;
    struct iovec *iov;
    poll_event (timeout);/*if event: calls read function assigned to fd on which event occured*/
    int i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
            if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
                continue;

            if (mif->flags & MEMIF_IF_FLAG_CONNECTING)
                continue;

            if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
                {
                    if ((mm->flags & MEMIF_MM_FLAG_IS_INT) == 0)
                    {
                        do 
                        {
                            iov = (struct iovec *)malloc(sizeof(struct iovec) * iov_arr_len);
                            rx += ret = memif_recv (mif->if_index, &iov, iov_arr_len);
                            free(iov);
                            iov = NULL;
                        } while (ret != 0);
                        memif_update_ring (mif);
                    }
                    continue;
                }

            if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
                {
                    memif_connect_master (mif);
                }
    }
    if (mm->flags & MEMIF_MM_FLAG_IS_INT)
    {
        i = -1;
        u16 *int_if;
        while ((int_if =
                (u16 *) vec_get_next (&i, mm->int_if)) != NULL)
        {
            do
            {
                iov = (struct iovec *)malloc(sizeof(struct iovec) * iov_arr_len);
                rx += ret = memif_recv (*int_if, &iov, iov_arr_len);
                free(iov);
                iov = NULL;
            } while (ret != 0);
            mif = memif_dump (*int_if);
            vec_free_at_index (i, mm->int_if);
            memif_update_ring (mif);
        i++;
        }
    }
    return rx;
}
