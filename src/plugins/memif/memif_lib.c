#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
/*#include <vpp/app/version.h>*/
#include "memif_lib.h"

#define MEMIF_DEBUG 1

#if MEMIF_DEBUG == 1
#define DEBUG_LOG(...) clib_warning(__VA_ARGS__)
#define DEBUG_UNIX_LOG(...) clib_unix_warning(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

#define SIZEOF_SIGSET (_NSIG / 8)

memif_main_t memif_main;
int epfd;

memif_if_t *
memif_dump (uword if_index)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif = { 0 };
    pool_foreach (mif, mm->interfaces,
        ({
            if (mif->if_index == if_index)
                {
                    return mif;
                }
        }));
    DEBUG_LOG ("Memif with index %d not found.", if_index);
    return NULL;
}

void
memif_file_update (unix_file_t *f, unix_file_update_type_t update_type)
{
    struct epoll_event evt;
    if (update_type == UNIX_FILE_UPDATE_ADD)
        {
            memset (&evt, 0, sizeof(evt));
            evt.data.ptr = f;
            evt.events = EPOLLIN;
            if (epoll_ctl (epfd, EPOLL_CTL_ADD, f->file_descriptor, &evt) < 0)
                DEBUG_LOG ("Failed to add fd to epoll.\n");
        }
}

void
memif_set_file_update ()
{
    unix_main_t *um = &unix_main;
    um->file_update = memif_file_update;
}

void
memif_connect (memif_if_t *mif)
{
    int num_rings = mif->num_s2m_rings + mif->num_m2s_rings;
    memif_ring_data_t *rd = NULL;

    vec_validate_aligned (mif->ring_data, num_rings - 1, CLIB_CACHE_LINE_BYTES);
        vec_foreach (rd, mif->ring_data)
            {
                rd->last_head = 0;
            }
    mif->head_offset = 0;
    mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
    mif->flags |= MEMIF_IF_FLAG_CONNECTED;
}

static void
memif_remove_pending_conn (memif_pending_conn_t * pending_conn)
{
  memif_main_t *mm = &memif_main;

  unix_file_del (&unix_main,
         unix_main.file_pool + pending_conn->connection.index);
  pool_put (mm->pending_conns, pending_conn);
}

void
memif_disconnect (memif_if_t *mif)
{
    mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
    if (mif->interrupt_line.index != ~0)
        {
            unix_file_del (&unix_main, unix_main.file_pool + mif->interrupt_line.index);
            mif->interrupt_line.index = ~0;
            mif->interrupt_line.fd = -1;
        }
    if (mif->connection.index != ~0)
        {
            unix_file_del (&unix_main, unix_main.file_pool + mif->connection.index);
            mif->connection.index = ~0;
            mif->connection.fd = -1;
        }
    /*TODO: unmap shared memory file*/
    /*munmap (*mif->regions, vec_len (*mif->regions));*/
    vec_free (mif->regions);
}

static void
memif_close_if (memif_main_t *mm, memif_if_t *mif)
{
    memif_listener_t *listener = 0;
    memif_pending_conn_t *pending_conn = 0;
    memif_disconnect (mif);
    
    if (mif->listener_index != (uword) ~ 0)
        {
            listener = pool_elt_at_index (mm->listeners, mif->listener_index);
            if (--listener->usage_counter == 0)
                {
                    /* not used anymore -> remove the socket and pending connections */
                    /* *INDENT-OFF* */
                    pool_foreach (pending_conn, mm->pending_conns,
                        ({
                            if (pending_conn->listener_index == mif->listener_index)
                                {
                                    memif_remove_pending_conn (pending_conn);
                                }
                        }));
                    /* *INDENT-ON* */
                    unix_file_del (&unix_main,
                            unix_main.file_pool + listener->socket.index);
                    pool_put (mm->listeners, listener);
                    unlink ((char *) mif->socket_filename);
                }
        }

  /*clib_spinlock_free (&mif->lockp);*/

  mhash_unset (&mm->if_index_by_key, &mif->key, &mif->if_index);
  vec_free (mif->socket_filename);
  vec_free (mif->ring_data);

  memset (mif, 0, sizeof (*mif));
  pool_put (mm->interfaces, mif);
}

int memif_delete (uword if_index)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    if ((mif = memif_dump (if_index)) == NULL)
        return -1;
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

int
memif_init ()
{
    memif_main_t *mm = &memif_main;
    memset (mm, 0, sizeof (memif_main_t));
    mhash_init (&mm->if_index_by_key, sizeof (uword), sizeof (u64));
    vec_validate (mm->default_socket_filename,
        strlen (MEMIF_DEFAULT_SOCKET_FILENAME));
    strncpy ((char *) mm->default_socket_filename, MEMIF_DEFAULT_SOCKET_FILENAME,
             vec_len (mm->default_socket_filename) - 1);
    return 0;
}

static clib_error_t *
memif_int_fd_read_ready (unix_file_t *uf)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
    u8 b;
    ssize_t size;

    size = read (uf->file_descriptor, &b, sizeof (b));
    if (0 == size)
        {
            /* interrupt line was disconnected */
            unix_file_del (&unix_main,
                unix_main.file_pool + mif->interrupt_line.index);
            mif->interrupt_line.index = ~0;
            mif->interrupt_line.fd = -1;
            DEBUG_LOG("disconnect?\n");
        }
    /*TODO: handle interrupt */
    /*if disconnected, call nterrupt?? */
    DEBUG_LOG("interrupt called\n");
    return 0;
}

static clib_error_t *
memif_process_connect_req (memif_pending_conn_t * pending_conn,
                            memif_msg_t * req, struct ucred *slave_cr,
                            int shm_fd, int int_fd)
{
    memif_main_t *mm = &memif_main;
    int fd = pending_conn->connection.fd;
    unix_file_t *uf = 0;
    memif_if_t *mif = 0;
    memif_msg_t resp = { 0 };
    unix_file_t template = { 0 };
    void *shm;
    uword *p;
    u8 retval = 0;
    static clib_error_t *error = 0;

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

    p = mhash_get (&mm->if_index_by_key, &req->key);
    if (!p)
        {
            DEBUG_LOG
            ("Connection request with unmatched key (0x%" PRIx64 ")", req->key);
            retval = 4;
            goto response;
        }

    mif = vec_elt_at_index (mm->interfaces, *p);
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
            error = clib_error_return_unix (0, "mmap fd %d", shm_fd);
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

    mif->log2_ring_size = req->log2_ring_size;
    mif->num_s2m_rings = req->num_s2m_rings;
    mif->num_m2s_rings = req->num_m2s_rings;
    mif->buffer_size = req->buffer_size;
    mif->remote_pid = slave_cr->pid;
    mif->remote_uid = slave_cr->uid;
    vec_add1 (mif->regions, shm);

    /* register interrupt line */
    mif->interrupt_line.fd = int_fd;
    template.read_function = memif_int_fd_read_ready;
    template.file_descriptor = int_fd;
    template.private_data = mif->if_index;
    mif->interrupt_line.index = unix_file_add (&unix_main, &template);

    /* change context for future messages */
    uf = vec_elt_at_index (unix_main.file_pool, pending_conn->connection.index);
    uf->private_data = mif->if_index << 1;
    mif->connection = pending_conn->connection;
    pool_put (mm->pending_conns, pending_conn);
    pending_conn = 0;

    memif_connect (mif);

response:
  resp.version = MEMIF_VERSION;
  resp.type = MEMIF_MSG_TYPE_CONNECT_RESP;
  resp.retval = retval;
  if (send (fd, &resp, sizeof (resp), 0) < 0)
    {
      DEBUG_UNIX_LOG ("Failed to send connection response");
      error = clib_error_return_unix (0, "send fd %d", fd);
      if (pending_conn)
    memif_remove_pending_conn (pending_conn);
      else
    memif_disconnect (mif);
    }
  if (retval > 0)
    {
      if (shm_fd >= 0)
    close (shm_fd);
      if (int_fd >= 0)
    close (int_fd);
    }
  return error;
}

static clib_error_t *
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
        memif_connect (mif);
    else
        memif_disconnect (mif);

    return 0;
}

static clib_error_t *
memif_conn_fd_read_ready (unix_file_t * uf)
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
    static clib_error_t *error = 0;

    iov[0].iov_base = (void *) &msg;
    iov[0].iov_len = sizeof (memif_msg_t);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctl;
    mh.msg_controllen = sizeof (ctl);

    /* grab the appropriate context */
    if (uf->private_data & 1)
        pending_conn = vec_elt_at_index (mm->pending_conns,
                     uf->private_data >> 1);
    else
        mif = vec_elt_at_index (mm->interfaces, uf->private_data >> 1);

    /* receive the incoming message */
    size = recvmsg (uf->file_descriptor, &mh, 0);
    if (size != sizeof (memif_msg_t))
        {
            if (size != 0)
                {
                    DEBUG_UNIX_LOG ("Malformed message received on fd %d",
                        uf->file_descriptor);
                    error = clib_error_return_unix (0, "recvmsg fd %d",
                        uf->file_descriptor);
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

            case MEMIF_MSG_TYPE_DISCONNECT:
                goto disconnect;

            default:
            DEBUG_LOG ("Received unknown message type");
            goto disconnect;
        }
    return 0;

disconnect:
  if (pending_conn)
    memif_remove_pending_conn (pending_conn);
  else
    memif_disconnect (mif);
  return error;
}


static clib_error_t *
memif_conn_fd_accept_ready (unix_file_t * uf)
{
    memif_main_t *mm = &memif_main;
    memif_listener_t *listener = 0;
    memif_pending_conn_t *pending_conn = 0;
    int addr_len;
    struct sockaddr_un client;
    int conn_fd;
    unix_file_t template = { 0 };

    listener = pool_elt_at_index (mm->listeners, uf->private_data);

    addr_len = sizeof (client);
    conn_fd = accept (uf->file_descriptor,
         (struct sockaddr *) &client, (socklen_t *) &addr_len);

    if (conn_fd < 0)
        return clib_error_return_unix (0, "accept fd %d", uf->file_descriptor);

    pool_get (mm->pending_conns, pending_conn);
    pending_conn->index = pending_conn - mm->pending_conns;
    pending_conn->listener_index = listener->index;
    pending_conn->connection.fd = conn_fd;

    template.read_function = memif_conn_fd_read_ready;
    template.file_descriptor = conn_fd;
    template.private_data = (pending_conn->index << 1) | 1;
    pending_conn->connection.index = unix_file_add (&unix_main, &template);

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
    struct epoll_event evt;
    memset (&evt, 0, sizeof(evt));
    evt.events = EPOLLIN;
    int rv = epoll_pwait (epfd, &evt, 1, timeout, NULL);
    if (rv < 0)
    {
        DEBUG_LOG("epoll_pwait error: %s\n", strerror(errno));
        return;
    }
    if (rv > 0)
    {
        unix_file_t *f = (unix_file_t *) evt.data.ptr;
        f->read_function(f);
    }
}

static void
memif_send_conn_req (memif_if_t *mif)
{
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
    unix_file_t template = { 0 };

    msg.version = MEMIF_VERSION;
    msg.type = MEMIF_MSG_TYPE_CONNECT_REQ;
    msg.key = mif->key;
    msg.log2_ring_size = mif->log2_ring_size;
    msg.num_s2m_rings = mif->num_s2m_rings;
    msg.num_m2s_rings = mif->num_m2s_rings;
    msg.buffer_size = mif->buffer_size;

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
            DEBUG_UNIX_LOG ("Failed to map anonymous file into memory");
            goto error;
        }

    vec_add1 (mif->regions, shm);
    ((memif_shm_t *) mif->regions[0])->cookie = 0xdeadbeef;
    for (i = 0; i < mif->num_s2m_rings; i++)
        {
            ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
            ring->head = ring->tail = 0;
            ring->next_alloc = ring->buffer_offset = buffer_offset;
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
            ring->head = ring->tail = 0;
            ring->next_alloc = ring->buffer_offset = buffer_offset + mif->buffer_size;
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
            DEBUG_UNIX_LOG ("Failed to create a pair of connected sockets");
            goto error;
        }

    mif->interrupt_line.fd = fd_array[0];
    template.read_function = memif_int_fd_read_ready;
    template.file_descriptor = mif->interrupt_line.fd;
    template.private_data = mif->if_index;
    mif->interrupt_line.index = unix_file_add (&unix_main, &template);

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
            goto error;
        }

    /* No need to keep the descriptor open,
    * mmap creates an extra reference to the underlying file */
    close (mfd);
    mfd = -1;
    /* This FD is given to peer, so we can close it */
    close (fd_array[1]);
    fd_array[1] = -1;
    return;

error:
  if (mfd > -1)
    close (mfd);
  if (fd_array[1] > -1)
    close (fd_array[1]);
  memif_disconnect (mif);
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
        DEBUG_LOG("socket () FAIL!\nError: %s\n", strerror(errno));
    }
    unix_file_t temp = { 0 };
    if (connect (sockfd, (struct sockaddr *) &sun, sizeof (struct sockaddr_un)) == 0)
        {
            mif->connection.fd = sockfd;
            temp.file_descriptor = sockfd;
            temp.read_function = memif_conn_fd_read_ready;
            temp.private_data = mif->if_index << 1;
            mif->connection.index = unix_file_add (&unix_main, &temp);
        }
    else
        {
            DEBUG_LOG ("connect() FAIL!\nError: %s\n", strerror(errno));
            close(sockfd);
            return;
        }
    memif_send_conn_req (mif);
}

uword
memif_create (memif_create_args_t *args)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif = { 0 };
    uword *p;
    int ret = 0;

    p = mhash_get (&mm->if_index_by_key, &args->key);
    if (p) {
        DEBUG_LOG ("Memif with key 0x%" PRIx64 " already exists.", args->key);
    }

    pool_get (mm->interfaces, mif);
    memset (mif, 0, sizeof (*mif));
    mif->key = args->key;
    mif->if_index = mif - mm->interfaces;
    mif->listener_index = ~0;
    mif->connection.index = mif->interrupt_line.index = ~0;
    mif->connection.fd = mif->interrupt_line.fd = -1;
    mif->flags = 0;

    /* TODO: clib_spinlock_init */

    mif->log2_ring_size = args->log2_ring_size;
    mif->buffer_size = args->buffer_size;

    /* TODO: make configurable */
    mif->num_s2m_rings = 1;
    mif->num_m2s_rings = 1;
    
    mhash_set_mem (&mm->if_index_by_key, &args->key, &mif->if_index, 0);

    if (args->socket_filename != 0)
        mif->socket_filename = args->socket_filename;
    else
        mif->socket_filename = vec_dup (mm->default_socket_filename);

    if (args->is_int)
        mif->flags |= MEMIF_IF_FLAG_INTERRUPT;

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
                        ret = VNET_API_ERROR_SYSCALL_ERROR_2;
                        goto error;
                    }
                /* *INDENT-OFF* */
                pool_foreach (listener, mm->listeners,
                    ({
                        if (listener->sock_dev == file_stat.st_dev &&
                        listener->sock_ino == file_stat.st_ino)
                        {
                            /* attach memif to the existing listener */
                            mif->listener_index = listener->index;
                            ++listener->usage_counter;
                            goto signal;
                        }
                    }));
                /* *INDENT-ON* */
                unlink ((char *) mif->socket_filename);
            }

        pool_get (mm->listeners, listener);
        memset (listener, 0, sizeof (*listener));
        listener->socket.fd = -1;
        listener->socket.index = ~0;
        listener->index = listener - mm->listeners;
        listener->usage_counter = 1;

        if ((listener->socket.fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
            {
                ret = VNET_API_ERROR_SYSCALL_ERROR_3;
                goto error;
            }

        un.sun_family = AF_UNIX;
        strncpy ((char *) un.sun_path, (char *) mif->socket_filename, sizeof (un.sun_path) - 1);

        if (setsockopt (listener->socket.fd, SOL_SOCKET, SO_PASSCRED,
                        &on, sizeof (on)) < 0)
            {
                ret = VNET_API_ERROR_SYSCALL_ERROR_4;
                goto error;
            }
        if (bind (listener->socket.fd, (struct sockaddr *) &un,
                    sizeof (un)) == -1)
            {
                ret = VNET_API_ERROR_SYSCALL_ERROR_5;
                goto error;
            }
        if (listen (listener->socket.fd, 1) == -1)
            {
                ret = VNET_API_ERROR_SYSCALL_ERROR_6;
                goto error;
            }

        if (stat ((char *) mif->socket_filename, &file_stat) == -1)
            {
                ret = VNET_API_ERROR_SYSCALL_ERROR_7;
                goto error;
            }

        listener->sock_dev = file_stat.st_dev;
        listener->sock_ino = file_stat.st_ino;

        unix_file_t template = { 0 };
        template.read_function = memif_conn_fd_accept_ready;
        template.file_descriptor = listener->socket.fd;
        template.private_data = listener->index;
        listener->socket.index = unix_file_add (&unix_main, &template);
        
        mif->listener_index = listener->index;
    }
    else
        {
            mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;
        }

signal:
  if (pool_elts (mm->interfaces) == 1)
    /* TODO: MEMIF_PROCESS_EVENT_START */
  return 0;

error:
  memif_close_if (mm, mif);
  return ret;
}

int
memif_send (uword if_index, memif_ring_type_t type)
{
    memif_if_t *mif = memif_dump(if_index);
    u8 rid = 0;
    memif_ring_t *ring = memif_get_ring (mif, type, rid);
    memif_ring_t *s2m = memif_get_ring (mif, MEMIF_RING_S2M, rid);
    memif_ring_t *m2s = memif_get_ring (mif, MEMIF_RING_M2S, rid);
    u16 ring_size = 1 << mif->log2_ring_size;
    u16 mask = ring_size - 1;
    u16 head, tail;
    u16 free_slots;
    int rv = 0;
    head = ring->head;
    tail = ring->tail;

    if (tail > head)
        free_slots = tail - head;
    else
        free_slots = ring_size - head + tail;
        
    head = (head + mif->head_offset) & mask;
    mif->head_offset = 0;
    /*
    void *b = malloc(1);
    if (send(mif->interrupt_line.fd, b, 1, 0) < 0)
    {
        DEBUG_LOG("Failed to send interrupt!\n");
        rv = -2;
    }
    */
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
    memif_ring_data_t *rd =
        vec_elt_at_index (mif->ring_data, rid + type * mif->num_s2m_rings);
    u16 head;

    memif_main_t *nm = &memif_main;
    u32 *to_next = 0;
    u32 n_free_bufs;
    u32 bi0;
    u16 ring_size = 1 << mif->log2_ring_size;
    u16 mask = ring_size - 1;
    u16 num_slots;
    void *mb0, *mb1;

    head = ring->head;
    if (head == rd->last_head)
        return 0;

    if (head > rd->last_head)
        num_slots = head - rd->last_head;
    else
        num_slots = ring_size - rd->last_head + head;
    int c = 0;
    while (num_slots && iov_arr_len)
    {
        while (num_slots > 5 && iov_arr_len > 2)
        {
            if (PREDICT_TRUE (rd->last_head + 5 < ring_size))
            {
                CLIB_PREFETCH (memif_get_buffer (mif, ring, rd->last_head + 2),
                    CLIB_CACHE_LINE_BYTES, LOAD);
                CLIB_PREFETCH (memif_get_buffer (mif, ring, rd->last_head + 3),
                    CLIB_CACHE_LINE_BYTES, LOAD);
                CLIB_PREFETCH (&ring->desc[rd->last_head + 4],
                    CLIB_CACHE_LINE_BYTES, LOAD);
                CLIB_PREFETCH (&ring->desc[rd->last_head + 5],
                    CLIB_CACHE_LINE_BYTES, LOAD);
            }
            else
            {
                CLIB_PREFETCH (memif_get_buffer
                    (mif, ring, (rd->last_head + 2) % mask),
                    CLIB_CACHE_LINE_BYTES, LOAD);
                CLIB_PREFETCH (memif_get_buffer
                    (mif, ring, (rd->last_head + 3) % mask),
                    CLIB_CACHE_LINE_BYTES, LOAD);
                CLIB_PREFETCH (&ring->desc[(rd->last_head + 4) % mask],
                    CLIB_CACHE_LINE_BYTES, LOAD);
                CLIB_PREFETCH (&ring->desc[(rd->last_head + 5) % mask],
                    CLIB_CACHE_LINE_BYTES, LOAD);
            }
            (*iov + c)->iov_len = ring->desc[rd->last_head].buffer_length;
            (*iov + c)->iov_base = malloc((*iov + c)->iov_len);
            if ((*iov + c)->iov_base == NULL){
                DEBUG_LOG("not enough free system memory malloc fail!\n");
                return c;
            }
            (*iov + c + 1)->iov_len = ring->desc[rd->last_head + 1].buffer_length;
            (*iov + c + 1)->iov_base = malloc((*iov + c + 1)->iov_len);
            if ((*iov + c + 1)->iov_base == NULL){
                DEBUG_LOG("not enough free system memory malloc fail!\n");
                return c;
            }
            void *mb0 = memif_get_buffer (mif, ring, rd->last_head);
            clib_memcpy ((*iov + c)->iov_base, mb0,
                CLIB_CACHE_LINE_BYTES);
            rd->last_head = (rd->last_head + 1) & mask;
            
            void *mb1 = memif_get_buffer (mif, ring, rd->last_head);
            clib_memcpy ((*iov + c + 1)->iov_base, mb1,
                CLIB_CACHE_LINE_BYTES);
            rd->last_head = (rd->last_head + 1) & mask;
            if ((*iov + c)->iov_len > CLIB_CACHE_LINE_BYTES)
                clib_memcpy ((*iov + c)->iov_base + CLIB_CACHE_LINE_BYTES,
                    mb0 + CLIB_CACHE_LINE_BYTES,
                    (*iov + c)->iov_len - CLIB_CACHE_LINE_BYTES);
            
            if ((*iov + c + 1)->iov_len > CLIB_CACHE_LINE_BYTES)
                clib_memcpy ((*iov + c + 1)->iov_base + CLIB_CACHE_LINE_BYTES,
                    mb0 + CLIB_CACHE_LINE_BYTES,
                    (*iov + c + 1)->iov_len - CLIB_CACHE_LINE_BYTES);
            
            num_slots -= 2;
            c += 2;
            iov_arr_len -= 2;
        }
        (*iov + c)->iov_len = ring->desc[rd->last_head].buffer_length;
        (*iov + c)->iov_base = malloc((*iov + c)->iov_len);

        if ((*iov + c)->iov_base == NULL){
            DEBUG_LOG("not enough free system memory malloc fail!\n");
            return c;
        }
        void *mb0 = memif_get_buffer (mif, ring, rd->last_head);
        
        clib_memcpy ((*iov + c)->iov_base, mb0,
               CLIB_CACHE_LINE_BYTES);
        if ((*iov + c)->iov_len > CLIB_CACHE_LINE_BYTES)
            clib_memcpy ((*iov + c)->iov_base + CLIB_CACHE_LINE_BYTES,
                mb0 + CLIB_CACHE_LINE_BYTES,
                (*iov + c)->iov_len - CLIB_CACHE_LINE_BYTES);

        /* next packet */
        rd->last_head = (rd->last_head + 1) & mask;
        num_slots--;
        c++;
        iov_arr_len--;
    }
    ring->tail = head;
    return c;
}

void
memif_loop_run (int timeout)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    int iov_arr_len = 1025, rx = 0, i = 0;
    struct iovec *iov;
    poll_event (timeout);/*if event calls read function assigned to fd on which event occured*/
    pool_foreach (mif, mm->interfaces,
        ({
            if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
                continue;

            if (mif->flags & MEMIF_IF_FLAG_CONNECTING)
                continue;

            if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
                {
                    if ((mif->flags & MEMIF_IF_FLAG_INTERRUPT) == 0)
                    {
                        iov = (struct iovec *)malloc(sizeof(struct iovec) * iov_arr_len);
                        rx = memif_recv (mif->if_index, &iov, iov_arr_len);
                        for (i=0;i<rx;i++)
                        {
                            if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
                            {
                                if (strncmp ("M2S", iov[i].iov_base, 3) == 0)
                                    DEBUG_LOG("OK!\n");
                            }
                            else
                            {
                                if (strncmp ("S2M", iov[i].iov_base, 3) == 0)
                                    DEBUG_LOG("OK!\n");
                            }
                        }
                        free(iov);
                        iov = NULL;
                    }
                    continue;
                }

            if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
                {
                    memif_connect_master (mif);
                }
        }));
    /*handle interrupt mode:*/
}
