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
#include <sys/eventfd.h>

#include "memif_lib.h"
#include "memif_lib_priv.h"
#include "memif_lib_vec.h" 
/*
#define MEMIF_DEBUG 1

#if MEMIF_DEBUG == 1
#define DEBUG_LOG(...) printf("DEBUG_LOG: %s:%d: ", __func__, __LINE__); \
                       printf(__VA_ARGS__);                              \
                       printf("\n")
#define DEBUG_UNIX_LOG(...) printf("DEBUG_UNIX_LOG: %s:%d: ", __func__, __LINE__); \
                            printf(__VA_ARGS__);                                   \
                            printf("\n");
#endif
*/
#define SIZEOF_SIGSET (_NSIG / 8)

memif_main_t memif_main;
int epfd;


/*
 * Helper functions
 */

memif_main_t *
dump_memif_main ()
{
    return &memif_main;
}

memif_if_t *
memif_dump (uint64_t if_index)
{
    memif_main_t *mm = &memif_main;
    return (memif_if_t *) vec_get_at_index (if_index, mm->interfaces);
}

memif_if_t *
get_if_by_key (uint64_t key)
{
    memif_main_t *mm = &memif_main;
    if (mm->interfaces == NULL)
        return NULL;
    memif_if_t *mif;
    long i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
        if (mif->key == key)
            return mif;
    }
    return NULL;
}

/*
 * Memif file functions
 */

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

void
memif_file_del_by_index (uint64_t mf_index)
{
    memif_main_t *mm = &memif_main;
    memif_file_t *mf = (memif_file_t *) vec_get_at_index (mf_index, mm->files);
    memif_file_del (mf);
}

/*
 *
 */

void
memif_bring_up (uint64_t if_index)
{
    memif_if_t *mif = { 0 };
    if ((mif = memif_dump (if_index)) != NULL)
        {
            mif->flags |= MEMIF_IF_FLAG_ADMIN_UP;
            return;
        }
}

void
memif_bring_down (uint64_t if_index)
{
    memif_if_t *mif = { 0 };
    if ((mif = memif_dump (if_index)) != NULL)
        {
            mif->flags = ~MEMIF_IF_FLAG_ADMIN_UP;
            return;
        }
}

static void
memif_queue_intfd_close (memif_queue_t * mq)
{
    if (mq->int_memif_file_index != ~0)
        {
            memif_file_del_by_index (mq->int_memif_file_index);
            DEBUG_LOG ("memif_file del idx %lu", mq->int_memif_file_index);
            mq->int_memif_file_index = ~0;
            mq->int_fd = -1;
        }
    else if (mq->int_fd > -1)
        {
            close (mq->int_fd);
            mq->int_fd = -1;
        }
}

void
memif_disconnect (memif_if_t *mif)
{
    memif_queue_t *mq;
    memif_region_t *mr;
    long i;
    if (mif == NULL)
        return;

    mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
    if (mif->conn_memif_file_index != ~0)
        {
            memif_file_del_by_index (mif->conn_memif_file_index);
            DEBUG_LOG ("memif_file del idx %lu", mif->conn_memif_file_index);
            mif->conn_memif_file_index = ~0;
        }
    else if (mif->conn_fd > -1)
        close (mif->conn_fd);
    mif->conn_fd = -1;

    /* unassign rx thread */
    if (mif->rx_queues != NULL)
    {
        i = -1;
        while ((mq = (memif_queue_t *) vec_get_next (&i, mif->rx_queues)) != NULL)
            memif_queue_intfd_close (mq);
        vec_free (mif->rx_queues);
        mif->rx_queues = NULL;
    }
    if (mif->tx_queues != NULL)
    {
        i = -1;
        while ((mq = (memif_queue_t *) vec_get_next (&i, mif->tx_queues)) != NULL)
            memif_queue_intfd_close (mq);
        vec_free (mif->tx_queues);
        mif->tx_queues = NULL;
    }
    if (mif->regions != NULL)
    {
        i = -1;
        while ((mr = (memif_region_t *) vec_get_next (&i, mif->regions)) != NULL)
        {
            if (munmap (mr->shm, mr->region_size) < 0)
            {
                DEBUG_LOG ("munmaf failed!: %s", strerror(errno));
            }
            if (mr->fd > -1)
                close (mr->fd);
            mr->fd = -1;
        }
        vec_free (mif->regions);
        mif->regions = NULL;
    }

    mif->remote_pid = 0;
    (&memif_main)->on_disconnect (mif);
}

static void *
memif_int_fd_read_ready (memif_file_t * mf)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif = (memif_if_t *) vec_get_at_index (
                                        (mf->data >> 16), mm->interfaces);
    uint64_t b;
    ssize_t size;

    size = read (mf->fd, &b, sizeof (b));
    if (size < 0)
    {
        DEBUG_LOG ("Socket read fail!: %s", strerror (errno));
    }
    else
    {
        mm->on_interrupt (mif);
    }

    return 0;
}

int
memif_connect (memif_if_t * mif)
{
    memif_region_t *mr;
    memif_file_t template = { 0 };
    long i;

    DEBUG_LOG ("connect %lu", mif->dev_instance);

    i = -1;
    while ((mr = (memif_region_t *) vec_get_next (&i, mif->regions)) != NULL)
    {
        if (mr->shm)
            continue;
        if (mr->fd < 0)
        {
            DEBUG_LOG ("no memory region!");
            return -1;
        }

        if ((mr->shm = mmap (NULL, mr->region_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, mr->fd, 0)) == MAP_FAILED)
        {
            DEBUG_LOG ("mmap fail! %s", strerror (errno));
            return -1;
        }
    }

    template.read_function = memif_int_fd_read_ready;

    memif_queue_t *mq;

    i = -1;
    while ((mq = (memif_queue_t *) vec_get_next (&i, mif->tx_queues)) != NULL)
    {
        mq->ring = mif->regions[mq->region].shm + mq->offset;
        if (mq->ring->cookie != MEMIF_COOKIE)
        {
            DEBUG_LOG ("wrong cookie on tx ring %ld", i);
            return -1;
        }
    }

    i = -1;
    while ((mq = (memif_queue_t *) vec_get_next (&i, mif->rx_queues)) != NULL)
    {
        mq->ring = mif->regions[mq->region].shm + mq->offset;
        if (mq->ring->cookie != MEMIF_COOKIE)
        {
            DEBUG_LOG ("wrong cookie on rx ring %ld", i);
            return -1;
        }
        
        if (mq->int_fd > -1)
        {
            template.fd = mq->int_fd;
            template.data = (mif->dev_instance << 16) | (i & 0xFFFF);
            mq->int_memif_file_index = memif_file_add (&template);
            DEBUG_LOG ("memif_file_add fd %d pd %lu idx %lu", 
                        template.fd, template.data, mq->int_memif_file_index);
        }
        /* assign rx thread */
        /* set rx mode */
    }

    /* init mif->run struct on master */
    if ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) == 0)
        mif->run = mif->cfg;
    
    mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
    mif->flags |= MEMIF_IF_FLAG_CONNECTED;

    return 0;
}

static inline memif_ring_t *
memif_get_ring (memif_if_t *mif, memif_ring_type_t type, uint16_t ring_num)
{
    if (vec_get_len (mif->regions) == 0)
        return NULL;
    void *p = mif->regions[0].shm;
    int ring_size =
        sizeof (memif_ring_t) +
        sizeof (memif_desc_t) * (1 << mif->run.log2_ring_size);
    p += (ring_num + type * mif->run.num_s2m_rings) * ring_size;

    return (memif_ring_t *) p;
}

int
memif_init_regions_and_queues (memif_if_t * mif)
{
    uint64_t buffer_offset;
    memif_region_t *r;
    int x, y;
    memif_ring_t *ring;

    mif->regions = (memif_region_t *) vec_init (sizeof (memif_region_t *));
    r = (memif_region_t *) vec_get ((void **) &mif->regions);

    buffer_offset = (mif->run.num_s2m_rings + mif->run.num_m2s_rings) *
        (sizeof (memif_ring_t) +
         sizeof (memif_desc_t) * (1 << mif->run.log2_ring_size));

    r->region_size = buffer_offset +
        mif->run.buffer_size * (mif->run.num_s2m_rings + mif->run.num_m2s_rings);

    if ((r->fd = memfd_create ("memif_region 0", MFD_ALLOW_SEALING)) < 0)
    {
        DEBUG_LOG ("memfd create fail!: %s", strerror (errno));
        return -1;
    }
    if ((fcntl (r->fd, F_ADD_SEALS, F_SEAL_SHRINK)) < 0)
    {
        DEBUG_LOG ("SEAL SHRINK fail! %s", strerror (errno));
        return -1;
    }
    if ((ftruncate (r->fd, r->region_size)) < 0)
    {
        DEBUG_LOG ("Set file size fail! %s", strerror (errno));
        return -1;
    }
    if ((r->shm = mmap (NULL, r->region_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, r->fd, 0)) == MAP_FAILED)
    {
        DEBUG_LOG ("mmap fail! %s", strerror (errno));
        return -1;
    }

    for (x = 0; x < mif->run.num_s2m_rings; x++)
    {
        ring = memif_get_ring (mif, MEMIF_RING_S2M, x);
        ring->head = ring->tail = ring->head_offset = 0;
        ring->cookie = MEMIF_COOKIE;
        ring->buffer_offset = buffer_offset + (x * mif->run.buffer_size);
        for (y = 0; y < (1 << mif->run.log2_ring_size); y++)
        {
            ring->desc[y].region = 0;
            ring->desc[y].offset = buffer_offset + (x * mif->run.buffer_size);
            ring->desc[y].buffer_length = 0;
        }
    }
    for (x = 0; x < mif->run.num_m2s_rings; x++)
    {
        ring = memif_get_ring (mif, MEMIF_RING_M2S, x);
        ring->head = ring->tail = ring->head_offset = 0;
        ring->cookie = MEMIF_COOKIE;
        ring->buffer_offset = buffer_offset + (x * mif->run.buffer_size) +
                (mif->run.num_s2m_rings * mif->run.buffer_size);
        for (y = 0; y < (1 << mif->run.log2_ring_size); y++)
        {
            ring->desc[y].region = 0;
            ring->desc[y].offset = buffer_offset + (x * mif->run.buffer_size) + 
                (mif->run.num_s2m_rings * mif->run.buffer_size);
            ring->desc[y].buffer_length = 0;
        }
    }

    memif_queue_t *mq;
    
    mif->tx_queues = (memif_queue_t *) vec_init (sizeof (memif_queue_t *));
    for (x = 0; x < mif->run.num_s2m_rings; x++)
    {
        mq = (memif_queue_t *) vec_get ((void **) &mif->tx_queues);
        if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
        {
            DEBUG_LOG ("add nonblock event fd fail!: %s", strerror (errno));
            return -1;
        }
        mq->int_memif_file_index = ~0;
        mq->ring = memif_get_ring (mif, MEMIF_RING_S2M, x);
        mq->log2_ring_size = mif->cfg.log2_ring_size;
        mq->region = 0;
        mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
        mq->last_head = 0;
        mq->recv_mode = 0;
    }

    mif->rx_queues = (memif_queue_t *) vec_init (sizeof (memif_queue_t *));
    for (x = 0; x < mif->run.num_m2s_rings; x++)
    {
        mq = (memif_queue_t *) vec_get ((void **) &mif->rx_queues);
        if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
        {
            DEBUG_LOG ("add nonblock event fd fail!: %s", strerror (errno));
            return -1;
        }
        mq->int_memif_file_index = ~0;
        mq->ring = memif_get_ring (mif, MEMIF_RING_M2S, x);
        mq->log2_ring_size = mif->cfg.log2_ring_size;
        mq->region = 0;
        mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
        mq->last_head = 0;
        mq->recv_mode = 0;
    }
    
    return 0;
}

void
memif_set_mode (uint8_t recv_mode)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    mm->recv_mode = recv_mode;
    long i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
        if ((mif->flags & MEMIF_IF_FLAG_CONNECTED) == 0)
            continue;
        memif_msg_send_recv_mode (mif);
    }
}

memif_main_t *
memif_init (uint8_t recv_mode, memif_function_t *on_connect,
                memif_function_t *on_disconnect, memif_function_data_t *on_incoming_data,
                memif_function_t *on_interrupt)
{
    memif_main_t *mm = &memif_main;
    memset (mm, 0, sizeof (memif_main_t));

    mm->interfaces = vec_init (sizeof (memif_if_t));
    mm->files = vec_init (sizeof (memif_file_t));
    mm->int_ifs = vec_init (sizeof (uint16_t));
    mm->socket_files = vec_init (sizeof (memif_socket_file_t));
    /* hash init mm->socket_file_index_by_filename */

    mm->recv_mode = recv_mode;
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

    uint16_t *int_if = (uint16_t *) vec_get ((void **) &mm->int_ifs);
    *int_if = mif->dev_instance;

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

void
memif_connect_master (memif_if_t *mif)
{
    memif_main_t *mm = &memif_main;
    struct sockaddr_un sun;
    sun.sun_family = AF_UNIX;
    memif_socket_file_t *msf = (memif_socket_file_t *) vec_get_at_index (
            mif->socket_file_index, mm->socket_files);
    strncpy (sun.sun_path, (char *) msf->filename,
                sizeof (sun.sun_path) - 1);
    int sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0){
        DEBUG_LOG("socket () FAIL!\nError: %s", strerror(errno));
    }
    memif_file_t temp = { 0 };
    if (connect (sockfd, (struct sockaddr *) &sun, sizeof (struct sockaddr_un)) == 0)
        {
            mif->conn_fd = sockfd;
            temp.fd = mif->conn_fd;
            temp.read_function = memif_slave_conn_fd_read_ready;
            temp.error_function = memif_slave_conn_fd_error;
            temp.data = mif->dev_instance;
            mif->conn_memif_file_index = memif_file_add (&temp);
            DEBUG_LOG ("memif_file_add fd %d pd %lu idx %lu",
                        temp.fd, temp.data, mif->conn_memif_file_index);
            /* msf->dev_instance_by_fd hash */
            vec_set_at_index (&mif->dev_instance, mif->conn_fd,
                                (void **) &msf->dev_instance_by_fd);
            uint64_t *t = (uint64_t *) vec_get_at_index (mif->conn_fd, msf->dev_instance_by_fd);
            DEBUG_LOG ("mif->dev_instance: %lu", mif->dev_instance);
            DEBUG_LOG ("t: %lu", *t);

            mif->flags |= MEMIF_IF_FLAG_CONNECTING;
        }
    else
        {
            /*DEBUG_LOG ("connect() FAIL!\nError: %s\n", strerror(errno));*/
            close(sockfd);
            sockfd = -1;
            return;
        }
}

int
memif_delete (memif_if_t * mif)
{
    memif_main_t *mm = &memif_main;
    memif_socket_file_t *msf = (memif_socket_file_t *) vec_get_at_index (
            mif->socket_file_index, mm->socket_files);
    long i;

    mif->flags |= MEMIF_IF_FLAG_DELETING;

    memif_bring_down (mif->dev_instance);

    memif_disconnect (mif);

    /* unset hash msf->dev_instance_by_key */

    if (--(msf->ref_cnt) == 0)
    {
        DEBUG_LOG ("removing socket file %s", msf->filename);
        if (msf->is_listener)
        {
            uint64_t *x;
            memif_file_del_by_index (msf->memif_file_index);
            DEBUG_LOG ("memif_file_del idx %lu", msf->memif_file_index);
            if (msf->pending_file_indices != NULL)
            {
                i = -1;
                while ((x = (uint64_t *) vec_get_next(&i, msf->pending_file_indices)) != NULL)
                {
                    memif_file_del_by_index (*x);
                    DEBUG_LOG ("memif_file_del idx %lu", *x);
                }
                vec_free (msf->pending_file_indices);
                msf->pending_file_indices = NULL;
            }
        }
        /* hash free dev_instance_by_key */
        /* hash free dev_instance_by_fd */
        /* hash unset mm->socket_file_index_by_filename, msf->filename */
        free (msf->filename); /* TODO: make filename vector */
        msf->filename = NULL;
        vec_free_at_index (msf - mm->socket_files, mm->socket_files);
    }
    memset (mif, 0, sizeof (*mif));
    vec_free_at_index (mif - mm->interfaces, mm->interfaces);

    return 0;
}

uint64_t
memif_create (memif_create_args_t *args)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    int ret = 0;
    memif_socket_file_t *msf = 0;
    char *socket_filename;
    int rv = 0;

    mif = get_if_by_key (args->key);
    if (mif) {
        DEBUG_LOG ("Memif with key 0x%" PRIx64 " already exists.", args->key);
        return ret;
    }


    if (args->socket_filename == 0 || args->socket_filename[0] != '/')
    {
        rv = mkdir (MEMIF_DEFAULT_SOCKET_DIR, 0755);
        if (rv && errno != EEXIST)
        {
            DEBUG_LOG ("createing socket dir fail!: %s", strerror (errno));
            return -1;
        }
        if (args->socket_filename == 0)
        {
            uint16_t sdl = strlen (MEMIF_DEFAULT_SOCKET_DIR);
            uint16_t sfl = strlen (MEMIF_DEFAULT_SOCKET_FILENAME);
            /*socket_filename = (uint8_t *) vec_init (sizeof (uint8_t));*/
            /* TODO: remove malloc & use vector */
            socket_filename = (char *) malloc (sdl + sfl + 1);
            strncpy (socket_filename, MEMIF_DEFAULT_SOCKET_DIR, sdl);
            *(socket_filename + sdl) = '/';
            strncpy ((socket_filename + (sdl + 1)), MEMIF_DEFAULT_SOCKET_FILENAME, sfl);
        }
        else
        {
            uint16_t sdl = strlen (MEMIF_DEFAULT_SOCKET_DIR);
            uint16_t sfl = strlen ((char *) args->socket_filename);
            /*socket_filename = (uint8_t *) vec_init (sizeof (uint8_t));*/
            socket_filename = (char *) malloc (sdl + sfl + 1);
            strncpy (socket_filename, MEMIF_DEFAULT_SOCKET_DIR, sdl);
            *(socket_filename + sdl) = '/';
            strncpy ((socket_filename + (sdl + 1)), (char *) args->socket_filename, sfl);
        }
    }
    else
    {
        socket_filename = (char *) malloc (strlen ((char *) args->socket_filename));
        strncpy (socket_filename,(char *) args->socket_filename,
            strlen ((char *) args->socket_filename));
    }

    /* hash get mm->socket_file_index_by_filename, socket_filename */
/*
    if (p)
    {
        msf = (memif_socket_file_t *) vec_get_at_index (p[0], mm->socket_files);

        if (!msf->is_listener != !args->is_master)
            {
                rv = 1;
                goto done;
            }

*/
        /* hash get msf->dev_instance_by_key, args->key */
        /* if p ? goto done */
/*    }*/

    if (msf == 0)
    {
        struct stat file_stat;
        if (args->is_master && (stat (socket_filename, &file_stat) == 0))
        {
            if (S_ISSOCK (file_stat.st_mode))
                unlink (socket_filename);
            else
            {
                ret = errno;
                goto error;
            }
        }
        msf = (memif_socket_file_t *) vec_get ((void **) &mm->socket_files);
        memset (msf, 0, sizeof (memif_socket_file_t));
        /* hash init msf->dev_instance_by_key */
        msf->dev_instance_by_fd = vec_init (sizeof (uint64_t));
        /* hash create msf->dev_instance_by_fd */
        msf->filename = (uint8_t *) socket_filename;
        msf->fd = -1;
        msf->is_listener = (args->is_master != 0);
        msf->pending_file_indices = vec_init (sizeof (uint64_t));
        socket_filename = 0; /* ??? */
        /* hash set mm->socket_file_index_by_filename */
    }

    mif = (memif_if_t *) vec_get ((void **) &mm->interfaces);
    memset (mif, 0, sizeof (*mif));
    mif->key = args->key;
    rv = mif->dev_instance = mif - mm->interfaces;
    mif->socket_file_index = msf - mm->socket_files;
    mif->conn_memif_file_index = ~0;
    mif->conn_fd = -1;
    mif->flags = 0;

    mif->cfg.log2_ring_size = args->log2_ring_size;
    mif->cfg.buffer_size = args->buffer_size;
    mif->cfg.num_s2m_rings = args->is_master ? args->rx_queues : args->tx_queues;
    mif->cfg.num_m2s_rings = args->is_master ? args->tx_queues : args->rx_queues;
    mif->rx_queues = NULL;
    mif->tx_queues = NULL;

    if (msf->is_listener && msf->ref_cnt == 0)
    {
        struct sockaddr_un un = { 0 };
        struct stat file_stat;
        int on = 1;

        if ((msf->fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
        {
            ret = errno;
            goto error;
        }
        un.sun_family = AF_UNIX;
        strncpy ((char *) un.sun_path, (char *) msf->filename, sizeof (un.sun_path) - 1);

        if (setsockopt (msf->fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof (on)) < 0)
        {
            ret = errno;
            goto error;
        }
        if (bind (msf->fd, (struct sockaddr *) &un, sizeof (un)) == -1)
        {
            ret = errno;
            goto error;
        }
        if (listen (msf->fd, 1) == -1)
        {
            ret = errno;
            goto error;
        }
        if (stat ((char *) msf->filename, &file_stat) == -1)
        {
            ret = errno;
            goto error;
        }
        
        memif_file_t template = { 0 };
        template.read_function = memif_conn_fd_accept_ready;
        template.fd = msf->fd;
        template.data = mif->socket_file_index;
        msf->memif_file_index = memif_file_add (&template);
        DEBUG_LOG ("memif_file_add fd %d pf %lu idx %lu", template.fd,
                    template.data, msf->memif_file_index);
    }
    
    msf->ref_cnt++;

    if (args->is_master == 0)
        mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;

    /* hash set msf->dev_instance_by_key mif->dev_instance */

    goto done;

error:
    DEBUG_LOG ("memif_create ERROR: %s", strerror (ret));
    memif_delete (mif);
    return -1;

done:
    free (socket_filename); /* ??? */
    return rv;
}

/*
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
*/

int
memif_send (uint64_t if_index)
{
    memif_if_t *mif = memif_dump(if_index);
    uint8_t qid = 0;
    memif_queue_t *mq = vec_get_at_index (qid, mif->tx_queues);
    memif_ring_t *ring = mq->ring;
    uint16_t ring_size = 1 << mq->log2_ring_size;
    uint16_t mask = ring_size - 1;
    uint16_t head;
    int rv;

    head = ring->head;

    head = (head + ring->head_offset) & mask;
    rv = ring->head_offset;
    ring->head_offset = 0;

    if (mq->recv_mode == MEMIF_MM_RECV_MODE_INT)
    {
        uint64_t b = 1;
        write (mq->int_fd, &b, sizeof (b));
    }

/*
    if (mif->flags & MEMIF_IF_FLAG_PEER_INT)
    {
        u8 b = rid;
        int res = write (mif->interrupt_line.fd, &b, sizeof (b));
        if (res < 0)
        {
            if (errno == EWOULDBLOCK)
        {
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
*/
    ring->head = head;

    return rv;
}

int
memif_recv (uint64_t if_index, struct iovec **iov, uint32_t iov_arr_len)
{
    memif_if_t *mif = memif_dump(if_index);
    uint8_t qid = 0;
    memif_queue_t *mq = (memif_queue_t *) vec_get_at_index (qid, mif->rx_queues);
    memif_ring_t *ring = mq->ring;
    uint16_t head;
    uint16_t ring_size = (1 << mq->log2_ring_size);
    uint16_t mask = ring_size - 1;
    uint16_t num_slots;
    uint32_t rx = 0;


    head = ring->head;
    if (head == mq->last_head)
        return 0;

    if (head > mq->last_head)
        num_slots = head - mq->last_head;
    else
        num_slots = ring_size - mq->last_head + head;

    while (num_slots && iov_arr_len)
    {
        while (num_slots > 2 && iov_arr_len > 2)
        {
            (*iov + rx)->iov_base = memif_get_buffer (mif, ring, mq->last_head);
            (*iov + rx)->iov_len = ring->desc[mq->last_head].buffer_length;
            mq->last_head = (mq->last_head + 1) & mask;
            
            (*iov + rx + 1)->iov_base = memif_get_buffer (mif, ring, mq->last_head);
            (*iov + rx + 1)->iov_len = ring->desc[(mq->last_head + 1) & mask].buffer_length;
            mq->last_head = (mq->last_head + 1) & mask;
            
            num_slots -= 2;
            rx += 2;
            iov_arr_len -= 2;
        }
        
        (*iov + rx)->iov_base = memif_get_buffer (mif, ring, mq->last_head);
        (*iov + rx)->iov_len = ring->desc[mq->last_head].buffer_length;
        mq->last_head = (mq->last_head + 1) & mask;
        
        num_slots--;
        rx++;
        iov_arr_len--;
    }


    (&memif_main)->on_incoming_data (mif, iov, rx);
    ring->tail = head;
    return rx;
}

/*
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
*/

int
memif_loop_run (int timeout)
{
    memif_main_t *mm = &memif_main;
    memif_if_t *mif;
    int iov_arr_len = 1024, rx = 0, ret = 0;
    struct iovec *iov;
    poll_event (timeout);/*if event: calls read function assigned to fd on which event occured*/
    long i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
            if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
                continue;

            if (mif->flags & MEMIF_IF_FLAG_CONNECTING)
                continue;

            if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
                {
                    if (mm->recv_mode == MEMIF_MM_RECV_MODE_POLL)
                    {
                        do 
                        {
                            iov = (struct iovec *)malloc(sizeof(struct iovec) * iov_arr_len);
                            rx += ret = memif_recv (mif->dev_instance, &iov, iov_arr_len);
                            free(iov);
                            iov = NULL;
                        } while (ret != 0);
                        /*memif_update_ring (mif);*/
                    }
                    continue;
                }

            if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
                {
                    memif_connect_master (mif);
                }
    }
    if (mm->recv_mode == MEMIF_MM_RECV_MODE_INT)
    {
        i = -1;
        uint16_t *int_if;
        while ((int_if =
                (uint16_t *) vec_get_next (&i, mm->int_ifs)) != NULL)
        {
            do
            {
                iov = (struct iovec *)malloc(sizeof(struct iovec) * iov_arr_len);
                rx += ret = memif_recv (*int_if, &iov, iov_arr_len);
                free(iov);
                iov = NULL;
            } while (ret != 0);
            mif = memif_dump (*int_if);
            vec_free_at_index (i, mm->int_ifs);
            /*memif_update_ring (mif);*/
        i++;
        }
    }
    return rx;
}
