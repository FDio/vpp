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
#include <string.h>
#include <stdio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include "memif_lib.h"

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define DEFAULT "\x1b[0m"

void
print_shm (uword if_index)
{
    memif_if_t *mif = memif_dump (if_index);
    printf("shm: %p\n", mif->regions);
    u8 rid = 0;
    memif_ring_t *ring = memif_get_ring (mif, MEMIF_RING_S2M, rid);
    printf("S2M ring:\nHead:\t%d\nTail:\t%d\n", ring->head, ring->tail);
    ring = memif_get_ring (mif, MEMIF_RING_M2S, rid);
    printf("M2S ring:\nHead:\t%d\nTail:\t%d\n", ring->head, ring->tail);
}
/*
void
test_send_recv (memif_if_t *mif, memif_ring_t *ring,
                     memif_ring_type_t type, u64 alloc_size, u64 alloc_num, char *test_info)
{
    struct iovec *iov;
    int rv;
    int i, f = 0, g = 0;
    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    {
        for (i=0;i<alloc_num;i++)
        {
            (char *)memif_alloc_buffer (mif, ring, alloc_size);
        } 
        memif_send (mif->if_index, type);
    }
    poll_event (-1);
    iov = (struct iovec *)malloc(alloc_num * sizeof(struct iovec));
    memif_recv (mif->if_index, &iov);
    for (i=0;i<alloc_num;i++)
    {
        if ((iov + i)->iov_len != alloc_size)
            f++;
        else
            g++;
    }
    if (test_info)
        printf("Test info: %s\n", test_info);
    printf("alloc size:\t%ld\nalloc num:\t%ld\nmemif buffer size:\t%ld\nalloc total:\t\t%ld\n",
         alloc_size, alloc_num, mif->buffer_size*2, alloc_size*alloc_num);
    printf(GREEN "number of good recv: %d\n" DEFAULT, g);
    printf(RED "number of failed recv: %d\n" DEFAULT, f);

    if ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) == 0)
    {
        for (i=0;i<alloc_num;i++)
        {
            memif_alloc_buffer (mif, ring, alloc_size);
        } 
        memif_send (mif->if_index, type);
    }
}
*/
int
main (void)
{
    if (memif_init() < 0)
        printf(RED "memif_init FAIL!\n" DEFAULT);
    else
        printf(GREEN "memif_init OK!\n" DEFAULT);
    
    memif_set_file_update ();
    epoll_init ();

    memif_if_t *mif;
    memif_create_args_t args;

    args.key = 1;
    args.socket_filename = 0;
    args.log2_ring_size = 10;
    args.buffer_size = 2048*1024;
    args.is_master = 1;
    args.is_int = 0;

    printf ("is_master: 1 = MASTER | 0 = SLAVE\n");
    int in;
    scanf("%d", &in);
    if (in)
        args.is_master = 1;
    else
        args.is_master = 0;

    uword if_index;
    if (if_index = memif_create (&args) < 0)
        printf(RED "memif_create FAIL!\n" DEFAULT);
    else
        printf(GREEN "memif_create OK!\n" DEFAULT);

    mif = memif_dump (if_index);
    if (mif == NULL)
        printf(RED "memif dump FAIL!\n" DEFAULT);
    else
        printf(GREEN "memif dump OK!\n" DEFAULT);

    if (mif->flags & MEMIF_IF_FLAG_INTERRUPT)
        printf("Interrupt\n");
    else
        printf("Poll\n");

    memif_bring_up (if_index);
    if (mif->flags & MEMIF_IF_FLAG_ADMIN_UP)
        printf(GREEN "memif bring up OK!\n" DEFAULT);
    else
        printf(RED "memif bring up FAIL!\n" DEFAULT);

    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        printf("SLAVE\n");
    else
        printf("MASTER\n");

    while (1)
    {
        memif_loop_run (1);
        if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
            break;
    }
    printf("memif connect OK!\n");

    char *usr_msg;
    memif_ring_type_t type;
    int k = 0;
    while (k++ < 10)
    {
        memif_loop_run (1);
        if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
            type = MEMIF_RING_S2M;
        else
            type = MEMIF_RING_M2S;
        memif_ring_t *ring = memif_get_ring(mif, type, 0);
        
        int msg_num = 10;
        u64 msg_size;
        u64 full_msg_size = 0;
        int i,e;
        for (i=0;i<msg_num;i++)
        {
            msg_size = rand () % 4096 + 1024;
            usr_msg = (char *)memif_alloc_buffer (mif, ring, msg_size);
            if (usr_msg == NULL)
            {
                printf("not enough free memory!\nmsg_size = %ld\nbuffer_size %ld\n",
                    msg_size, mif->buffer_size);
                continue;
            }
            else
            {
                for (e=0;e<msg_size;e++)
                {
                    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
                        strncpy (usr_msg, "S2M", 3);
                    else
                        strncpy (usr_msg, "M2S", 3);
                }
            }
        }
        memif_send (if_index, type);
    }

    memif_bring_down (if_index);
    mif = memif_dump (if_index);
    if (mif->flags & ~MEMIF_IF_FLAG_ADMIN_UP)
        printf(GREEN "memif bring down OK!\n" DEFAULT);
    else
        printf(RED "memif bring down FAIL!\n" DEFAULT);

    memif_delete (if_index);
    mif = memif_dump (if_index);
    if (mif == NULL)
        printf(GREEN "memif delete OK!\n" DEFAULT);
    else
        printf(RED "memif delete FAIL!\n" DEFAULT);

    return 0;
}
