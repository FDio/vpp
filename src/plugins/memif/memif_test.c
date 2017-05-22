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
#include <netdb.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "memif_lib.h"

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define DEFAULT "\x1b[0m"

/* test flags definitions */
#define TEST_IS_INIT (1 << 0)

int
kbhit ()
{
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO (&fds);
    FD_SET (STDIN_FILENO, &fds);
    select (STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    return FD_ISSET (STDIN_FILENO, &fds);
}

u16 in_cksum (u16 *addr, int len)
{
    register int sum = 0;
    u16 answer = 0;
    register u16 *w = addr;
    register int nleft = len;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(u8 *) (&answer) = *(u8 *) w;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void
create_icmp_packet (char *packet, u8 type)
{
    if (packet == NULL)
        return;
    u64 pck_size = (sizeof(struct iphdr) + sizeof(struct icmphdr));
    struct iphdr *ip;
    struct icmphdr *icmp;
    ip = (struct iphdr *) packet;
    icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = pck_size;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr("ran.dom.bul.shi");
    ip->daddr = inet_addr("ran.dom.bul.shi");
    ip->check = in_cksum ((unsigned short *)ip, sizeof(struct iphdr));
    icmp->type = type;
    icmp->checksum = in_cksum ((unsigned short *)icmp, sizeof(struct icmphdr));
}

void *
memif_test_on_connect (memif_if_t *mif)
{
    if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
        printf ("memif connected\n");
    else
        printf ("callback error (on_connect)\n");
    return NULL;
}

void *
memif_test_on_disconnect (memif_if_t *mif)
{
    if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
        printf ("callback error (on_disconnect)\n");
    else
        printf ("memif disconnected\n");
    return NULL;
}

void *
memif_test_on_incoming_data (memif_if_t *mif, struct iovec **iov, u32 rx)
{
    u32 count = 0;
    u32 e_rx = 0, r_rx = 0;
    while (rx)
      {
        char *packet = (*iov + count)->iov_base;
        struct iphdr *ip = (struct iphdr *) packet;
        struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
        if ((ip->version == 4) && (icmp->type == ICMP_ECHO))
            e_rx++;
        else if ((ip->version == 4) && (icmp->type == ICMP_ECHOREPLY))
            r_rx++;
        count++;
        rx--;
      }
    u32 i;
    memif_ring_type_t type;
    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        type = MEMIF_RING_S2M;
    else
        type = MEMIF_RING_M2S;
    memif_ring_t *ring = memif_get_ring (mif, type, 0);
    for (i = 0; i < e_rx; i++)
    {
        create_icmp_packet ((char *) memif_alloc_buffer (mif,  ring,
                                sizeof (struct iphdr) + sizeof (struct icmphdr)),
                                ICMP_ECHOREPLY);
    }
    memif_send (mif->if_index);
    printf ("total packets:\t\t%d\n", count);
    printf ("echo replies received:\t%d\n", r_rx);
    printf ("echo requests received:\t%d\n", e_rx);
    return NULL;
}

void
memif_test_init (char *tok, u32 *flags)
{
    if (*flags & TEST_IS_INIT)
    {
        printf("memif already initialized\n");
        return;
    }
    u16 mm_flags = 0;
    tok = strtok (NULL, " ");
    if (tok != NULL)
    {
        if (strncmp (tok, "mode", 4) == 0)
        {
            tok = strtok (NULL, " ");
            if (tok != NULL)
          {
            if (strncmp (tok, "polling", 7) == 0)
                mm_flags &= ~MEMIF_MM_FLAG_IS_INT;
            else if (strncmp (tok, "interrupt", 10) == 0)
                mm_flags |= MEMIF_MM_FLAG_IS_INT;
            else
            {
                printf("expected mode <polling|interrupt>\n");
                return;
            }
          }
          else
            {
              printf("expected mode <polling|interrupt>\n");
              return;
            }
        }
    }
    memif_init (mm_flags, memif_test_on_connect,
                    memif_test_on_disconnect, memif_test_on_incoming_data, memif_on_interrupt);
    epoll_init ();
    *flags |= TEST_IS_INIT;
}

void
memif_test_show (char *tok)
{
    memif_main_t *mm = dump_memif_main ();
    memif_if_t *mif;
    if (mm->flags & MEMIF_MM_FLAG_IS_INT)
        printf("interrupt mode\n");
    else
        printf("polling mode\n");
    int i = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
            printf ("index: %d\n", mif->if_index);
            printf ("role: ");
            if (mm->interfaces[i].flags & MEMIF_IF_FLAG_IS_SLAVE)
                printf("slave\n");
            else
                printf("master\n");
            printf ("key: 0x%ld\n", mif->key);
            printf ("state: ");
            if (mm->interfaces[i].flags & MEMIF_IF_FLAG_ADMIN_UP)
                printf("interface is up\n");
            else
                printf("interface is down\n");
            printf ("link: ");
            if (mm->interfaces[i].flags & MEMIF_IF_FLAG_CONNECTED)
                printf("connected\n");
            else
                printf("disconnected\n");
            printf ("peer mode: ");
            if (mm->interfaces[i].flags & MEMIF_IF_FLAG_PEER_INT)
                printf("interrupt\n");
            else
                printf("polling\n");
            printf ("socket: %s\n", mif->socket_filename);
    }
}

void
memif_test_set_mode (char *tok)
{
    tok = strtok(NULL, " ");
    if (tok == NULL)
    {
        printf ("expected mode <polling|interrupt>\n");
        return;
    }
    if (strncmp(tok, "polling", 7) == 0)
        memif_set_mode (0);
    else if (strncmp (tok, "interrupt", 10) == 0)
        memif_set_mode (MEMIF_MM_FLAG_IS_INT);
    else
    {
        printf ("expected mode <polling|interrupt>\n");
        return;
    }
}

uword
memif_test_create_if (char *tok)
{
    memif_create_args_t args;
    args.key = 1;
    args.socket_filename = 0;
    args.log2_ring_size = 10;
    args.buffer_size = 1024*2048;
    args.is_master = 1;

    char *end;
    u64 ret;

    while ((tok = strtok (NULL, " ")) != NULL)
    {
        if (strncmp (tok, "slave", 5) == 0)
        {
            args.is_master = 0;
        }
        else if (strncmp (tok, "master", 6) == 0)
        {
            args.is_master = 1;
        }
        else if (strncmp (tok, "key", 3) == 0)
        {
            tok = strtok (NULL, " ");
            ret = strtol (tok, &end, 10);
            args.key = ret;
        }
        else if (strncmp (tok, "socket", 6) == 0)
        {
            tok = strtok (NULL, " ");
            char *tmp = (char *) malloc (strlen(tok));
            memcpy (tmp, tok, strlen(tok));
            args.socket_filename = (u8 *) tmp;
        }
        else if (strncmp (tok, "ring", 4) == 0)
        {
            tok = strtok (NULL, " ");
            ret = strtol (tok, &end, 10);
            args.log2_ring_size = ret;
        }
        else if (strncmp (tok, "buffer", 6) == 0)
        {
            tok = strtok (NULL, " ");
            ret = strtol (tok, &end, 10);
            args.buffer_size = ret;
        }
    }
    return memif_create (&args);
}

void
memif_test_delete_if (char *tok)
{
    char *end;
    u64 ret;
    tok = strtok (NULL, " ");
    if (tok != NULL)
    {
        ret = strtol (tok, &end, 10);
        memif_delete (ret);
    }
    else
        printf ("expected index\n");
}

void
memif_test_admin (char *tok)
{
    char *end;
    u64 ret;
    tok = strtok (NULL, " ");
    if (tok != NULL)
    {
        if (strncmp(tok, "up", 2) == 0)
        {
            tok = strtok (NULL, " ");
            if (tok != NULL)
            {
                ret = strtol (tok, &end, 10);
                memif_bring_up (ret);
            }
            else
                printf ("expected index\n");
        }
        else if (strncmp(tok, "down", 4) == 0)
        {
            tok = strtok (NULL, " ");
            if (tok != NULL)
            {
                ret = strtol (tok, &end, 10);
                memif_bring_down (ret);
            }
            else
                printf ("expected index\n");
        }
        else
        {
            printf("expected state <up|down>\n");
            return;
        }
    }
}

void
memif_test_ping (char *tok)
{
    char *end;
    u64 ret;
    uword if_index;
    tok = strtok (NULL, " ");
    if (tok != NULL)
    {
        ret = strtol (tok, &end, 10);
        if_index = ret;
    }
    else
    {
        printf ("expected index\n");
        return;
    }
    memif_ring_type_t type;
    memif_ring_t *ring;
    memif_if_t *mif = memif_dump (if_index);
    if (mif == NULL)
    {
        printf ("memif with index %d does not exist\n", if_index);
        return;
    }
    u32 tx = 0;
    if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
        type = MEMIF_RING_S2M;
    else
        type = MEMIF_RING_M2S;

    ring = memif_get_ring (mif, type, 0);
    

    tok = strtok(NULL, " ");
    if (tok != NULL)
    {
        char *end;
        u64 ret, i;
        ret = strtol (tok, &end, 10);
        for (i = 0; i < ret; i++)
        {
            create_icmp_packet ((char *) memif_alloc_buffer (mif,  ring,
                                    sizeof (struct iphdr) + sizeof (struct icmphdr)), ICMP_ECHO);
        }
    }
    else
        create_icmp_packet ((char *) memif_alloc_buffer (mif,  ring,
                                sizeof (struct iphdr) + sizeof (struct icmphdr)), ICMP_ECHO);

    tx = memif_send (if_index);
    printf ("packets sent: %d\n", tx);
}

int
main (void)
{
    char usr_input[MAX_INPUT];
    char *token;
    u32 flags = 0;

    while (1)
    {
        if (kbhit ())
        {
          fgets(usr_input, MAX_INPUT, stdin);
          if (usr_input[0] == '\n')
            continue;
          usr_input[strlen(usr_input) - 1] = '\0';
          token = strtok(usr_input, " ");
          if (strncmp(token, "exit", 4) == 0)
            return 0;
          if (strncmp(token, "init", 4) == 0)
            memif_test_init (token, &flags);
          else if (strncmp(token, "show", 4) == 0)
            memif_test_show (token);
          else if (strncmp(token, "mode", 4) == 0)
            memif_test_set_mode (token);
          else if (strncmp(token, "create", 6) == 0)
            memif_test_create_if (token);
          else if (strncmp(token, "delete", 6) == 0)
            memif_test_delete_if (token);
          else if (strncmp(token, "admin", 5) == 0)
            memif_test_admin (token);
          else if (strncmp(token, "ping", 4) == 0)
            memif_test_ping (token);
        }
        if (flags & TEST_IS_INIT)
            memif_loop_run(0);
    }
    return 0;
}
