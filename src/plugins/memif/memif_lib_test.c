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
#include "memif_lib_vec.h"
#include "memif_lib_priv.h"

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

uint16_t in_cksum (uint16_t *addr, int len)
{
    register int sum = 0;
    uint16_t answer = 0;
    register uint16_t *w = addr;
    register int nleft = len;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(uint8_t *) (&answer) = *(uint8_t *) w;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void
create_icmp_packet (char *packet, uint8_t type)
{
    if (packet == NULL)
        return;
    uint64_t pck_size = (sizeof(struct iphdr) + sizeof(struct icmphdr));
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
memif_test_on_incoming_data (memif_if_t *mif, struct iovec **iov, uint32_t rx)
{
    uint32_t count = 0;
    uint32_t e_rx = 0, r_rx = 0;
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
    uint32_t i;
    for (i = 0; i < e_rx; i++)
    {
        create_icmp_packet ((char *) memif_alloc_buffer (mif,
                                sizeof (struct iphdr) + sizeof (struct icmphdr)),
                                ICMP_ECHOREPLY);
    }
    memif_send (mif->dev_instance);
    printf ("total packets:\t\t%d\n", count);
    printf ("echo replies received:\t%d\n", r_rx);
    printf ("echo requests received:\t%d\n", e_rx);
    return NULL;
}

void
memif_test_init (char *tok, uint32_t *flags)
{
    if (*flags & TEST_IS_INIT)
    {
        printf("memif already initialized\n");
        return;
    }
    uint8_t recv_mode = 0;
    tok = strtok (NULL, " ");
    if (tok != NULL)
    {
        if (strncmp (tok, "mode", 4) == 0)
        {
            tok = strtok (NULL, " ");
            if (tok != NULL)
          {
            if (strncmp (tok, "polling", 7) == 0)
                recv_mode = MEMIF_MM_RECV_MODE_POLL;
            else if (strncmp (tok, "interrupt", 10) == 0)
                recv_mode = MEMIF_MM_RECV_MODE_INT;
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
    memif_init (recv_mode, memif_test_on_connect,
                    memif_test_on_disconnect, memif_test_on_incoming_data, memif_on_interrupt);
    epoll_init ();
    *flags |= TEST_IS_INIT;
}

void
memif_test_show (char *tok)
{
    memif_main_t *mm = dump_memif_main ();
    memif_if_t *mif;
    memif_queue_t *mq;
    if (mm->recv_mode == MEMIF_MM_RECV_MODE_INT)
        printf("interrupt mode\n");
    else
        printf("polling mode\n");
    long i = -1, e = -1;
    while ((mif = (memif_if_t *) vec_get_next (&i, mm->interfaces)) != NULL)
    {
            printf ("index: %lu\n", mif->dev_instance);
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
            while ((mq = (memif_queue_t *) vec_get_next (&e, mif->tx_queues)) != NULL)
            {
                printf ("queue idx %lu receive mode: ", e);
                if (mq->recv_mode == MEMIF_MM_RECV_MODE_INT)
                    printf("interrupt\n");
                else
                    printf("polling\n");
            }
            /*printf ("socket: %s\n", mif->socket_filename);*/
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
        memif_set_mode (MEMIF_MM_RECV_MODE_POLL);
    else if (strncmp (tok, "interrupt", 10) == 0)
        memif_set_mode (MEMIF_MM_RECV_MODE_INT);
    else
    {
        printf ("expected mode <polling|interrupt>\n");
        return;
    }
}

uint64_t
memif_test_create_if (char *tok)
{
    memif_create_args_t args;
    args.key = 1;
    args.socket_filename = 0;
    args.log2_ring_size = 10;
    args.buffer_size = 1024*2048;
    args.is_master = 1;
    args.rx_queues = 1;
    args.tx_queues = 1;

    char *end;
    uint64_t ret;

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
            args.socket_filename = (uint8_t *) tmp;
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
    uint64_t ret;
    tok = strtok (NULL, " ");
    if (tok != NULL)
    {
        ret = strtol (tok, &end, 10);
        memif_delete (memif_dump (ret));
    }
    else
        printf ("expected index\n");
}

void
memif_test_admin (char *tok)
{
    char *end;
    uint64_t ret;
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
    uint64_t ret;
    uint64_t if_index;
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
    memif_if_t *mif = memif_dump (if_index);
    if (mif == NULL)
    {
        printf ("memif with index %lu does not exist\n", if_index);
        return;
    }
    uint32_t tx = 0;

    tok = strtok(NULL, " ");
    if (tok != NULL)
    {
        char *end;
        uint64_t ret, i;
        ret = strtol (tok, &end, 10);
        for (i = 0; i < ret; i++)
        {
            create_icmp_packet ((char *) memif_alloc_buffer (mif,
                                    sizeof (struct iphdr) + sizeof (struct icmphdr)), ICMP_ECHO);
        }
    }
    else
        create_icmp_packet ((char *) memif_alloc_buffer (mif,
                                sizeof (struct iphdr) + sizeof (struct icmphdr)), ICMP_ECHO);

    tx = memif_send (if_index);
    printf ("packets sent: %d\n", tx);
}

int
main (void)
{
    char usr_input[MAX_INPUT];
    char *token;
    uint32_t flags = 0;

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
