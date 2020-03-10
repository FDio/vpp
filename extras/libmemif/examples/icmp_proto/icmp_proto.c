/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

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
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <asm/byteorder.h>
#include <byteswap.h>
#include <assert.h>

#include <icmp_proto.h>


#define GET_HEADER(out,hdr,src,off) do {	\
					out = (hdr*)(src + off); \
					off += sizeof (hdr); \
				} while (0)

#define SIZE_MAC_DICT 5

static struct timespec start;

static struct _arp_table
{
  uint8_t mac[SIZE_MAC_DICT][6];
  uint8_t ip[SIZE_MAC_DICT][4];
  uint8_t cnt_items;
  uint8_t pos_new_items;
}
arp_table =
{
0};

static uint16_t
cksum (void *addr, ssize_t len)
{
  char *data = (char *) addr;

  uint32_t acc = 0xffff;

  ssize_t i;
  for (i = 0; (i + 1) < len; i += 2)
    {
      uint16_t word;
      memcpy (&word, data + i, 2);
      acc += ntohs (word);
      if (acc > 0xffff)
	acc -= 0xffff;
    }

  if (len & 1)
    {
      uint16_t word = 0;
      memcpy (&word, data + len - 1, 1);
      acc += ntohs (word);
      if (acc > 0xffff)
	acc -= 0xffff;
    }
  return htons (~acc);
}

int
print_packet (void *pck)
{
  if (pck == NULL)
    {
      printf ("ICMP_PROTO: no data\n");
      return -1;
    }
  struct iphdr *ip;
  struct icmphdr *icmp;
  ip = (struct iphdr *) pck;
  icmp = (struct icmphdr *) (pck + sizeof (struct iphdr));
  printf ("received packet:\n");
  printf ("\tiphdr:\n");
  printf ("\t\tihl: %u\n\t\tversion: %u\n\t\tlen: %u\n\t\tid: %u\n",
	  ip->ihl, ip->version, __bswap_16 (ip->tot_len), ip->id);
  printf ("\t\tprotocol: %u\n", ip->protocol);

  printf ("\t\tsaddr: ");
  int i;
  for (i = 0; i < 4; i++)
    {
      printf ("%u.", ((uint8_t *) & ip->saddr)[i]);
    }
  printf ("\n");

  printf ("\t\tdaddr: ");
  for (i = 0; i < 4; i++)
    {
      printf ("%u.", ((uint8_t *) & ip->daddr)[i]);
    }
  printf ("\n");
  printf ("\ticmphdr:\n");
  printf ("\t\ttype: %s\n",
	  (icmp->type == ICMP_ECHO) ? "ICMP_ECHO" : "ICMP_ECHOREPLY");

  return 0;
}

static ssize_t
resolve_arp (void *arp)
{
  struct arphdr *resp = (struct arphdr *) arp;

  resp->ar_hrd = __bswap_16 (ARPHRD_ETHER);

  resp->ar_pro = __bswap_16 (0x0800);

  resp->ar_hln = 6;
  resp->ar_pln = 4;

  resp->ar_op = __bswap_16 (ARPOP_REPLY);

  return sizeof (struct arphdr);
}

static ssize_t
resolve_eth_arp (struct ether_arp *eth_arp, void *eth_arp_resp,
		 uint8_t ip_addr[4])
{
  struct ether_arp *resp = (struct ether_arp *) eth_arp_resp;

  resolve_arp (&resp->ea_hdr);

  memcpy (resp->arp_tha, eth_arp->arp_sha, 6);
  memcpy (resp->arp_tpa, eth_arp->arp_spa, 4);

  memcpy (resp->arp_sha,
	  (((struct ether_header *) (eth_arp_resp -
				     sizeof (struct
					     ether_header)))->ether_shost),
	  6);

  memcpy (resp->arp_spa, ip_addr, 4);

  return sizeof (struct ether_arp);
}

static ssize_t
resolve_eth (struct ether_header *eth, void *eth_resp)
{
  struct ether_header *resp = (struct ether_header *) eth_resp;
  memcpy (resp->ether_dhost, eth->ether_shost, 6);

  uint8_t hw_addr[6];
  int i;
  for (i = 0; i < 6; i++)
    {
      hw_addr[i] = 'a';
    }
  memcpy (resp->ether_shost, hw_addr, 6);

  resp->ether_type = eth->ether_type;

  return sizeof (struct ether_header);
}

static ssize_t
resolve_ip (struct iphdr *ip, void *ip_resp, uint8_t ip_addr[4])
{
  struct iphdr *resp = (struct iphdr *) ip_resp;
  resp->ihl = 5;
  resp->version = 4;
  resp->tos = 0;
  /*len updated later */
  resp->tot_len = 0x0000;
  resp->id = 0;
  resp->frag_off = 0;
  resp->ttl = 0x40;
  resp->protocol = 1;
  ((uint8_t *) & resp->saddr)[0] = ip_addr[0];
  ((uint8_t *) & resp->saddr)[1] = ip_addr[1];
  ((uint8_t *) & resp->saddr)[2] = ip_addr[2];
  ((uint8_t *) & resp->saddr)[3] = ip_addr[3];
  resp->daddr = ip->saddr;

  /* resp->check =  cksum (resp, sizeof (struct iphdr)); */

  return sizeof (struct iphdr);
}

static ssize_t
resolve_icmp (struct icmphdr *icmp, void *icmp_resp)
{
  struct icmphdr *resp = (struct icmphdr *) icmp_resp;
  resp->type = 0x00;
  resp->code = 0;
  resp->un.echo.id = icmp->un.echo.id;
  resp->un.echo.sequence = icmp->un.echo.sequence;

  /*resp->checksum = cksum (resp, sizeof (struct icmphdr)); */

  return sizeof (struct icmphdr);
}

int
resolve_packet (void *in_pck, ssize_t in_size,
		void *out_pck, uint32_t * out_size, uint8_t ip_addr[4])
{
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip, *ip_out;
  struct icmphdr *icmp;
  *out_size = 0;

  if ((in_pck == NULL) || (out_pck == NULL))
    return -1;

  eh = (struct ether_header *) in_pck;
  *out_size = resolve_eth (eh, out_pck);

  if (eh->ether_type == 0x0608)
    {
      eah = (struct ether_arp *) (in_pck + *out_size);
      *out_size += resolve_eth_arp (eah, out_pck + *out_size, ip_addr);

    }
  else if (eh->ether_type == 0x0008)
    {
#ifdef ICMP_DBG
      print_packet (in_pck + *out_size);
#endif
      ip = (struct iphdr *) (in_pck + *out_size);
      ip_out = (struct iphdr *) (out_pck + *out_size);
      *out_size += resolve_ip (ip, out_pck + *out_size, ip_addr);
      if (ip->protocol == 1)
	{
	  icmp = (struct icmphdr *) (in_pck + *out_size);
	  *out_size += resolve_icmp (icmp, out_pck + *out_size);
	  ((struct icmphdr *) (out_pck + *out_size -
			       sizeof (struct icmphdr)))->checksum =
	    cksum (out_pck + *out_size - sizeof (struct icmphdr),
		   sizeof (struct icmphdr));
	  /* payload */
	  memcpy (out_pck + *out_size, in_pck + *out_size,
		  in_size - *out_size);
	  *out_size = in_size;
	  ip_out->tot_len =
	    __bswap_16 (*out_size - sizeof (struct ether_header));
	  ip_out->check = cksum (ip_out, sizeof (struct iphdr));
	}
    }
  return 0;
}

static ssize_t
generate_eth (struct ether_header *eh, uint8_t hw_daddr[6])
{
  uint8_t hw_addr[6];
  int i;
  for (i = 0; i < 6; i++)
    {
      hw_addr[i] = 'a';
    }
  memcpy (eh->ether_shost, hw_addr, 6);
  memcpy (eh->ether_dhost, hw_daddr, 6);

  eh->ether_type = 0x0008;

  return sizeof (struct ether_header);
}

static ssize_t
generate_ip (struct iphdr *ip, uint8_t saddr[4], uint8_t daddr[4])
{
  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  /*len updated later */
  ip->tot_len = 0x5400;
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 0x40;
  ip->protocol = 1;
  /* saddr */
  ((uint8_t *) & ip->saddr)[0] = saddr[0];
  ((uint8_t *) & ip->saddr)[1] = saddr[1];
  ((uint8_t *) & ip->saddr)[2] = saddr[2];
  ((uint8_t *) & ip->saddr)[3] = saddr[3];
  /* daddr */
  ((uint8_t *) & ip->daddr)[0] = daddr[0];
  ((uint8_t *) & ip->daddr)[1] = daddr[1];
  ((uint8_t *) & ip->daddr)[2] = daddr[2];
  ((uint8_t *) & ip->daddr)[3] = daddr[3];

  ip->check = cksum (ip, sizeof (struct iphdr));

  return sizeof (struct iphdr);
}

static ssize_t
generate_icmp (struct icmphdr *icmp, uint32_t seq, uint16_t id)
{
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = id;
  icmp->un.echo.sequence = seq;

  return sizeof (struct icmphdr);
}

int
arp_ident (void *pck, uint32_t * size)
{
  if (*size < sizeof (struct ether_header) + sizeof (struct ether_arp))
    return 0;

  struct ether_header *eh;
  uint32_t offset = 0;

  GET_HEADER (eh, struct ether_header, pck, offset);

  if (eh->ether_type == 0x0608)
    {
      struct ether_arp *eah;
      GET_HEADER (eah, struct ether_arp, pck, offset);
      struct arphdr *arp = &eah->ea_hdr;

      if (arp->ar_op != __bswap_16 (ARPOP_REPLY))
	return 0;

      uint8_t hw_daddr[6];
      uint8_t ip_rcv[4];

      memcpy (hw_daddr, eah->arp_sha, 6);
      memcpy (ip_rcv, eah->arp_spa, 4);

#ifdef ICMP_DBG
      printf ("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", hw_daddr[0],
	      hw_daddr[1], hw_daddr[2], hw_daddr[3], hw_daddr[4],
	      hw_daddr[5]);

      printf ("ip: %d.%d.%d.%d\n", ip_rcv[0], ip_rcv[1], ip_rcv[2],
	      ip_rcv[3]);
#endif
      uint16_t pos_item;
      uint8_t ip_hit = 0;

      for (pos_item = 0; pos_item < arp_table.cnt_items; pos_item++)
	{
	  if (memcmp (arp_table.ip[pos_item], ip_rcv, 4) == 0)
	    {
	      memcpy (arp_table.mac[pos_item], hw_daddr, 6);
	      memcpy (arp_table.ip[pos_item], ip_rcv, 4);
	      ip_hit = 1;
	      break;
	    }
	}

      if (!ip_hit)
	{
	  memcpy (arp_table.mac[arp_table.pos_new_items], hw_daddr, 6);
	  memcpy (arp_table.ip[arp_table.pos_new_items], ip_rcv, 4);

	  if (arp_table.cnt_items < SIZE_MAC_DICT)
	    arp_table.cnt_items++;

	  arp_table.pos_new_items++;
	  arp_table.pos_new_items %= SIZE_MAC_DICT;
	}
#ifdef ICMP_DBG
      printf ("count items of macs: %u\n", arp_table.cnt_items);
#endif
      return 1;
    }

  return 0;
}

static uint8_t cnt_ret_pck = 0;
static uint8_t cnt_ping_send = 0;
static uint8_t last_pck_resp = 0;
long echo_ms;
int max_ping;
int cnt_ping = 0;

int (*f_ping1) (uint32_t) = NULL;

int
echo_ident (void *pck, uint32_t * size, uint16_t id)
{
  uint16_t sequence;
  uint16_t id_packet;
  uint8_t ttl;
  uint8_t ip_rcv[4];

  struct ether_header *eh;
  struct icmphdr *icmp;
  struct iphdr *ip;
  uint32_t offset = 0;

  if (*size < (sizeof (struct ether_header) + sizeof (struct iphdr)
	       + sizeof (struct icmphdr)))
    return 0;

  eh = (struct ether_header *) pck;

  if (eh->ether_type == 0x0008)
    {
      offset = sizeof (struct ether_header);

      ip = (struct iphdr *) (pck + offset);
      offset += sizeof (struct iphdr);
      memcpy (ip_rcv, &ip->saddr, 4);
      ttl = ip->ttl;

      icmp = (struct icmphdr *) (pck + offset);
      id_packet = icmp->un.echo.id;
      sequence = icmp->un.echo.sequence;

      if (icmp->type == ICMP_ECHOREPLY)
	{
	  char ip_str[17];

	  if (id == id_packet && inet_ntop (AF_INET, &ip_rcv, ip_str, 16))
	    {
	      cnt_ret_pck++;
	      struct timespec current;
	      clock_gettime (CLOCK_REALTIME, &current);
	      double echo_time = 1000 * (current.tv_sec - start.tv_sec);
	      echo_time += (current.tv_nsec - start.tv_nsec) / 1000000.0;
	      printf ("%u bytes from %s: icmp_seq=%d ttl=%d time=%4.4f ms\n",
		      *size, ip_str, sequence, ttl, echo_time);
	    }
	  return 1;
	}
    }

  return 0;
}

int
ping_init (int wait_echo_ms, int max_cnt_ping, int (*f_ping) (uint32_t))
{
  f_ping1 = f_ping;
  echo_ms = wait_echo_ms;
  max_ping = max_cnt_ping;
}

void
start_ping ()
{
  cnt_ping = max_ping;
}

int
poll_ping (int *timeout, char rqst_stop)
{
  if (cnt_ping > 0 || last_pck_resp)
    {
      struct timespec current;
      clock_gettime (CLOCK_REALTIME, &current);

      long rem_time_ms = echo_ms;
      rem_time_ms -= 1000 * (current.tv_sec - start.tv_sec);
      rem_time_ms -= (current.tv_nsec - start.tv_nsec) / 1000000;

      if (!rqst_stop && rem_time_ms > 0 && cnt_ping != max_ping)
	{
	  *timeout = rem_time_ms;
	}
      else
	{
	  if (last_pck_resp || rqst_stop)
	    {
	      printf ("\n");
	      printf ("Statistics: %d sent, %d received, %d%c packet loss\n",
		      cnt_ping_send, cnt_ret_pck,
		      (100 * (cnt_ping_send - cnt_ret_pck)) / cnt_ping_send,
		      '%');

	      cnt_ret_pck = 0;
	      last_pck_resp = 0;
	      cnt_ping = 0;
	      cnt_ping_send = 0;

	      return 1;
	    }
	  else
	    {
	      if (f_ping1 == NULL)
		{
		  cnt_ping = 0;
#ifdef ICMP_DBG
		  printf ("not valid pointer to ping function\n");
#endif
		  return -1;
		}
	      if (f_ping1 (max_ping - cnt_ping) < 0)
		{
		  cnt_ping = 0;
		}
	      else
		{
		  cnt_ping_send++;
		  if (cnt_ping == 1)
		    last_pck_resp = 1;
		  cnt_ping--;
		  *timeout = 0;
		}
	    }
	}
    }

  return 0;
}

void
generate_ping (void *pck, uint32_t * size, uint8_t saddr[4], uint8_t daddr[4],
	       uint32_t seq, uint16_t id)
{
  uint8_t *hw_daddr = NULL;
  uint16_t pos_item;
  uint8_t mac_hit = 0;

  for (pos_item = 0; pos_item < arp_table.cnt_items; pos_item++)
    {
      if (memcmp (arp_table.ip[pos_item], daddr, 4) == 0)
	{
	  hw_daddr = arp_table.mac[pos_item];
	  mac_hit = 1;
	  break;
	}
    }

  if (mac_hit)
    generate_packet (pck, size, saddr, daddr, hw_daddr, seq, id);
  else
    make_arp_rqst (pck, size, saddr, daddr);

  clock_gettime (CLOCK_REALTIME, &start);
}

int
ip_dst_match (void *pck, uint32_t * size, uint8_t ip_addr[4])
{
  uint32_t offset = 0;
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip;

  if (*size < sizeof (struct ether_header))
    return 0;

  GET_HEADER (eh, struct ether_header, pck, offset);

  if (eh->ether_type == 0x0608)
    {
      if (*size < offset + sizeof (struct ether_arp))
	return 0;

      GET_HEADER (eah, struct ether_arp, pck, offset);

      if (memcmp (eah->arp_tpa, ip_addr, 4) == 0)
	return 1;

    }
  else if (eh->ether_type == 0x0008)
    {
      if (*size < offset + sizeof (struct iphdr))
	return 0;

      GET_HEADER (ip, struct iphdr, pck, offset);

      if (memcmp ((char *) &ip->daddr, ip_addr, 4) == 0)
	return 1;
    }

  offset += sizeof (struct ether_header);

  return 0;
}

int
ip_src_match (void *pck, uint32_t * size, uint8_t ip_addr[4])
{
  uint32_t offset = 0;
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip;

  if (*size < sizeof (struct ether_header))
    return 0;

  GET_HEADER (eh, struct ether_header, pck, offset);

  if (eh->ether_type == 0x0608)
    {
      if (*size < offset + sizeof (struct ether_arp))
	return 0;

      GET_HEADER (eah, struct ether_arp, pck, offset);

      if (memcmp (eah->arp_spa, ip_addr, 4) == 0)
	return 1;

    }
  else if (eh->ether_type == 0x0008)
    {
      if (*size < offset + sizeof (struct iphdr))
	return 0;

      GET_HEADER (ip, struct iphdr, pck, offset);

      if (memcmp ((char *) &ip->saddr, ip_addr, 4) == 0)
	return 1;
    }

  offset += sizeof (struct ether_header);

  return 0;
}

int
generate_packet (void *pck, uint32_t * size, uint8_t saddr[4],
		 uint8_t daddr[4], uint8_t hw_daddr[6], uint32_t seq,
		 uint16_t id)
{
  struct ether_header *eh;
  struct iphdr *ip;
  struct icmphdr *icmp;

  *size = 0;

  eh = (struct ether_header *) pck;
  *size += generate_eth (eh, hw_daddr);

  ip = (struct iphdr *) (pck + *size);
  *size += generate_ip (ip, saddr, daddr);

  icmp = (struct icmphdr *) (pck + *size);
  *size += generate_icmp (icmp, seq, id);

  ((struct icmphdr *) (pck + *size - sizeof (struct icmphdr)))->checksum =
    cksum (pck + *size - sizeof (struct icmphdr), sizeof (struct icmphdr));

  ip->tot_len = __bswap_16 (*size - sizeof (struct ether_header));
  ip->check = 0;
  ip->check = cksum (ip, sizeof (struct iphdr));

  return 0;
}

int
generate_packet2 (void *pck, uint32_t * size, uint8_t saddr[4],
		  uint8_t daddr[4], uint8_t hw_daddr[6], uint32_t seq,
		  uint16_t id, icmpr_flow_mode_t mode)
{
  struct ether_header *eh;
  struct iphdr *ip;
  struct icmphdr *icmp;

  *size = 0;

  if (mode == ICMPR_FLOW_MODE_ETH)
    {
      eh = (struct ether_header *) pck;
      *size += generate_eth (eh, hw_daddr);
    }

  ip = (struct iphdr *) (pck + *size);
  *size += generate_ip (ip, saddr, daddr);

  icmp = (struct icmphdr *) (pck + *size);
  *size += generate_icmp (icmp, seq, id);

  ((struct icmphdr *) (pck + *size - sizeof (struct icmphdr)))->checksum =
    cksum (pck + *size - sizeof (struct icmphdr), sizeof (struct icmphdr));

  ip->tot_len = __bswap_16 (*size - sizeof (struct ether_header));
  ip->check = 0;
  ip->check = cksum (ip, sizeof (struct iphdr));

  return 0;
}



int
resolve_packet2 (void *pck, uint32_t * size, uint8_t ip_addr[4])
{
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip;
  struct icmphdr *icmp;
  uint32_t offset = 0;

  if (pck == NULL)
    return -3;

  GET_HEADER (eh, struct ether_header, pck, offset);

  memcpy (eh->ether_dhost, eh->ether_shost, 6);
  memcpy (eh->ether_shost, "aaaaaa", 6);

  if (eh->ether_type == 0x0608)
    {
      GET_HEADER (eah, struct ether_arp, pck, offset);

      if (memcmp (eah->arp_tpa, ip_addr, 4) != 0)
	return -1;

      struct arphdr *arp = &eah->ea_hdr;

      arp->ar_hrd = __bswap_16 (ARPHRD_ETHER);
      arp->ar_pro = __bswap_16 (0x0800);

      arp->ar_hln = 6;
      arp->ar_pln = 4;

      arp->ar_op = __bswap_16 (ARPOP_REPLY);

      memcpy (eah->arp_tha, eah->arp_sha, 6);
      memcpy (eah->arp_tpa, eah->arp_spa, 4);

      memcpy (eah->arp_sha, eh->ether_shost, 6);
      memcpy (eah->arp_spa, ip_addr, 4);
    }

  else if (eh->ether_type == 0x0008)
    {
      GET_HEADER (ip, struct iphdr, pck, offset);

      if (ip->protocol == 1)
	{
	  ip->ihl = 5;
	  ip->version = 4;
	  ip->tos = 0;
	  ip->tot_len = 0x0000;
	  ip->id = 0;
	  ip->frag_off = 0;
	  ip->ttl = 0x40;
	  ip->protocol = 1;
	  ip->check = 0x0000;
	  ip->daddr = ip->saddr;
	  ((uint8_t *) & ip->saddr)[0] = ip_addr[0];
	  ((uint8_t *) & ip->saddr)[1] = ip_addr[1];
	  ((uint8_t *) & ip->saddr)[2] = ip_addr[2];
	  ((uint8_t *) & ip->saddr)[3] = ip_addr[3];

	  GET_HEADER (icmp, struct icmphdr, pck, offset);

	  icmp->type = 0x00;
	  icmp->code = 0;
	  icmp->checksum = cksum (icmp, sizeof (struct icmphdr));

	  /* rest is payload */
	  offset = *size;

	  ip->tot_len = __bswap_16 (offset - sizeof (struct ether_header));
	  ip->check = cksum (ip, sizeof (struct iphdr));
	}
    }

  assert (offset == *size && "unsupported protocol");
  return 0;
}


int
resolve_packet3 (void **pck_, uint32_t * size, uint8_t ip_addr[4])
{
  struct ether_header *eh;
  struct iphdr *ip;
  struct icmphdr *icmp;
  int32_t offset = 0;
  uint16_t encap_size = sizeof (struct ether_header);
  void *pck = *pck_;

  if (pck == NULL)
    return 0;

  *pck_ -= encap_size;
  offset -= encap_size;

  GET_HEADER (eh, struct ether_header, pck, offset);

  uint8_t hw_daddr[6];
  memset (hw_daddr, 0, sizeof (uint8_t) * 6);

  generate_eth (eh, hw_daddr);

  if (eh->ether_type == 0x0008)
    {
      GET_HEADER (ip, struct iphdr, pck, offset);

      if (ip->protocol == 1)
	{
	  ip->ihl = 5;
	  ip->version = 4;
	  ip->tos = 0;
	  ip->tot_len = 0x0000;
	  ip->id = 0;
	  ip->frag_off = 0;
	  ip->ttl = 0x40;
	  ip->protocol = 1;
	  ip->check = 0x0000;
	  ip->daddr = ip->saddr;
	  ((uint8_t *) & ip->saddr)[0] = ip_addr[0];
	  ((uint8_t *) & ip->saddr)[1] = ip_addr[1];
	  ((uint8_t *) & ip->saddr)[2] = ip_addr[2];
	  ((uint8_t *) & ip->saddr)[3] = ip_addr[3];

	  GET_HEADER (icmp, struct icmphdr, pck, offset);

	  icmp->type = 0x00;
	  icmp->code = 0;
	  icmp->checksum = cksum (icmp, sizeof (struct icmphdr));

	  /* rest is payload */
	  offset = *size;

	  ip->tot_len = __bswap_16 (offset - sizeof (struct ether_header));
	  ip->check = cksum (ip, sizeof (struct iphdr));
	}
    }

  offset += encap_size;

  assert (offset != *size &&
	  "new packet length must be increased by encap size");

  /* overwrite packet size */
  *size = offset;

  return 0;
}

int
make_arp_rqst (void *pck, uint32_t * size, uint8_t saddr[4], uint8_t daddr[4])
{
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip;
  struct icmphdr *icmp;
  uint32_t offset = 0;

  if (pck == NULL)
    return -3;

  GET_HEADER (eh, struct ether_header, pck, offset);

  memset (eh->ether_dhost, 0xff, 6);
  memcpy (eh->ether_shost, "aaaaaa", 6);
  eh->ether_type = 0x0608;


  GET_HEADER (eah, struct ether_arp, pck, offset);

  struct arphdr *arp = &eah->ea_hdr;

  arp->ar_hrd = __bswap_16 (ARPHRD_ETHER);
  arp->ar_pro = __bswap_16 (0x0800);

  arp->ar_hln = 6;
  arp->ar_pln = 4;

  arp->ar_op = __bswap_16 (ARPOP_REQUEST);

  memset (eah->arp_tha, 0x00, 6);
  memcpy (eah->arp_tpa, daddr, 4);

  memcpy (eah->arp_sha, "aaaaaa", 6);
  memcpy (eah->arp_spa, saddr, 4);

  *size = offset;

  return 0;
}
