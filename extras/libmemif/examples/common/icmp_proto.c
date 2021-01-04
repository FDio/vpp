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
  printf ("\t\tihl: %u\n\t\tversion: %u\n\t\tlen: %u\n\t\tid: %u\n", ip->ihl,
	  ip->version, __bswap_16 (ip->tot_len), ip->id);
  printf ("\t\tprotocol: %u\n", ip->protocol);

  printf ("\t\tsaddr: ");
  int i;
  for (i = 0; i < 4; i++)
    {
      printf ("%u.", ((uint8_t *) &ip->saddr)[i]);
    }
  printf ("\n");

  printf ("\t\tdaddr: ");
  for (i = 0; i < 4; i++)
    {
      printf ("%u.", ((uint8_t *) &ip->daddr)[i]);
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

  memcpy (
    resp->arp_sha,
    (((struct ether_header *) (eth_arp_resp - sizeof (struct ether_header)))
       ->ether_shost),
    6);

  memcpy (resp->arp_spa, ip_addr, 4);

  return sizeof (struct ether_arp);
}

static ssize_t
resolve_eth (struct ether_header *eth, void *eth_resp, uint8_t hw_addr[6])
{
  struct ether_header *resp = (struct ether_header *) eth_resp;
  memcpy (resp->ether_dhost, eth->ether_shost, 6);

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
  ((uint8_t *) &resp->saddr)[0] = ip_addr[0];
  ((uint8_t *) &resp->saddr)[1] = ip_addr[1];
  ((uint8_t *) &resp->saddr)[2] = ip_addr[2];
  ((uint8_t *) &resp->saddr)[3] = ip_addr[3];
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
resolve_packet (void *in_pck, ssize_t in_size, void *out_pck,
		uint32_t *out_size, uint8_t ip_addr[4], uint8_t hw_addr[6])
{
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip, *ip_out;
  struct icmphdr *icmp;
  *out_size = 0;

  if ((in_pck == NULL) || (out_pck == NULL))
    return -1;

  eh = (struct ether_header *) in_pck;
  *out_size = resolve_eth (eh, out_pck, hw_addr);

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
	  ((struct icmphdr *) (out_pck + *out_size - sizeof (struct icmphdr)))
	    ->checksum = cksum (out_pck + *out_size - sizeof (struct icmphdr),
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
  ((uint8_t *) &ip->saddr)[0] = saddr[0];
  ((uint8_t *) &ip->saddr)[1] = saddr[1];
  ((uint8_t *) &ip->saddr)[2] = saddr[2];
  ((uint8_t *) &ip->saddr)[3] = saddr[3];
  /* daddr */
  ((uint8_t *) &ip->daddr)[0] = daddr[0];
  ((uint8_t *) &ip->daddr)[1] = daddr[1];
  ((uint8_t *) &ip->daddr)[2] = daddr[2];
  ((uint8_t *) &ip->daddr)[3] = daddr[3];

  ip->check = cksum (ip, sizeof (struct iphdr));

  return sizeof (struct iphdr);
}

static ssize_t
generate_icmp (struct icmphdr *icmp, uint32_t seq)
{
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = 0;
  icmp->un.echo.sequence = seq;

  return sizeof (struct icmphdr);
}

int
generate_packet (void *pck, uint32_t *size, uint8_t saddr[4], uint8_t daddr[4],
		 uint8_t hw_daddr[6], uint32_t seq)
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
  *size += generate_icmp (icmp, seq);

  ((struct icmphdr *) (pck + *size - sizeof (struct icmphdr)))->checksum =
    cksum (pck + *size - sizeof (struct icmphdr), sizeof (struct icmphdr));

  ip->tot_len = __bswap_16 (*size - sizeof (struct ether_header));
  ip->check = 0;
  ip->check = cksum (ip, sizeof (struct iphdr));

  return 0;
}

int
generate_packet2 (void *pck, uint32_t *size, uint8_t saddr[4],
		  uint8_t daddr[4], uint8_t hw_daddr[6], uint32_t seq,
		  icmpr_flow_mode_t mode)
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
  *size += generate_icmp (icmp, seq);

  ((struct icmphdr *) (pck + *size - sizeof (struct icmphdr)))->checksum =
    cksum (pck + *size - sizeof (struct icmphdr), sizeof (struct icmphdr));

  ip->tot_len = __bswap_16 (*size - sizeof (struct ether_header));
  ip->check = 0;
  ip->check = cksum (ip, sizeof (struct iphdr));

  return 0;
}

#define GET_HEADER(out, hdr, src, off)                                        \
  do                                                                          \
    {                                                                         \
      out = (hdr *) (src + off);                                              \
      off += sizeof (hdr);                                                    \
    }                                                                         \
  while (0)

int
resolve_packet_zero_copy (void *pck, uint32_t *size, uint8_t ip_addr[4],
			  uint8_t hw_addr[6])
{
  struct ether_header *eh;
  struct ether_arp *eah;
  struct iphdr *ip;
  struct icmphdr *icmp;
  uint32_t offset = 0;

  if (pck == NULL)
    return 0;

  GET_HEADER (eh, struct ether_header, pck, offset);

  memcpy (eh->ether_dhost, eh->ether_shost, 6);
  memcpy (eh->ether_shost, hw_addr, 6);

  if (eh->ether_type == 0x0608)
    {
      GET_HEADER (eah, struct ether_arp, pck, offset);
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
	  ((uint8_t *) &ip->saddr)[0] = ip_addr[0];
	  ((uint8_t *) &ip->saddr)[1] = ip_addr[1];
	  ((uint8_t *) &ip->saddr)[2] = ip_addr[2];
	  ((uint8_t *) &ip->saddr)[3] = ip_addr[3];

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
resolve_packet_zero_copy_add_encap (void **pck_, uint32_t *size,
				    uint8_t ip_addr[4])
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
	  ((uint8_t *) &ip->saddr)[0] = ip_addr[0];
	  ((uint8_t *) &ip->saddr)[1] = ip_addr[1];
	  ((uint8_t *) &ip->saddr)[2] = ip_addr[2];
	  ((uint8_t *) &ip->saddr)[3] = ip_addr[3];

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
