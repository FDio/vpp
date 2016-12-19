/*
 * pcap2pg.c: convert pcap input to pg input
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief Functions to convert PCAP file format to VPP PG (Packet Generator)
 *
 */
#include <vnet/unix/pcap.h>
#include <vnet/ethernet/packet.h>
#include <stdio.h>

pcap_main_t pcap_main;

/**
 * @brief char * to seed a PG file
 */
static char * pg_fmt =
  "packet-generator new {\n"
  "    name s%d\n"
  "    limit 1\n"
  "    size %d-%d\n"
  "    node ethernet-input\n";


/**
 * @brief Packet Generator Stream boilerplate
 *
 * @param *ofp - FILE
 * @param i - int
 * @param *pkt - u8
 */
void stream_boilerplate (FILE *ofp, int i, u8 * pkt)
{
  fformat(ofp, pg_fmt, i, vec_len(pkt), vec_len(pkt));
}

/**
 * @brief Conversion of PCAP file to PG file format
 *
 * @param *pm - pcap_main_t
 * @param *ofp - FILE
 *
 * @return rc - int
 *
 */
int pcap2pg (pcap_main_t * pm, FILE *ofp)
{
  int i, j;
  u8 *pkt;

  for (i = 0; i < vec_len (pm->packets_read); i++)
    {
      int offset;
      ethernet_header_t * h;
      u64 ethertype;

      pkt = pm->packets_read[i];
      h = (ethernet_header_t *)pkt;

      stream_boilerplate (ofp, i, pkt);

      fformat (ofp, "    data {\n");

      ethertype = clib_net_to_host_u16 (h->type);

      /**
       * In vnet terms, packet generator interfaces are not ethernets.
       * They don't have vlan tables.
       * This transforms captured 802.1q VLAN packets into
       * regular Ethernet packets.
       */
      if (ethertype == 0x8100 /* 802.1q vlan */)
        {
          u16 * vlan_ethertype = (u16 *)(h+1);
          ethertype = clib_net_to_host_u16(vlan_ethertype[0]);
          offset = 18;
        }
      else
        offset = 14;

      fformat (ofp,
               "          0x%04x: %02x%02x.%02x%02x.%02x%02x"
               " -> %02x%02x.%02x%02x.%02x%02x\n",
               ethertype,
               h->src_address[0],
               h->src_address[1],
               h->src_address[2],
               h->src_address[3],
               h->src_address[4],
               h->src_address[5],
               h->dst_address[0],
               h->dst_address[1],
               h->dst_address[2],
               h->dst_address[3],
               h->dst_address[4],
               h->dst_address[5]);

      fformat (ofp, "      hex 0x");

      for (j = offset; j < vec_len (pkt); j++)
          fformat (ofp, "%02x", pkt[j]);

      fformat (ofp, " }\n");
      fformat (ofp, "}\n\n");
    }
  return 0;
}

/**
 * @brief pcap2pg.
 * usage: pcap2pg -i <input-file> [-o <output-file>]
 */
int main (int argc, char **argv)
{
  unformat_input_t input;
  pcap_main_t * pm = &pcap_main;
  u8 * input_file = 0, * output_file = 0;
  FILE * ofp;
  clib_error_t * error;

  unformat_init_command_line (&input, argv);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(&input, "-i %s", &input_file)
          || unformat (&input, "input %s", &input_file))
        ;
      else if (unformat (&input, "-o %s", &output_file)
               || unformat (&input, "output %s", &output_file))
        ;
      else 
        {
        usage:
          fformat(stderr, 
                  "usage: pcap2pg -i <input-file> [-o <output-file>]\n");
          exit (1);
        }
    }

  if (input_file == 0)
    goto usage;
  
  pm->file_name = (char *)input_file;
  error = pcap_read (pm);

  if (error)
    {
      clib_error_report (error);
      exit (1);
    }

  if (output_file)
    {
      ofp = fopen ((char *)output_file, "rw");
      if (ofp == NULL)
        clib_unix_warning ("Couldn't create '%s'", output_file);
      exit (1);
    }
  else
    {
      ofp = stdout;
    }
  
  pcap2pg (pm, ofp);

  fclose (ofp);
  exit (0);
}
