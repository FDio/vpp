/*
 * pcap2cinit.c: convert pcap input to a u8 ** initializer
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * @brief Functions to convert PCAP file format to a u8 ** initializer
 *
 */
#include <vppinfra/pcap.h>
#include <vnet/ethernet/packet.h>
#include <stdio.h>

pcap_main_t pcap_main;

/**
 * @brief Conversion of PCAP file to u8 ** initializer stanzas
 *
 * @param *pm - pcap_main_t
 * @param *ofp - FILE
 *
 * @return rc - int
 *
 */
int
pcap2cinit (pcap_main_t * pm, FILE * ofp)
{
  int i, j;
  u8 *pkt;

  for (i = 0; i < vec_len (pm->packets_read); i++)
    {
      pkt = (u8 *) pm->packets_read[i];

      fformat (ofp, "static u8 __pcap_pkt%d [] = {\n  ", i);

      for (j = 0; j < vec_len (pkt); j++)
	{
	  if (((j + 1) % 8) == 0)
	    fformat (ofp, "0x%02x,\n  ", pkt[j]);
	  else
	    fformat (ofp, "0x%02x, ", pkt[j]);
	}
      fformat (ofp, "\n};\n");
    }

  fformat (ofp, "static u8 *__pcap_pkts [] = {\n");

  for (i = 0; i < vec_len (pm->packets_read); i++)
    fformat (ofp, "  __pcap_pkt%d, \n", i);

  fformat (ofp, "};\n");

  return 0;
}

/**
 * @brief pcap2pg.
 * usage: pcap2pg -i <input-file> [-o <output-file>]
 */
int
main (int argc, char **argv)
{
  unformat_input_t input;
  pcap_main_t *pm = &pcap_main;
  u8 *input_file = 0, *output_file = 0;
  FILE *ofp;
  clib_error_t *error;

  unformat_init_command_line (&input, argv);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "-i %s", &input_file)
	  || unformat (&input, "input %s", &input_file))
	;
      else if (unformat (&input, "-o %s", &output_file)
	       || unformat (&input, "output %s", &output_file))
	;
      else
	{
	usage:
	  fformat (stderr,
		   "usage: pcap2pg -i <input-file> [-o <output-file>]\n");
	  exit (1);
	}
    }

  if (input_file == 0)
    goto usage;

  pm->file_name = (char *) input_file;
  error = pcap_read (pm);

  if (error)
    {
      clib_error_report (error);
      exit (1);
    }

  if (output_file)
    {
      ofp = fopen ((char *) output_file, "w+");
      if (ofp == NULL)
	{
	  clib_unix_warning ("Couldn't create '%s'", output_file);
	  exit (1);
	}
    }
  else
    {
      ofp = stdout;
    }

  pcap2cinit (pm, ofp);

  fclose (ofp);
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
