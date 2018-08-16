/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel and/or its affiliates.
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
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <dpi/dpi.h>

dpi_main_t dpi_main;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_dpi_bypass, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-dpi-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip6_dpi_bypass, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-dpi-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-on* */

void
vnet_int_dpi_bypass (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-dpi-bypass",
                 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-dpi-bypass",
                 sw_if_index, is_enable, 0, 0);
}

u32
hs_parse_flagstr(char *flagsStr)
{
  u32 flags = 0;

  for (int i = 0; i < strlen(flagsStr); i++)
    {
      switch (flagsStr[i])
        {
          case 'i':
              flags |= HS_FLAG_CASELESS;
              break;
          case 'm':
              flags |= HS_FLAG_MULTILINE;
              break;
          case 's':
              flags |= HS_FLAG_DOTALL;
              break;
          case 'H':
              flags |= HS_FLAG_SINGLEMATCH;
              break;
          case 'V':
              flags |= HS_FLAG_ALLOWEMPTY;
              break;
          case '8':
              flags |= HS_FLAG_UTF8;
              break;
          case 'W':
              flags |= HS_FLAG_UCP;
              break;
          case '\r': /* stray carriage-return */
              break;
          default:
              break;
        }
    }
  return flags;
}


clib_error_t *
dpi_init (vlib_main_t * vm)
{
  dpi_main_t *hsm = &dpi_main;

  hsm->vnet_main = vnet_get_main ();
  hsm->vlib_main = vm;

  return 0;
}

VLIB_INIT_FUNCTION (dpi_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deep Packet Inspection",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
