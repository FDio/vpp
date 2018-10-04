/*
 * mss_clamp.c - TCP MSS clamping plug-in
 *
 * Copyright (c) 2018 Cisco and/or its affiliates
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <mss_clamp/mss_clamp.h>
#include <mss_clamp/mss_clamp.api_types.h>

mssc_main_t mssc_main;

/* Action function shared between message handler and debug CLI */

static void
mssc_enable_disable_feat (u32 sw_if_index, u8 dir4, u8 dir6, int enable)
{
  if (dir4 == MSS_CLAMP_DIR_NONE && dir6 == MSS_CLAMP_DIR_NONE)
    return;

  // ip4
  if ((dir4 & MSS_CLAMP_DIR_RX) != MSS_CLAMP_DIR_NONE)
    vnet_feature_enable_disable ("ip4-unicast", "tcp-mss-clamping-ip4-in",
				 sw_if_index, enable, 0, 0);
  if ((dir4 & MSS_CLAMP_DIR_TX) != MSS_CLAMP_DIR_NONE)
    vnet_feature_enable_disable ("ip4-output", "tcp-mss-clamping-ip4-out",
				 sw_if_index, enable, 0, 0);
  // ip6
  if ((dir6 & MSS_CLAMP_DIR_RX) != MSS_CLAMP_DIR_NONE)
    vnet_feature_enable_disable ("ip6-unicast", "tcp-mss-clamping-ip6-in",
				 sw_if_index, enable, 0, 0);
  if ((dir6 & MSS_CLAMP_DIR_TX) != MSS_CLAMP_DIR_NONE)
    vnet_feature_enable_disable ("ip6-output", "tcp-mss-clamping-ip6-out",
				 sw_if_index, enable, 0, 0);
}

int
mssc_enable_disable (u32 sw_if_index, u8 dir4, u8 dir6, u16 mss4, u16 mss6)
{
  mssc_main_t *cm = &mssc_main;
  u8 *dir_enabled4, *dir_enabled6;
  int rv = 0;

  if (dir4 == MSS_CLAMP_DIR_NONE)
    mss4 = MSS_CLAMP_UNSET;
  if (dir6 == MSS_CLAMP_DIR_NONE)
    mss6 = MSS_CLAMP_UNSET;

  vec_validate_init_empty (cm->dir_enabled4, sw_if_index, MSS_CLAMP_DIR_NONE);
  vec_validate_init_empty (cm->dir_enabled6, sw_if_index, MSS_CLAMP_DIR_NONE);
  vec_validate_init_empty (cm->max_mss4, sw_if_index, MSS_CLAMP_UNSET);
  vec_validate_init_empty (cm->max_mss6, sw_if_index, MSS_CLAMP_UNSET);

  cm->max_mss4[sw_if_index] = mss4;
  cm->max_mss6[sw_if_index] = mss6;
  dir_enabled4 = &cm->dir_enabled4[sw_if_index];
  dir_enabled6 = &cm->dir_enabled6[sw_if_index];

  // Disable the directions that are no longer needed
  mssc_enable_disable_feat (sw_if_index, (*dir_enabled4) & ~dir4,
			    (*dir_enabled6) & ~dir6, 0);
  // Enable the new directions
  mssc_enable_disable_feat (sw_if_index, ~(*dir_enabled4) & dir4,
			    ~(*dir_enabled6) & dir6, 1);

  *dir_enabled4 = dir4;
  *dir_enabled6 = dir6;

  return rv;
}

int
mssc_get_mss (u32 sw_if_index, u8 *dir4, u8 *dir6, u16 *mss4, u16 *mss6)
{
  mssc_main_t *cm = &mssc_main;
  int rv = VNET_API_ERROR_FEATURE_DISABLED;

  if (vec_len (cm->dir_enabled4) > sw_if_index &&
      MSS_CLAMP_DIR_NONE != cm->dir_enabled4[sw_if_index])
    {
      *mss4 = cm->max_mss4[sw_if_index];
      *dir4 = cm->dir_enabled4[sw_if_index];
      rv = 0;
    }
  else
    {
      *mss4 = MSS_CLAMP_DIR_NONE;
      *dir4 = 0;
    }

  if (vec_len (cm->dir_enabled6) > sw_if_index &&
      MSS_CLAMP_DIR_NONE != cm->dir_enabled6[sw_if_index])
    {
      *mss6 = cm->max_mss6[sw_if_index];
      *dir6 = cm->dir_enabled6[sw_if_index];
      rv = 0;
    }
  else
    {
      *mss6 = MSS_CLAMP_DIR_NONE;
      *dir6 = 0;
    }
  return rv;
}

static uword
unformat_mssc_dir (unformat_input_t *input, va_list *args)
{
  u8 *result = va_arg (*args, u8 *);
  u8 dir = MSS_CLAMP_DIR_RX | MSS_CLAMP_DIR_TX;

  if (unformat (input, "disable"))
    dir = MSS_CLAMP_DIR_NONE;
  else if (unformat (input, "enable"))
    dir = MSS_CLAMP_DIR_RX | MSS_CLAMP_DIR_TX;
  else if (unformat (input, "rx"))
    dir = MSS_CLAMP_DIR_RX;
  else if (unformat (input, "tx"))
    dir = MSS_CLAMP_DIR_TX;
  else
    return 0;

  *result = dir;
  return 1;
}

static clib_error_t *
mssc_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  u8 dir4 = ~0, dir6 = ~0;
  u32 mss4 = ~0, mss6 = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4 %U", unformat_mssc_dir, &dir4))
	;
      else if (unformat (input, "ip6 %U", unformat_mssc_dir, &dir6))
	;
      else if (unformat (input, "ip4-mss %d", &mss4))
	;
      else if (unformat (input, "ip6-mss %d", &mss6))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface");

  if (dir4 == (u8) ~0 || dir6 == (u8) ~0)
    return clib_error_return (
      0, "Please specify the MSS clamping direction for ip4 and ip6");

  if (dir4 != MSS_CLAMP_DIR_NONE)
    {
      if (mss4 == ~0)
	return clib_error_return (
	  0, "Please specify the Max Segment Size for ip4");
      if (mss4 >= MSS_CLAMP_UNSET)
	return clib_error_return (0, "Invalid Max Segment Size");
    }
  if (dir6 != MSS_CLAMP_DIR_NONE)
    {
      if (mss6 == ~0)
	return clib_error_return (
	  0, "Please specify the Max Segment Size for ip6");
      if (mss6 >= MSS_CLAMP_UNSET)
	return clib_error_return (0, "Invalid Max Segment Size");
    }

  rv = mssc_enable_disable (sw_if_index, dir4, dir6, mss4, mss6);

  if (rv)
    return clib_error_return (0, "Failed: %d = %U", rv, format_vnet_api_errno,
			      rv);

  return (NULL);
}

VLIB_CLI_COMMAND (mssc_enable_disable_command, static) = {
  .path = "set interface tcp-mss-clamp",
  .short_help = "set interface tcp-mss-clamp <interface-name> "
		"ip4 [enable|disable|rx|tx] ip4-mss <size> "
		"ip6 [enable|disable|rx|tx] ip6-mss <size>",
  .function = mssc_enable_command_fn,
};

static u8 *
format_mssc_clamping (u8 *s, va_list *args)
{
  u8 dir = va_arg (*args, u32);
  u16 mss = va_arg (*args, u32);
#define DIR2S(d)                                                              \
  (((d) == (MSS_CLAMP_DIR_RX | MSS_CLAMP_DIR_TX)) ?                           \
     "" :                                                                     \
     (((d) == MSS_CLAMP_DIR_RX) ? " [RX]" : " [TX]"))

  if (MSS_CLAMP_DIR_NONE == dir)
    {
      return format (s, "disabled");
    }
  u32 mss_u32 = mss;
  return format (s, "%d%s", mss_u32, DIR2S (dir));
}

static clib_error_t *
mssc_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  mssc_main_t *cm = &mssc_main;
  u32 sw_if_index = ~0;
  u32 ii;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnet_get_main (),
		    &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      vec_foreach_index (ii, cm->dir_enabled4)
	{
	  u8 dir4 = cm->dir_enabled4[ii];
	  u8 dir6 = cm->dir_enabled6[ii];
	  if (MSS_CLAMP_DIR_NONE != dir4 || MSS_CLAMP_DIR_NONE != dir6)
	    {
	      u16 mss4 = cm->max_mss4[ii];
	      u16 mss6 = cm->max_mss6[ii];
	      vlib_cli_output (vm, "%U: ip4: %U ip6: %U",
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       ii, format_mssc_clamping, dir4, mss4,
			       format_mssc_clamping, dir6, mss6);
	    }
	}
    }
  else
    {
      u16 mss4, mss6;
      u8 dir4, dir6;
      mssc_get_mss (sw_if_index, &dir4, &dir6, &mss4, &mss6);
      vlib_cli_output (vm, "%U: ip4: %U ip6: %U", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index, format_mssc_clamping,
		       dir4, mss4, format_mssc_clamping, dir6, mss6);
    }

  return (NULL);
}

VLIB_CLI_COMMAND (mssc_show_command, static) = {
  .path = "show interface tcp-mss-clamp",
  .short_help = "show interface tcp-mss-clamp [interface-name]",
  .long_help = "show TCP MSS clamping configurations",
  .function = mssc_show_command_fn,
};

static clib_error_t *
mssc_init (vlib_main_t *vm)
{
  return NULL;
}

VLIB_INIT_FUNCTION (mssc_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
