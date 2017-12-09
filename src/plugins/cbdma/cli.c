/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <cbdma/cbdma.h>

#define foreach_cbdma_reg \
  _(0x00, 4, 0, CHANCNT, num_chan) \
  _(0x01, 4, 0, XFERCAP, trans_size) \
  _(0x03, 3, 3, INTRCTRL, MSIX_VECCTRL) \
  _(0x03, 2, 2, INTRCTRL, intp) \
  _(0x03, 1, 1, INTRCTRL, intp_sts) \
  _(0x03, 0, 0, INTRCTRL, Mstr_intp_En) \
  _(0x04, 0, 0, ATTNSTATUS, ChanAttn) \
  _(0x08, 7, 4, CBVER, mjrver) \
  _(0x08, 3, 0, CBVER, mnrver) \
  _(0x0c, 15, 15, INTRDELAY, Interrupt_Coalescing_Supported) \
  _(0x0c, 13, 0, INTRDELAY, Interrupt_Delay_Time) \
  _(0x0e, 3, 3, CS_STATUS, Address_Remapping) \
  _(0x0e, 2, 2, CS_STATUS, Memory_Bypass) \
  _(0x0e, 1, 1, CS_STATUS, MMIO_Restriction) \
  _(0x10, 27, 27, DMACAPABILITY, InterVM_Supported) \
  _(0x10, 25, 25, DMACAPABILITY, BlockFill_NULL_Supported) \
  _(0x10, 24, 24, DMACAPABILITY, NoST) \
  _(0x10, 10, 10, DMACAPABILITY, DIF) \
  _(0x10, 9, 9, DMACAPABILITY, XOR_RAID6) \
  _(0x10, 8, 8, DMACAPABILITY, XOR_RAID5) \
  _(0x10, 7, 7, DMACAPABILITY, Extended_APIC_ID) \
  _(0x10, 6, 6, DMACAPABILITY, Block_Fill) \
  _(0x10, 5, 5, DMACAPABILITY, Move_CRC) \
  _(0x10, 4, 4, DMACAPABILITY, DCA) \
  _(0x10, 3, 3, DMACAPABILITY, XOR) \
  _(0x10, 2, 2, DMACAPABILITY, Marker_Skipping) \
  _(0x10, 1, 1, DMACAPABILITY, CRC) \
  _(0x10, 0, 0, DMACAPABILITY, Page_Break) \
  _(0x14, 15, 0, DCAOFFSET, DCAREGPTR) \
  _(0x100, 7, 4, DCA_VER, Major_Revision) \
  _(0x100, 3, 0, DCA_VER, Minor_Revision) \


u8 *
format_cbdma_registers (u8 * s, va_list * args)
{
  void *bar = va_arg (*args, void *);
  u32 val;

#define _(off, msb, lsb, reg, field) \
  val = cbdma_get_bits (bar, off, msb, lsb); \
  s = format (s, "%-40s0x%x\n", #reg "." #field, val);

  foreach_cbdma_reg
#undef _
    return s;
}


u8 *
format_cbdma_channel_state (u8 * s, va_list * args)
{
  cbdma_channel_t *cc = va_arg (*args, cbdma_channel_t *);
  u32 val = cbdma_get_channel_state (cc);

#define _(a, b, str)  if (val == a) return format (s, str);
  forach_cbdma_channel_state
#undef _
    return format (s, "unknown");
}

u8 *
format_cbdma_chanerr (u8 * s, va_list * args)
{
  cbdma_channel_t *cc = va_arg (*args, cbdma_channel_t *);
  u32 val = cbdma_get_u32 (cc->bar, 0xa8);

  s = format (s, "CHANERR: %x", val);

  return s;
}

static u8 *
format_cbdma_channel (u8 * s, va_list * args)
{
  cbdma_channel_t *cc = va_arg (*args, cbdma_channel_t *);
  u32 verbose = va_arg (*args, u32);

  if (!cc)
    return s;

  s = format (s, "%U: engine %u channel %u\n",
	      format_vlib_pci_addr, vlib_pci_get_addr (cc->pci_dev_handle),
	      cc->engine, cc->channel);
  s = format (s, "    version %u.%u max-transfer-size %u dca-version %u.%u\n",
	      cbdma_get_bits (cc->bar, 0x08, 7, 4),
	      cbdma_get_bits (cc->bar, 0x08, 3, 0),
	      1 << cbdma_get_bits (cc->bar, 0x01, 4, 0),
	      cbdma_get_bits (cc->bar, 0x100, 7, 4),
	      cbdma_get_bits (cc->bar, 0x100, 3, 0));

  s = format (s, "    state: %U", format_cbdma_channel_state, cc);
  s = format (s, "    %U", format_cbdma_chanerr, cc);
  if (verbose)
    s = format (s, "    %U", format_cbdma_registers, cc->bar);

  return s;
}

static clib_error_t *
show_cbdma_fn (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  cbdma_main_t *cm = &cbdma_main;
  u32 engine = 0, channel = 0, verbose = 0;
  int engine_selected = 0, channel_selected = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "channel %u", &channel))
	    channel_selected = 1;
	  else if (unformat (line_input, "engine %u", &engine))
	    engine_selected = 1;
	  else if (unformat (line_input, "%u/%u", &engine, &channel))
	    engine_selected = channel_selected = 1;
	  else if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, input);
	}
      unformat_free (line_input);
    }

  if (engine_selected && channel_selected)
    {
      vlib_cli_output (vm, "\n%U\n", format_cbdma_channel,
		       cbdma_get_channel (engine, channel), verbose);
      return 0;
    }
  else if (engine_selected)
    {
      vec_foreach_index (channel, cm->engines[engine].channels)
	vlib_cli_output (vm, "\n%U\n", format_cbdma_channel,
			 cbdma_get_channel (engine, channel), verbose);
    }

  vec_foreach_index (engine, cm->engines)
    vec_foreach_index (channel, cm->engines[engine].channels)
    vlib_cli_output (vm, "\n%U\n", format_cbdma_channel,
		     cbdma_get_channel (engine, channel), verbose);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cbdma_interface, static) =
{
  .path = "show cbdma",
  .short_help = "show cbdma",
  .function = show_cbdma_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_cbdma_fn (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u8 *src, *dst, **srcv = 0, **dstv = 0;
  u32 size = 1024, count = 2048, i, j, ch;
  u32 channel = 0, engine = 0, n_channels = 1;
  cbdma_channel_t *cc;
  vlib_physmem_region_index_t pr;
  int n_alloc, fail = 0;
  f64 before, after;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "channel %u", &channel))
	    ;
	  else if (unformat (line_input, "engine %u", &engine))
	    ;
	  else if (unformat (line_input, "%u/%u", &engine, &channel))
	    ;
	  else if (unformat (line_input, "count %u", &count))
	    ;
	  else if (unformat (line_input, "size %u", &size))
	    ;
	  else if (unformat (line_input, "num-channels %u", &n_channels))
	    ;
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, input);
	}
      unformat_free (line_input);
    }

  n_alloc = (((int) (size * count * 2 * 1.2) >> 21) + 1) << 21;
  err = vlib_physmem_region_alloc (vm, "cbdma test", n_alloc, engine,
				   VLIB_PHYSMEM_F_INIT_MHEAP, &pr);
  if (err)
    return err;

  for (ch = channel; ch < channel + n_channels; ch++)
    for (i = 0; i < (count / n_channels); i++)
      {
	u64 src_pa, dst_pa;
	src = vlib_physmem_alloc_aligned (vm, pr, &err, size, 64);
	if (err)
	  return err;

	dst = vlib_physmem_alloc_aligned (vm, pr, &err, size, 64);
	if (err)
	  return err;

	vec_add1 (srcv, src);
	vec_add1 (dstv, dst);

	for (j = 0; j < size; j++)
	  src[j] = j;

	src_pa = vlib_physmem_virtual_to_physical (vm, pr, src);
	dst_pa = vlib_physmem_virtual_to_physical (vm, pr, dst);

	cc = cbdma_get_channel (engine, ch);
	cbdma_add_req (cc, src_pa, dst_pa, size);
      }

  vlib_cli_output (vm, "transfer size:       %u bytes", size);
  vlib_cli_output (vm, "transfer count:      %u", count);
  vlib_cli_output (vm, "number of channels:  %u", n_channels);
  vlib_cli_output (vm, "total transfer size: %u bytes", size * count);

  before = vlib_time_now (vm);
  u8 run_bitmap = 0;
  for (ch = channel; ch < channel + n_channels; ch++)
    {
      cc = cbdma_get_channel (engine, ch);
      cbdma_run (cc);
      run_bitmap |= 1 << ch;
    }
  while (run_bitmap)
    {
      for (ch = channel; ch < channel + n_channels; ch++)
	{
	  cc = cbdma_get_channel (engine, ch);
	  if (cbdma_get_channel_state (cc) == CBDMA_CHANNEL_STATE_IDLE)
	    run_bitmap &= ~(1 << ch);
	}
      __builtin_ia32_pause ();
    }

  after = vlib_time_now (vm);

  vlib_cli_output (vm, "total transfer time: %.7f", after - before);
  vlib_cli_output (vm, "transfer speed:      %.2f Gbps",
		   8 * (size * count) / (after - before) / (1 << 30));

  for (i = 0; i < count; i++)
    {
      src = srcv[i];
      dst = dstv[i];
      for (j = 0; j < size; j++)
	if (dst[j] != (u8) j)
	  {
	    fail = 1;
	    goto fail;
	  }
    }

fail:
  if (fail)
    vlib_cli_output (vm, "data verification:   FAILED (transfer %u offset %u "
		     "(0x%x) found 0x%02x expected 0x%02x)", i, j, j, dst[j],
		     (u8) j);
  else
    vlib_cli_output (vm, "data verification:   OK");

  for (i = 0; i < count; i++)
    {
      vlib_physmem_free (vm, pr, (void *) srcv[i]);
      vlib_physmem_free (vm, pr, (void *) dstv[i]);
    }
  vlib_physmem_region_free (vm, pr);
  vec_free (srcv);
  vec_free (dstv);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_cbdma, static) =
{
  .path = "test cbdma",
  .short_help = "test cbdma",
  .function = test_cbdma_fn,
};
/* *INDENT-ON* */


clib_error_t *
cbdma_cli_init (vlib_main_t * vm)
{
  clib_error_t *error;
  if ((error = vlib_call_init_function (vm, cbdma_init)))
    return error;
  return 0;
}

VLIB_INIT_FUNCTION (cbdma_cli_init);

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
