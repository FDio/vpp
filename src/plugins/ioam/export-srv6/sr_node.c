/*
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
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <ioam/export-common/ioam_export.h>

typedef struct
{
  u32 next_index;
  u32 flow_label;
} export_trace_t;

/* packet trace format function */
static u8 *
format_export_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  export_trace_t *t = va_arg (*args, export_trace_t *);

  s = format (s, "EXPORT: flow_label %d, next index %d",
	      t->flow_label, t->next_index);
  return s;
}

vlib_node_registration_t sr_export_node;
extern vlib_node_registration_t export_node;
extern ioam_export_main_t sr_ioam_export_main;

#define foreach_export_error \
_(RECORDED, "Packets recorded for export")

typedef enum
{
#define _(sym,str) EXPORT_ERROR_##sym,
  foreach_export_error
#undef _
    EXPORT_N_ERROR,
} export_error_t;

static char *export_error_strings[] = {
#define _(sym,string) string,
  foreach_export_error
#undef _
};

typedef enum
{
  //EXPORT_NEXT_SR_INPUT,
  EXPORT_NEXT_SR_POP,
  EXPORT_N_NEXT,
} export_next_t;

always_inline void
copy3cachelines (void *dst, const void *src, size_t n)
{
#if 0
  if (PREDICT_FALSE (n < DEFAULT_EXPORT_SIZE))
    {
      /* Copy only the first 1/2 cache lines whatever is available */
      if (n >= 64)
	clib_mov64 ((u8 *) dst, (const u8 *) src);
      if (n >= 128)
	clib_mov64 ((u8 *) dst + 64, (const u8 *) src + 64);
      return;
    }
  clib_mov64 ((u8 *) dst, (const u8 *) src);
  clib_mov64 ((u8 *) dst + 64, (const u8 *) src + 64);
  clib_mov64 ((u8 *) dst + 128, (const u8 *) src + 128);
#endif
#if 1

  u64 *copy_dst, *copy_src;
  int i;
  copy_dst = (u64 *) dst;
  copy_src = (u64 *) src;
  if (PREDICT_FALSE (n < DEFAULT_EXPORT_SIZE))
    {
      for (i = 0; i <= n / 64; i++)
	{
	  copy_dst[0] = copy_src[0];
	  copy_dst[1] = copy_src[1];
	  copy_dst[2] = copy_src[2];
	  copy_dst[3] = copy_src[3];
	  copy_dst[4] = copy_src[4];
	  copy_dst[5] = copy_src[5];
	  copy_dst[6] = copy_src[6];
	  copy_dst[7] = copy_src[7];
	  copy_dst += 8;
	  copy_src += 8;
	}
      return;
    }
  for (i = 0; i < 3; i++)
    {
      copy_dst[0] = copy_src[0];
      copy_dst[1] = copy_src[1];
      copy_dst[2] = copy_src[2];
      copy_dst[3] = copy_src[3];
      copy_dst[4] = copy_src[4];
      copy_dst[5] = copy_src[5];
      copy_dst[6] = copy_src[6];
      copy_dst[7] = copy_src[7];
      copy_dst += 8;
      copy_src += 8;
    }
#endif
}

static void
sr_export_fixup_func (vlib_buffer_t * export_buf, vlib_buffer_t * pak_buf)
{
  /* Todo: on implementing SR IOAM analyse */
}

static uword
sr_export_node_fn (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ioam_export_main_t *em = &sr_ioam_export_main;
  ioam_export_node_common (em, vm, node, frame, ip6_header_t, payload_length,
			   ip_version_traffic_class_and_flow_label,
			   EXPORT_NEXT_SR_POP, sr_export_fixup_func);
  return frame->n_vectors;
}

/*
 * Node for SR IOAM export
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_export_node) =
{
  .function = sr_export_node_fn,
  .name = "sr-ioam-export",
  .vector_size = sizeof (u32),
  .format_trace = format_export_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (export_error_strings),
  .error_strings = export_error_strings,
  .n_next_nodes = EXPORT_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
  //{[EXPORT_NEXT_SR_INPUT] = "ip6-lookup"},
  {[EXPORT_NEXT_SR_POP] = "sr-pop-ioam"},
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
