#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <stdbool.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */


#include "gpcapng.h"
#include "gpcapng_node.h"
#include "write_pcapng.h"


/******************************************************************************
 * Packet processing and GENEVE parsing
 ******************************************************************************/

/* GENEVE header structure */
typedef struct {
  u8 ver_opt_len;      /* Version and option length */
  u8 flags;            /* Flags */
  u16 protocol;        /* Protocol type */
  u8 vni[3];           /* VNI (24 bits) */
  u8 reserved;         /* Reserved */
} geneve_header_t;

/* GENEVE option structure */
typedef struct {
  u16 opt_class;       /* Option class */
  u8 type;             /* Type */
  u8 flags_length;     /* Flags (4 bits) and length (4 bits) in 4-byte multiples */
  u8 data[0];          /* Option data (variable length) */
} geneve_option_t;

static_always_inline u8
geneve_get_version (const geneve_header_t *h)
{
  return (h->ver_opt_len & GENEVE_VERSION_MASK) >> GENEVE_VERSION_SHIFT;
}

static_always_inline u8
geneve_get_opt_len (const geneve_header_t *h)
{
  return (h->ver_opt_len & GENEVE_OPT_LEN_MASK) >> GENEVE_OPT_LEN_SHIFT;
}

static_always_inline u32
geneve_get_vni (const geneve_header_t *h)
{
  return (((u32) h->vni[0]) << 16) | (((u32) h->vni[1]) << 8) | h->vni[2];
}

static_always_inline u8
geneve_opt_get_length (const geneve_option_t *opt)
{
  return (opt->flags_length & 0x1F) * 4;
}

/* Function to check if a packet matches a 5-tuple filter */
static bool
packet_matches_tuple_filter (const u8 *packet_data, u32 packet_len, 
                            const geneve_tuple_filter_t *filter)
{
  u32 i;
  
  /* Make sure we have enough data */
  if (packet_len < filter->length)
    return false;
    
  /* Apply mask and compare values */
  for (i = 0; i < filter->length; i++)
    {
      if ((packet_data[i] & filter->mask[i]) != (filter->value[i] & filter->mask[i]))
        goto no_match;
    }
    
  return true;
no_match:
  /*
    clib_warning("pkt: %U", format_hexdump, packet_data, packet_len);
    clib_warning("dat: %U", format_hexdump, filter->value, vec_len(filter->value));
    clib_warning("msk: %U", format_hexdump, filter->mask, vec_len(filter->mask));
  */
  return false;
}

/* Check if packet matches a Geneve filter */
static u32
geneve_packet_matches_filter (gpcapng_main_t *gpm,
                             const u8 *outer_hdr, u32 outer_len,
                             const u8 *inner_hdr, u32 inner_len,
                             const geneve_header_t *geneve_hdr,
                             u32 geneve_header_len,
                             const geneve_capture_filter_t *filter)
{
  const geneve_option_t *opt;
  u32 remaining_len;
  int i;
  const u32 DEST_INDEX_NONE = ~0;
  u32 dest_index_match = filter->destination_index;

  /* Check basic Geneve header fields if specified in filter */
  if (filter->ver_present && filter->ver != geneve_get_version (geneve_hdr))
    return DEST_INDEX_NONE;
    
  if (filter->opt_len_present && filter->opt_len != geneve_get_opt_len (geneve_hdr))
    return DEST_INDEX_NONE;
    
  if (filter->proto_present && filter->protocol != clib_net_to_host_u16 (geneve_hdr->protocol))
    return DEST_INDEX_NONE;
    
  if (filter->vni_present && filter->vni != geneve_get_vni (geneve_hdr))
    return DEST_INDEX_NONE;
    
  /* Check 5-tuple filters */
  if (filter->outer_tuple_present && 
      !packet_matches_tuple_filter (outer_hdr, outer_len, &filter->outer_tuple)) {
    return DEST_INDEX_NONE;
  }
    
  if (filter->inner_tuple_present && 
      !packet_matches_tuple_filter (inner_hdr, inner_len, &filter->inner_tuple))
    return DEST_INDEX_NONE;
  
  /* No option filters, match just on basic headers and tuples */
  if (vec_len (filter->option_filters) == 0)
    return dest_index_match;

  /* Start of options */
  opt = (const geneve_option_t *)(geneve_hdr + 1);
  remaining_len = geneve_header_len - sizeof (geneve_header_t);
  
  /* Check each option filter */
  for (i = 0; i < vec_len (filter->option_filters); i++)
    {
      const geneve_option_t *current_opt = opt;
      bool found = false;
      u16 opt_class;
      u8 opt_type;
      uword *p;
      
      /* Resolve option class/type from name if needed */
      if (filter->option_filters[i].option_name)
        {
          /* Look up option definition by name */
          p = hash_get_mem (gpm->option_by_name, filter->option_filters[i].option_name);
          if (!p)
            return DEST_INDEX_NONE;  /* Unknown option name, can't match */
            
          const geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
          opt_class = opt_def->opt_class;
          opt_type = opt_def->type;
        }
      else
        {
          /* Use direct option class/type from filter */
          opt_class = filter->option_filters[i].opt_class;
          opt_type = filter->option_filters[i].type;
        }
      
      /* Search for the option in the packet */
      current_opt = opt;
      while (remaining_len >= sizeof (geneve_option_t))
        {
          u8 opt_len = geneve_opt_get_length (current_opt);
          
          /* Check if this option matches what we're looking for */
          if (clib_net_to_host_u16 (current_opt->opt_class) == opt_class &&
              current_opt->type == opt_type)
            {
              found = true;
              
              /* If we only care about presence, we're done */
              if (filter->option_filters[i].match_any)
                break;
                
              /* Check data content */
              if (filter->option_filters[i].data_len > 0)
                {
                  u8 check_len = filter->option_filters[i].data_len;
                  
                  /* Make sure we don't try to match more than the actual option data */
                  if (check_len > opt_len - 4) 
                    check_len = opt_len - 4;
                    
                  /* Skip matching if not enough data */
                  if (check_len <= 0)
                    {
                      found = false;
                      break;
                    }
                  
                  /* If we have a mask, apply it */
                  if (filter->option_filters[i].mask)
                    {
                      u8 j;
                      for (j = 0; j < check_len; j++)
                        {
                          u8 masked_data = current_opt->data[j] & filter->option_filters[i].mask[j];
                          u8 masked_filter = filter->option_filters[i].data[j] & filter->option_filters[i].mask[j];
                          
                          if (masked_data != masked_filter)
                            {
                              found = false;
                              break;
                            }
                        }
                    }
                  else
                    {
                      /* Exact match */
                      if (memcmp (current_opt->data, filter->option_filters[i].data, check_len) != 0)
                        found = false;
                    }
                }
                
              break;
            }
            
          /* Move to next option */
          if (opt_len < sizeof (geneve_option_t))
            break;  /* Malformed option */
            
          current_opt = (const geneve_option_t *)((u8 *)current_opt + opt_len);
          remaining_len -= opt_len;
        }
        
      /* If required option wasn't found, no match */
      if (!found)
        return DEST_INDEX_NONE;
    }
    
  /* All filters matched */
  return dest_index_match;
}

/* Check if the packet matches any global filter */
static u32
geneve_packet_matches_global_filter (gpcapng_main_t *gpm,
                       const u8 *outer_hdr, u32 outer_len,
                       const u8 *inner_hdr, u32 inner_len,
                       const geneve_header_t *geneve_hdr,
                       u32 geneve_header_len)
{
  int i;
  
  /* Check each global filter */
  for (i = 0; i < vec_len (gpm->global_filters); i++)
    {
      u32 dest_index = geneve_packet_matches_filter (gpm, 
                                      outer_hdr, outer_len,
                                      inner_hdr, inner_len,
                                      geneve_hdr, geneve_header_len,
                                      &gpm->global_filters[i]);
      if (dest_index != ~0)
        return dest_index;
    }
    
  return ~0;
}

/* Extract inner IP header from packet */
static u8 *
get_inner_ip_header (const geneve_header_t *geneve_hdr, u32 geneve_header_len,
                    u32 *inner_len)
{
  u8 *inner_hdr;
  
  /* Calculate inner header pointer */
  inner_hdr = (u8 *)(geneve_hdr) + geneve_header_len;
  
  /* Determine inner header length (simplified) */
  *inner_len = 60;  /* Conservative estimate */
  
  return inner_hdr;
}

// extern void process_http_gpcapng_retries(u16 worker_index);

/* Filter and capture Geneve packets */
static_always_inline uword gpcapng_node_common (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame, int is_output)
{

  gpcapng_main_t *gpm = get_gpcapng_main();
  u32 n_left_from, *from, *to_next;
  u32 n_left_to_next;
  u32 worker_index = vlib_get_thread_index ();
  u32 next_index;
  u32 n_captured = 0;
  u32 n_matched = 0;
  u32 n_dropped = 0;
  u32 n_not_ready = 0;
  int i;
  
  
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      
      while (n_left_from > 0 && n_left_to_next > 0)
        {
	  u64 packet_start = clib_cpu_time_now();
          vlib_buffer_t *b0;
          u32 bi0, sw_if_index0, next0 = 0;
          ip4_header_t *ip4;
          ip6_header_t *ip6;
          ethernet_header_t *ether;
          udp_header_t *udp;
          geneve_header_t *geneve;
          // bool is_ip6;
	  u32 destination_capture_index = ~0; /* do not capture */
          
          /* Prefetch next packet */
          if (n_left_from > 1)
            {
              vlib_buffer_t *b1;
              b1 = vlib_get_buffer (vm, from[1]);
              CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);
            }
          
          /* Get current packet */
          bi0 = from[0];
          from += 1;
          n_left_from -= 1;
          to_next[0] = bi0;
          to_next += 1;
          n_left_to_next -= 1;
          
          b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer (b0)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
	  vnet_feature_next (&next0, b0);
	  // clib_warning("CAPTURE is_out: %d", is_output);
          
          /* Skip interfaces where capture is not enabled, 
             unless global filters are defined */
          if ((sw_if_index0 >= vec_len (gpm->per_interface) ||
              !gpm->per_interface[sw_if_index0].capture_enabled) &&
              vec_len (gpm->global_filters) == 0)
            {
              goto packet_done;
            }
          
          /* Parse either IPv4 or IPv6 header */
          ether = vlib_buffer_get_current (b0);
          ip4 = (ip4_header_t *) (ether+1);
          
          const u8 *outer_header = (const u8 *)ip4;
          u32 outer_header_len = sizeof(ip4_header_t);
          
          if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
            {
/* IPv4 */
              // is_ip6 = false;
              outer_header_len = (ip4->ip_version_and_header_length & 0x0F) * 4;
              
              /* Skip non-UDP packets */
              if (ip4->protocol != IP_PROTOCOL_UDP)
                goto packet_done;
                
              /* UDP header follows IPv4 header */
              udp = (udp_header_t *)((u8 *)ip4 + outer_header_len);
	      outer_header_len += sizeof(udp_header_t);
            }
          else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60)
            {
              /* IPv6 */
              // is_ip6 = true;
              ip6 = (ip6_header_t *)ip4;
              outer_header = (const u8 *)ip6;
              outer_header_len = sizeof(ip6_header_t);
              
              /* Skip non-UDP packets */
              if (ip6->protocol != IP_PROTOCOL_UDP)
                goto packet_done;
                
              /* UDP header follows IPv6 header */
              udp = (udp_header_t *)(ip6 + 1);
	      outer_header_len += sizeof(udp_header_t);
            }
          else
            {
              /* Neither IPv4 nor IPv6 */
              goto packet_done;
            }
          
          /* Check UDP port for GENEVE */
          if (clib_net_to_host_u16 (udp->dst_port) != GENEVE_UDP_DST_PORT)
            goto packet_done;
            
          /* GENEVE header follows UDP header */
          geneve = (geneve_header_t *)(udp + 1);
          
          /* Calculate GENEVE header length including options */
          u32 geneve_opt_len = geneve_get_opt_len (geneve) * 4;
          u32 geneve_header_len = sizeof (geneve_header_t) + geneve_opt_len;
          
          /* Get inner header for inner 5-tuple filtering */
          u32 inner_header_len = 0;
          const u8 *inner_header = get_inner_ip_header(geneve, geneve_header_len, &inner_header_len);
          
          /* Check if packet matches any global filter */
          if (vec_len (gpm->global_filters) > 0) 
	    {
              destination_capture_index = geneve_packet_matches_global_filter (gpm, outer_header, outer_header_len,
                                    inner_header, inner_header_len,
                                    geneve, geneve_header_len);
            }
          
          /* Check if the packet matches any per-interface filter */
          if ((destination_capture_index == ~0) && 
              sw_if_index0 < vec_len (gpm->per_interface) && 
              gpm->per_interface[sw_if_index0].capture_enabled)
            {
              for (i = 0; i < vec_len (gpm->per_interface[sw_if_index0].filters); i++)
                {
                  u32 cap_index = geneve_packet_matches_filter (gpm, 
                                                 outer_header, outer_header_len,
                                                 inner_header, inner_header_len,
                                                 geneve, geneve_header_len,
                                                 &gpm->per_interface[sw_if_index0].filters[i]);
		  if (cap_index != ~0) {
		      destination_capture_index = cap_index;
                      break;
		  }
                }
            }

	  if (destination_capture_index != ~0) {
	    n_matched += 1;
	  }
            
          if (destination_capture_index < vec_len(gpm->worker_output_ctx[worker_index]) && destination_capture_index < vec_len(gpm->outputs)
	  && clib_bitmap_get(gpm->worker_output_ctx_is_ready[worker_index], destination_capture_index))
            {
              /* Capture the matching packet */
	      gpcapng_dest_t *output = &vec_elt(gpm->outputs, destination_capture_index);
	      void *output_ctx = gpm->worker_output_ctx[worker_index][destination_capture_index];
              u64 timestamp = vlib_time_now (vm) * 1000000; 
              u32 orig_len = vlib_buffer_length_in_chain (vm, b0);
              vlib_buffer_t *buf_iter = b0;
              
              /* Allocate a temporary buffer for the entire packet */
              u8 *packet_copy = 0;
              vec_validate (packet_copy, orig_len - 1);
              
              /* Copy packet data from buffer chain */
              u32 offset = 0;
              while (buf_iter)
                {
                  u32 len = buf_iter->current_length;
                  clib_memcpy_fast (packet_copy + offset, 
                                   vlib_buffer_get_current (buf_iter),
                                   len);
                  offset += len;
                  buf_iter = buf_iter->flags & VLIB_BUFFER_NEXT_PRESENT ?
                           vlib_get_buffer (vm, buf_iter->next_buffer) : 0;
                }

              gpcapng_worker_context_common_t *worker_common = output_ctx;
	      worker_common->packet_counter += 1;

              vec_add_pcapng_epb (&worker_common->buffer_vec, output_ctx, (sw_if_index0 << 1) | is_output,
                                         timestamp, orig_len,
                                         packet_copy, offset);

              /* Write packet data to PCAPng file */
              if (vec_len(worker_common->buffer_vec) > 4000) {
	        int res = output->chunk_write(output_ctx, worker_common->buffer_vec, vec_len(worker_common->buffer_vec));
		if (res == 0) {
	          worker_common->last_sent_packet_counter = worker_common->packet_counter;
	          worker_common->last_batch_sent_packet_counter = worker_common->packet_counter;
		} else {
		   worker_common->last_sent_packet_counter = worker_common->last_batch_sent_packet_counter;
		   n_dropped += 1;
		}
		vec_reset_length(worker_common->buffer_vec);
	      } else {
	          /* optimistically count as sent */
	          worker_common->last_sent_packet_counter = worker_common->packet_counter;
	      }
	
                                         
              vec_free (packet_copy);
	      n_captured += 1;
            }
	    else {
	       n_not_ready += 1;
	    }
packet_done:
            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              pcapng_capture_trace_t *t =
              vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
	      t->elapsed = clib_cpu_time_now() - packet_start;
	      t->dest_index = destination_capture_index;
            }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, PCAPNG_CAPTURE_ERROR_MATCHED, n_matched);
  vlib_node_increment_counter (vm, node->node_index, PCAPNG_CAPTURE_ERROR_CAPTURED, n_captured);
  vlib_node_increment_counter (vm, node->node_index, PCAPNG_CAPTURE_ERROR_DROPPED, n_dropped);
  vlib_node_increment_counter (vm, node->node_index, PCAPNG_CAPTURE_ERROR_NOT_READY, n_not_ready);

  /* Process HTTP retries for this worker - done in a separate node*/
  // process_http_gpcapng_retries(vlib_get_thread_index());

  return frame->n_vectors;
}

VLIB_NODE_FN (gpcapng_node_out) (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame)
{
   return gpcapng_node_common(vm, node, frame, 1);
}

VLIB_NODE_FN (gpcapng_node_in) (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame)
{
   return gpcapng_node_common(vm, node, frame, 0);
}

