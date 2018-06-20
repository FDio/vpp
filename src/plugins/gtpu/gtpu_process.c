/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <svm/ssvm.h>
#include <vlibmemory/socket_client.h>
#include <vlibapi/vat_helper_macros.h>
#include <vat/vat.h>
#include <gtpu/gtpu.h>
#include <gtpu/gtpu_msg_enum.h>
#include <vnet/lisp-cp/packets.h>

/* define message structures */
#define vl_typedefs
#include <gtpu/gtpu.api.h>
#undef vl_typedefs

vlib_node_registration_t gtpu_process_node;
vlib_node_registration_t gtpu_echo_node;

#define GTPU_ECHO_REQUEST_INTERVAL      60  /* 60 s */
#define GTPU_T3_RESPONSE                3   /* 3s */
#define GTPU_N3_REQUESTS                5

#define foreach_ip4_offset  _(0) _(1) _(2) _(3)
#define foreach_ip6_offset  \
    _(0) _(1) _(2) _(3) _(4) _(5) _(6) _(7) _(8) _(9) _(10) _(11) _(12) _(13) _(14) _(15)


static void 
gtpu_error_notify(u8 error_code, u32 teid, ip46_address_t *dst)
{
    gtpu_main_t *gtm = &gtpu_main;
    vl_api_registration_t *vl_reg;
    vl_api_gtpu_error_indication_details_t *mp;
    vpe_client_registration_t *client;
    gtpu_client_registration_t *registrations = &gtm->registrations;

    mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
    memset (mp, 0, sizeof (*mp));

    mp->_vl_msg_id = ntohs (VL_API_GTPU_ERROR_INDICATION_DETAILS);

    mp->teid = teid;
    mp->code = error_code;
    
#define _(offs) mp->dst_address[offs] = dst->as_u8[offs];
    if (ip46_address_is_ip4 (dst))
    {
        foreach_ip4_offset
    }
    else
    {
        foreach_ip6_offset
    }
#undef _

    /* *INDENT-OFF* */
    pool_foreach (client, registrations->clients, (
                        {
                        vl_reg = vl_api_client_index_to_registration (client->client_index);
                        vl_api_send_msg (vl_reg, (u8 *)mp);
                        }
                ));
    /* *INDENT-ON* */
}

static u8 
gtpu_path_error_check(vlib_main_t *vm, gtpu_path_t *path)
{
    f64 now = vlib_time_now (vm);
    
    /* After retransmitting to N3_REQUESTS, wait for T3_RESPONSE interval */
    if (path->re_echo_request >= GTPU_N3_REQUESTS 
        && GTPU_T3_RESPONSE <= now - path->last_send_request_time)
    {
        if (!path->path_error)
        {
            gtpu_error_notify(GTPU_EVENT_PATH_ERROR, 0, &path->dst);
            path->path_error = 1;
        }
        return 1;
    }

    return 0;
}

static void
gtpu_re_echo_request_check(vlib_main_t *vm, gtpu_path_t *path)
{
    f64 now = vlib_time_now (vm);

    /* No message was received for a long time since the last time the packet was sent */
    if (path->last_receive_response_time < path->last_send_request_time
        && now - path->last_send_request_time >= GTPU_T3_RESPONSE)
    {
        /* retransmit */
        if (!path->re_echo_request)
        {
            //clib_warning ("Retransmit because timeout.");
            path->re_echo_request = 1;

            /* send echo request packet right now */
            path->echo_request = 1;

            path->counter.re_echo_request_count += 1;
        }
    }
}

static u8 gtpu_echo_request_check(vlib_main_t *vm, gtpu_path_t *path)
{
    f64 now = vlib_time_now (vm);

    if ((path->re_echo_request && (GTPU_T3_RESPONSE <= now - path->last_send_request_time))
        || (!path->re_echo_request && (GTPU_ECHO_REQUEST_INTERVAL <= now - path->last_send_request_time)))
    {
        if (!path->echo_request)
        {
            path->re_echo_request = path->re_echo_request ? path->re_echo_request + 1 : 0;
        }

        /* Cannot retransmit exceed 3 */
        if (path->re_echo_request <= GTPU_N3_REQUESTS)
        {
            path->echo_request = 1;
        }
    }

    if (path->echo_request)
    {
        return 1;
    }

    return 0;
}

static u8 gtpu_event_process(vlib_main_t * vm, uword event_type, uword *event_data)
{
    gtpu_main_t *gtm = &gtpu_main;
    u32 bi;
    vlib_buffer_t *buffer;
    ip4_header_t *ip4;
    ip6_header_t *ip6;
    gtpu4_tunnel_key_t key4;
    gtpu6_tunnel_key_t key6;
    uword *p;
    gtpu_path_t *path;
    gtpu_header_t * gtpu;

    if (!event_data)
    {
        return 0;
    }
    bi = *event_data;
    
    switch (event_type)
    {
        case GTPU_EVENT_TYPE_FAST_POLLING_START:
            return 0;
        case GTPU_EVENT_TYPE_ECHO_RESPONSE_IP4:
        case GTPU_EVENT_TYPE_ECHO_RESPONSE_IP6:
            {
                buffer = vlib_get_buffer (vm, bi);
                
                if (GTPU_EVENT_TYPE_ECHO_RESPONSE_IP4 == event_type) /* ip4 */
                {
                    ip4 = vlib_buffer_get_current(buffer);
                    key4.src = ip4->src_address.as_u32;
                    key4.teid = 0;
                    
                    p = hash_get (gtm->path_manage.gtpu4_path_by_key, key4.as_u64);
                }
                else        /* ip6 */
                {
                    ip6 = vlib_buffer_get_current (buffer);
                    key6.src.as_u64[0] = ip6->src_address.as_u64[0];
                    key6.src.as_u64[1] = ip6->src_address.as_u64[1];
                    key6.teid = 0;

                    p = hash_get_mem (gtm->path_manage.gtpu6_path_by_key, &key6);
                }
                
                if (!p)
                {
                    clib_warning ("BUG: Has no this path");
                    goto out;
                }

                path = pool_elt_at_index (gtm->path_manage.paths, p[0]);
                path->last_receive_response_time = vlib_time_now (vm);
                path->re_echo_request = 0;
                path->path_error = 0;
            }
            break;
        case GTPU_EVENT_TYPE_ERROR_INDICATE_IP4:
        case GTPU_EVENT_TYPE_ERROR_INDICATE_IP6:
        case GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP4:
        case GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP6:
        case GTPU_EVENT_TYPE_VERSION_NOT_SUPPORTED_IP4:
        case GTPU_EVENT_TYPE_VERSION_NOT_SUPPORTED_IP6:
            {
                u8 error = 0;
                ip46_address_t dst;
                
                buffer = vlib_get_buffer (vm, bi);
                gtpu = vlib_buffer_get_current (buffer);
                
                if (GTPU_EVENT_TYPE_ERROR_INDICATE_IP4 == event_type
                    || GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP4 == event_type
                    || GTPU_EVENT_TYPE_VERSION_NOT_SUPPORTED_IP4 == event_type) /* ip4 */
                {
                    ip4 = vlib_buffer_get_current(buffer);                    
                    dst = to_ip46(0, ip4->src_address.as_u8);
                    error = (GTPU_EVENT_TYPE_ERROR_INDICATE_IP4 == event_type ? GTPU_EVENT_RECEIVE_ERROR_INDICATION : 
                                (GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP4 == event_type ? GTPU_EVENT_NO_SUCH_TUNNEL : GTPU_EVENT_VERSION_NOT_SUPPORTED));
                }
                else /* ip6 */
                {
                    ip6 = vlib_buffer_get_current (buffer);
                    dst = to_ip46(1, ip6->src_address.as_u8);
                    error = (GTPU_EVENT_TYPE_ERROR_INDICATE_IP6 == event_type ? GTPU_EVENT_RECEIVE_ERROR_INDICATION : 
                                (GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP6 == event_type ? GTPU_EVENT_NO_SUCH_TUNNEL : GTPU_EVENT_VERSION_NOT_SUPPORTED));
                }
                
                gtpu_error_notify(error, gtpu->teid, &dst);
            }
            break;
        default:
            clib_warning ("BUG: Unknow event type 0x%wx", event_type);
            break;
    }

out:
    vlib_buffer_free_one(vm, bi);
    return 1;
}


static uword
gtpu_process (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
    gtpu_main_t *gtm = &gtpu_main;
    gtpu_path_t *path;
    uword event_type, *event_data = 0;
    u8 need_transmit = 0, ret = 0;
    f64 timeout = 0;
#define FAST_POLLING 3.0
#define SLOW_POLLING 60.0

    while (1)
    {
        if (pool_elts (gtm->path_manage.paths))
        {
            timeout = (timeout > 0 && timeout <= FAST_POLLING) ? timeout : FAST_POLLING;
        }
        else
        {
            timeout = SLOW_POLLING;
        }
        timeout = vlib_process_wait_for_event_or_clock(vm, timeout);
        event_type = vlib_process_get_events (vm, (uword **) & event_data);
        switch (event_type)
        {
            case ~0:		/* timeout */
              break;

            default:        /* event */
              ret = gtpu_event_process(vm, event_type, event_data);
              if (event_data)
              {
                  _vec_len (event_data) = 0;
              }
              if (ret)
              {
                  continue;
              }
        }

        timeout = 0;

        /* *INDENT-OFF* */
        pool_foreach (path, gtm->path_manage.paths, ({
                        if (!gtpu_path_error_check (vm, path))
                          {
                            gtpu_re_echo_request_check (vm, path);
                            need_transmit += gtpu_echo_request_check (vm, path);
                          }
                }));
        /* *INDENT-ON* */
        
        if (need_transmit)
        {
            vlib_main_t *work_vm = vm;
            if (vlib_num_workers ())
                work_vm = vlib_get_worker_vlib_main (0);
            
            vlib_node_set_state (work_vm, gtpu_echo_node.index, VLIB_NODE_STATE_POLLING);
            need_transmit = 0;
        }
    }

    return 0;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gtpu_process_node) =
{
  .function = gtpu_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "gtpu_process",
};
/* *INDENT-ON* */


static void 
gtpu_echo_request_send(vlib_main_t *vm, gtpu_path_t *path)
{
    ip4_header_t *ip4;
    ip6_header_t *ip6;
    udp_header_t *udp;
    gtpu_header_t *gtpu;
    u32 buffer_id = 0;
    vlib_buffer_t *buffer;
    vlib_frame_t *frame;
    u32 *to_next;
    vlib_buffer_free_list_t *fl;
    u8 is_ip4 = 0;
    
    if (vlib_buffer_alloc (vm, &buffer_id, 1) != 1)
    {
        clib_warning ("BUG: Alloc echo request buffer failed");
        return;
    }

    buffer = vlib_get_buffer (vm, buffer_id);
    fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
    vlib_buffer_init_for_free_list (buffer, fl);
    VLIB_BUFFER_TRACE_TRAJECTORY_INIT (buffer);

    /* Fix ip header */
    if (ip46_address_is_ip4 (&path->src)) /* ip4 */
    {
        ip4 = vlib_buffer_get_current (buffer);
        ip4->ip_version_and_header_length = 0x45;
        ip4->ttl = 254;
        ip4->protocol = IP_PROTOCOL_UDP;
        ip4->src_address = path->src.ip4;
        ip4->dst_address = path->dst.ip4;
        ip4->length = clib_host_to_net_u16(sizeof(*ip4) + sizeof(*udp) + (sizeof(*gtpu) - 4)/* Now only support 8-byte gtpu header. TBD */);
        ip4->checksum = ip4_header_checksum (ip4);

        buffer->current_length = sizeof(*ip4) + sizeof(*udp) + (sizeof(*gtpu) - 4);/* Now only support 8-byte gtpu header. TBD */

        udp = (udp_header_t *)(ip4 + 1);
        udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);
        udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);
        udp->checksum = 0;
        is_ip4 = 1;
    }
    else /* ip6 */
    {
        ip6 = vlib_buffer_get_current (buffer);
        ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (6 << 28);
        ip6->hop_limit = 255;
        ip6->protocol = IP_PROTOCOL_UDP;
        ip6->src_address = path->src.ip6;
        ip6->dst_address = path->dst.ip6;
        ip6->payload_length = clib_host_to_net_u16(sizeof(*udp) + (sizeof(*gtpu) - 4)/* Now only support 8-byte gtpu header. TBD */);

        buffer->current_length = sizeof(*ip6) + sizeof(*udp) + (sizeof(*gtpu) - 4);/* Now only support 8-byte gtpu header. TBD */
        
        udp = (udp_header_t *)(ip6 + 1);
        udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU6);
        udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU6);
        udp->checksum = 0;
    }

    /* Fix UDP length */
    udp->length = clib_host_to_net_u16(sizeof(*udp) + (sizeof(*gtpu) - 4)/* Now only support 8-byte gtpu header. TBD */);
    
    /* Fix GTPU */
    gtpu = (gtpu_header_t *)(udp + 1);
    gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
    gtpu->type = GTPU_TYPE_ECHO_REQUEST;   /* set the message type with echo request */
    gtpu->teid = 0;                       /* the teid of echo request packets must be 0 */
    gtpu->length = clib_host_to_net_u16((sizeof(*gtpu) - 4)/* Now only support 8-byte gtpu header. TBD */);
    
    /* Enqueue the packet right now */
    if (is_ip4) /* ip4 */
    {
        frame = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
        to_next = vlib_frame_vector_args (frame);
        to_next[0] = buffer_id;
        frame->n_vectors = 1;
        vlib_put_frame_to_node (vm, ip4_lookup_node.index, frame);
    }
    else  /* ip6 */
    {
        frame = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
        to_next = vlib_frame_vector_args (frame);
        to_next[0] = buffer_id;
        frame->n_vectors = 1;
        vlib_put_frame_to_node (vm, ip6_lookup_node.index, frame);
    }
}


static uword
gtpu_echo_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
    gtpu_main_t *gtm = &gtpu_main;
    gtpu_path_t *path;

    /* *INDENT-OFF* */
    pool_foreach (path, gtm->path_manage.paths, ({
		        /* if need to send echo request packet */
                        if (path->echo_request)
                          {
    		            gtpu_echo_request_send (vm, path);
                            path->last_send_request_time = vlib_time_now (vm);
                            path->echo_request = 0;
                            path->counter.echo_request_count += 1;
                          }
                }));
    /* *INDENT-ON* */
    
    vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);

    return 0;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gtpu_echo_node) =
{
  .function = gtpu_echo_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "gtpu_echo_input",
  /* Node will be left disabled until need to send echo request packets. */
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */


