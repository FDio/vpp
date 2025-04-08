
#include <vnet/buffer.h>
#include <vnet/ip/isft_packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vlib/main.h>

void determine_node_type(vlib_main_t * vm, vlib_buffer_t *b0, ip6_header_t *ip0) 
{
    u32 i;
    //u32 ip_version, traffic_class;
    u32 tmp_flow_label;
    i = clib_net_to_host_u32 (ip0->ip_version_traffic_class_and_flow_label);
    //ip_version = (i >> 28);
    //traffic_class = (i >> 20) & 0xff;
    tmp_flow_label = i & pow2_mask (20);

    u8 * isft_udp_pak = NULL;
    u16 isft_len = sizeof(ip4_header_t) + sizeof(udp_header_t) + sizeof(isft_hdr_t) + sizeof(isft_MD_t);
    vec_validate (isft_udp_pak, isft_len);
    ip4_address_t src = {.data = { 192, 168, 6, 2 }};
    ip4_address_t collector_IPv6_Addr = {.data = { 192, 168, 6, 1 }};
    u16 src_port = 5000; 
    u16 dst_port = 6000;
	
	  vlib_cli_output(vm, "flow label: %u", tmp_flow_label);
	  if (1) 
      {
        create_isft_ipv4_udp_pak (vm, b0, isft_udp_pak, src, collector_IPv6_Addr, src_port, dst_port);
		    return; 
	    }
}

void generate_isft_header(vlib_main_t *vm, isft_hdr_t *isft_hdr, u8 namespace_id, 
     u8 isft_option_type, u8 template, u32 flow_id, u32 sequence_number)
{
    //isft_hdr_t *isft_hdr0 = NULL;
    u32 hdr0 = 0;
    //u8 namespace_id0 = namespace_id;
    //u8 isft_option_type0 = isft_option_type;
    //u8 template0 = template;
    //u32 flow_id0 = flow_id;
    hdr0 |= ((namespace_id & 0x7F) << 25);     
    hdr0 |= ((isft_option_type & 0x3) << 23); 
    hdr0 |= ((template & 0x7) << 20);       
    hdr0 |= (flow_id & 0xFFFFF);      

    //isft_hdr0->namespaceid_isftoptiontype_template_flowid = hdr0;
    //isft_hdr0->sequence_number = 0x8888;

    isft_hdr->namespaceid_isftoptiontype_template_flowid = clib_host_to_net_u32(hdr0);
    isft_hdr->sequence_number = clib_host_to_net_u32(0x8888);
    vlib_cli_output(vm, "generate_isft_header: %x\n", isft_hdr->sequence_number);
    show_isft_hdr(vm, isft_hdr);
}

void extract_isft_header(vlib_main_t *vm, isft_hdr_t *isft_hdr) 
{
    //isft_hdr_t *isft_hdr0 = NULL;
    u32 hdr0 = 0;
    u8 namespace_id = 0x3;
    u8 isft_option_type = 0x1;
    u8 template = 0x7;
    u32 flow_id = 0x666;
    hdr0 |= ((namespace_id & 0x7F) << 25);     
    hdr0 |= ((isft_option_type & 0x3) << 23); 
    hdr0 |= ((template & 0x7) << 20);       
    hdr0 |= (flow_id & 0xFFFFF);      

    //isft_hdr0->namespaceid_isftoptiontype_template_flowid = hdr0;
    //isft_hdr0->sequence_number = 0x8888;

    isft_hdr->namespaceid_isftoptiontype_template_flowid = clib_host_to_net_u32(hdr0);
    isft_hdr->sequence_number = clib_host_to_net_u32(0x8888);
    vlib_cli_output(vm, "generate_isft_header: %x\n", isft_hdr->sequence_number);
    show_isft_hdr(vm, isft_hdr);
}

static clib_error_t *
set_isft_hdr_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  u8 namespace_id = 0;
  u8 isft_option_type = 0;
  u8 template = 0;
  u32 flow_id = 0;
  u32 sequence_number = 0;
  isft_hdr_t *isft_hdr = malloc(sizeof(isft_hdr_t));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "namespace_id 0x%x", &namespace_id));
      else if (unformat (input, "isft_option_type %x", &isft_option_type));
      else if (unformat (input, "template %x", &template));
      else if (unformat (input, "flow_id 0x%x", &flow_id));
      else if (unformat (input, "sequence_number 0x%x", &sequence_number));
      else
	break;
    }

      u8 *s = 0;
      s = format (s, "\nset_isft_hdr_command_fn!\n");
      s = format (s, "namespace_id : %x\n", namespace_id);
      s = format (s, "isft_option_type : %x\n", isft_option_type);
      s = format (s, "template : %x\n", template);
      s = format (s, "flow_id : %x\n", flow_id);
      s = format (s, "sequence_number : %x\n", sequence_number);
      vlib_cli_output (vm, "%v", s);
      vec_free (s);

    generate_isft_header(vm, isft_hdr, namespace_id, 
         isft_option_type, template, flow_id, sequence_number);

  return 0;
}

VLIB_CLI_COMMAND (set_isft_hdr_command, static) =
{
.path = "set isft-hdr data",
.short_help = "set isft-hdr \
             namespace_id <nn> isft_option_type <1|2|3> template <0|1|2|3|4|5|6|7> \
             flow_id <nn> sequence_number <sequence_number in hex>",
.function = set_isft_hdr_command_fn,
};

void show_isft_hdr (vlib_main_t * vm, isft_hdr_t *isft_hdr)
{
    u8 *s = 0;
    u32 namespaceid_isftoptiontype_template_flowid;
    u32 sequence_number;
    namespaceid_isftoptiontype_template_flowid = clib_net_to_host_u32 (isft_hdr->namespaceid_isftoptiontype_template_flowid);
    sequence_number = clib_net_to_host_u32 (isft_hdr->sequence_number);

    s = format (s, "show_isft_hdr generate ISFT Header:\n");
    s = format (s, "Namespace ID: 0x%x\n", namespaceid_isftoptiontype_template_flowid >> 25);
    s = format (s, "ISFT Option Type: 0x%x\n", (namespaceid_isftoptiontype_template_flowid >> 23) & 0x3);
    s = format (s, "Template: 0x%x\n", (namespaceid_isftoptiontype_template_flowid >> 20) & 0x7);
    s = format (s, "Flow ID: 0x%x\n", (namespaceid_isftoptiontype_template_flowid) & 0xFFFFF);
    s = format (s, "Sequence Number: 0x%x\n", sequence_number);
    
    s = format (s, "\n");

    vlib_cli_output (vm, "%v", s);
    vec_free (s);
}

void collect_isft_metadata(vlib_main_t *vm, vlib_buffer_t *b0, isft_hdr_t *isft_hdr, isft_MD_t *isft_md) 
{
  u8 template = 0;
  u32 namespaceid_isftoptiontype_template_flowid = clib_net_to_host_u32 (isft_hdr->namespaceid_isftoptiontype_template_flowid);
  vlib_cli_output(vm, "collect_isft_metadata0 isft_hdr1 : 0x%x\n", namespaceid_isftoptiontype_template_flowid);
  template =  (namespaceid_isftoptiontype_template_flowid >> 20) & 0xFF ;
  vlib_cli_output(vm, "collect_isft_metadata template : 0x%x\n", template);

  u16 in_eg_re = 0;
  u8 ingress_port_id = get_ingress_port_id(vm, b0);//no problem
  u8 egress_port_id = get_egress_port_id(vm, b0);//have problem,quan1
  u16 reserved = 0x0;
  in_eg_re |= ((ingress_port_id & 0x7) << 13);     
  in_eg_re |= ((egress_port_id & 0x7) << 10); 
  in_eg_re |= (reserved & 0x3FF);       
  isft_md->node_id = clib_host_to_net_u16(0x01 & 0xFFFF);
  isft_md->in_eg_re = clib_host_to_net_u16(in_eg_re);

  if (template & 0x1)  
  {
    isft_md->in_timestamp = get_in_timestamp(vm, b0);
    isft_md->out_timestamp = get_eg_timestamp(vm);//may no problem
    isft_md->forwarding_delay = clib_host_to_net_u32(0x07 & 0xFFFFFFFF);
  }

  if (template & 0x4)   
  {
    isft_md->queue_depth = clib_host_to_net_u16(0x08 & 0xFFFF);
    isft_md->buffer_occupancy = get_buffer_occupancy(vm, b0);//3f90 fixed

  }
  
  //isft_md->ingress_port_id = (0x02 & 0x7);
  //isft_md->egress_port_id = (0x03 & 0x7);
  //isft_md->reserved = (0x04 & 0x3FF);
  
  isft_md->checksum_complement = clib_host_to_net_u32(0x0a & 0xFFFFFFFF);
  vlib_cli_output(vm, "collect_isft_metadata: %x\n", in_eg_re);//2800
}

u8 get_ingress_port_id(vlib_main_t *vm, vlib_buffer_t * b0)
{
    u8 ingress_port_id = 0x0;

    ingress_port_id = (u8) (vnet_buffer (b0)->sw_if_index[VLIB_RX] & 0xFF); 
    vlib_cli_output(vm, "get_ingress_port_id: %x\n", ingress_port_id);
    return ingress_port_id;
}

u8 get_egress_port_id(vlib_main_t *vm, vlib_buffer_t * b0)
{
    u8 egress_port_id = 0x0;
    u32 adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
    ip_adjacency_t *adj = adj_get (adj_index);

    egress_port_id = (adj->rewrite_header.sw_if_index & 0xFF);
    vlib_cli_output(vm, "get_egress_port_id: %x\n", egress_port_id);
    return egress_port_id;
}

u32 get_in_timestamp(vlib_main_t *vm, vlib_buffer_t * b0) 
{
    u32 time_in;
    time_in = vnet_buffer2 (b0)->unused[4];

    vlib_cli_output(vm, "get_in_timestamp: 0x%x\n", time_in);
    time_in = clib_host_to_net_u32 (time_in);
    return time_in; 
}

u32 get_eg_timestamp(vlib_main_t *vm) 
{
    isft_time_u64_t time_u64;
    time_u64.ts_u64 = 0;
	  f64 time_f64 = (vlib_time_now (vm));
    vlib_cli_output(vm, "get_current_timestamp: %x\n", time_f64);

	  time_u64.ts_u64 = time_f64 * isft_tsp_mul[2];
	  time_u64.ts_u32[0] = clib_host_to_net_u32 (time_u64.ts_u32[0]);
    return time_u64.ts_u32[0]; 
}

u16 get_buffer_occupancy(vlib_main_t *vm, vlib_buffer_t * b0) 
{
    u16 buffer_occupancy = 0x0;
    // 获取缓冲区占用
    vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, b0->buffer_pool_index);
      u32 buff_avail = 0;
      if(bp)
      {
        buff_avail = bp->n_avail;
      }
      buffer_occupancy = clib_host_to_net_u16(buff_avail);
    vlib_cli_output(vm, "get_buffer_occupancy: %x\n", buffer_occupancy);
    
    return buffer_occupancy;
}

double get_buffer_occupancy_percent(vlib_main_t * vm, vlib_buffer_t *b0) 
{
    u16 max_size = vlib_buffer_get_default_data_size(vm); // 获取默认缓冲区大小
    return ((double)b0->current_length / max_size) * 100.0;
}

void create_isft_ipv4_udp_pak (vlib_main_t *vm, vlib_buffer_t *b0, u8 * isft_udp_pak,	
			 ip4_address_t src, ip4_address_t collector_IPv6_Addr,
			 u16 src_port, u16 dst_port)
{
  ip4_header_t *ip0;
  udp_header_t *udp0;
  isft_hdr_t *isft0;
  isft_MD_t *md0;
  u16  ip0_payload_len = 0, udp_len = 0;
  u16 md_len = sizeof (isft_MD_t);
  u16 isft_hdr_len = sizeof (isft_hdr_t) ;
  //u8 *current = NULL;
  
  vlib_cli_output(vm, "create_isft_ipv4_udp_pak: %u\n", src_port);

  ip0 = (ip4_header_t *) isft_udp_pak;

  ip0->ip_version_and_header_length = 0x45;
  ip0->tos = 0;
  ip0->fragment_id = 0;
  ip0->flags_and_fragment_offset = 0;
  ip0->ttl = 255;
  ip0->protocol = IP_PROTOCOL_UDP;
  ip0->checksum = 0;
  ip0->src_address = src;
  ip0->dst_address = collector_IPv6_Addr;

  udp0 = (udp_header_t *) (ip0 + 1);

  udp0->src_port = clib_host_to_net_u16 (src_port);
  udp0->dst_port = clib_host_to_net_u16 (dst_port);

  udp_len = sizeof(udp_header_t) + isft_hdr_len + md_len;
  udp0->length = clib_host_to_net_u16 (udp_len);
  udp0->checksum = 0;
  

  /* Populate isft header */
  isft0 = (isft_hdr_t *) (udp0 + 1);
  //isft0 = extract_isft_header(isft0, const flow_key_t *flow_key, u32 namespaceid_flags_isfttracetype_flowid)
  extract_isft_header(vm, isft0);
  //isft0->namespace_id = 0x01;
  //isft0->template = 001;
  //isft0->isft_option_type = 01;
  //isft0->flow_id = 0x666;
  //isft0->sequence_number = 0x8888;

  
  md0 = (isft_MD_t *) (isft0 + 1);
  collect_isft_metadata(vm, b0, isft0, md0);
  /*
  md0->node_id = 0x01;
  md0->ingress_port_id = 0x02;
  md0->egress_port_id = 0x03;
  md0->reserved = 0x04;
  md0->in_timestamp = 0x05;
  md0->out_timestamp = 0x06;
  md0->forwarding_delay = 0x07;
  md0->queue_depth = 0x08;
  md0->buffer_occupancy = 0x09;
  md0->checksum_complement = 0x0a;*/

  /* Calculate total length and set it in ip6 header */
  ip0_payload_len = udp_len;
  //ip0_len = (len > ip0_len) ? len : ip0_len;
  ip0->length = clib_host_to_net_u16 (sizeof (ip4_header_t) + ip0_payload_len);

  u16 packet_len = ip0_payload_len + sizeof (ip4_header_t);

  send_ipv4_packet_to_next_node_with_isft (vm, isft_udp_pak, packet_len);

  //return(packet_len);
}

void send_ipv4_packet_to_next_node_with_isft (vlib_main_t *vm, u8 *packet, u16 packet_len)
{
    u32 *buffers = NULL;
    vlib_buffer_t *b0;
    u32 *to_next;
    vlib_frame_t *nf = 0;
    vlib_node_t *next_node;
    
    vlib_cli_output(vm, "send_ipv4_packet_to_next_node_with_isft: %u\n", packet_len);

    next_node = vlib_get_node_by_name(vm, (u8 *) "ip4-lookup");
    nf = vlib_get_frame_to_node(vm, next_node->index);
    nf->n_vectors = 0;
    to_next = vlib_frame_vector_args(nf);

    vec_validate(buffers, 0);  
    if (vlib_buffer_alloc(vm, buffers,  vec_len (buffers)) != 1)
    {
        // Error
        return;
    }

    b0 = vlib_get_buffer(vm, buffers[0]);

    clib_memcpy_fast(b0->data, packet, packet_len);
    b0->current_data = 0;
    b0->current_length = packet_len;
    b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

    vnet_buffer(b0)->sw_if_index[VLIB_RX] = 0;  
    vnet_buffer(b0)->sw_if_index[VLIB_TX] = ~0; 

    // ：IPv6 -> UDP -> IOAM -> Payload
    ip4_header_t *ip4 = vlib_buffer_get_current(b0);
    udp_header_t *udp = (udp_header_t *)((u8 *)ip4 + sizeof(ip4_header_t));
    //isft_hdr_t *isft = (isft_hdr_t *)((u8 *)udp + sizeof(udp_header_t));

    //int bogus;
    udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip4);
    //ASSERT(bogus == 0);
    if (udp->checksum == 0)
        udp->checksum = 0xffff;  
        
    vlib_cli_output(vm, "udp->checksum: %x\n", udp->checksum);

    *to_next = buffers[0];
    nf->n_vectors++;
    to_next++;

    vlib_put_frame_to_node(vm, next_node->index, nf);
}

void create_isft_ipv6_udp_pak (vlib_main_t *vm, vlib_buffer_t *b0, u8 * isft_udp_pak,	
			 ip6_address_t src, ip6_address_t collector_IPv6_Addr,
			 u16 src_port, u16 dst_port)
{
  ip6_header_t *ip0;
  udp_header_t *udp0;
  isft_hdr_t *isft0;
  isft_MD_t *md0;
  u16  ip0_payload_len = 0, udp_len = 0;
  u16 md_len = sizeof (isft_MD_t);
  u16 isft_hdr_len = sizeof (isft_hdr_t) ;
  //u8 *current = NULL;

  ip0 = (ip6_header_t *) isft_udp_pak;

  ip0->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);

  ip0->protocol = IP_PROTOCOL_UDP;
  ip0->hop_limit = 255;

  ip0->src_address = src;
  ip0->dst_address = collector_IPv6_Addr;

  udp0 = (udp_header_t *) (ip0 + 1);

  udp0->src_port = clib_host_to_net_u16 (src_port);
  udp0->dst_port = clib_host_to_net_u16 (dst_port);

  udp_len = sizeof(udp_header_t) + isft_hdr_len + md_len;
  udp0->length = clib_host_to_net_u16 (udp_len);
  udp0->checksum = 0;

  /* Populate isft header */
  isft0 = (isft_hdr_t *) (udp0 + 1);
  //isft0 = generate_isft_header(isft0, const flow_key_t *flow_key, u32 namespaceid_flags_isfttracetype_flowid)
  isft0->namespaceid_isftoptiontype_template_flowid = 0x1;
  //isft0->namespace_id = 0x1;
  //isft0->isft_option_type = 0x1;
  //isft0->template = 0x1;
  //isft0->flow_id = 0x666;
  isft0->sequence_number = 0x8888;

  md0 = (isft_MD_t *) (isft0 + 1);
  collect_isft_metadata(vm, b0, isft0, md0);
  /*
  md0->node_id = 0x01;
  md0->ingress_port_id = 0x02;
  md0->egress_port_id = 0x03;
  md0->reserved = 0x04;
  md0->in_timestamp = 0x05;
  md0->out_timestamp = 0x06;
  md0->forwarding_delay = 0x07;
  md0->queue_depth = 0x08;
  md0->buffer_occupancy = 0x09;
  md0->checksum_complement = 0x0a;*/

  /* Calculate total length and set it in ip6 header */
  ip0_payload_len = udp_len;
  //ip0_len = (len > ip0_len) ? len : ip0_len;
  ip0->payload_length = clib_host_to_net_u16 (ip0_payload_len);

  u16 packet_len = ip0_payload_len + sizeof (ip6_header_t);

  send_ipv6_packet_to_next_node_with_isft (vm, isft_udp_pak, packet_len);

  //return(packet_len);
}

void send_ipv6_packet_to_next_node_with_isft (vlib_main_t *vm, u8 *packet, u16 packet_len)
{
    u32 *buffers = NULL;
    vlib_buffer_t *b0;
    u32 *to_next;
    vlib_frame_t *nf = 0;
    vlib_node_t *next_node;
    
    vlib_cli_output(vm, "send_packet_to_next_node_with_isft: %u\n", packet_len);

    next_node = vlib_get_node_by_name(vm, (u8 *) "ip4-lookup");
    nf = vlib_get_frame_to_node(vm, next_node->index);
    nf->n_vectors = 0;
    to_next = vlib_frame_vector_args(nf);

    vec_validate(buffers, 0);  
    if (vlib_buffer_alloc(vm, buffers,  vec_len (buffers)) != 1)
    {
        // Error
        return;
    }

    b0 = vlib_get_buffer(vm, buffers[0]);

    clib_memcpy_fast(b0->data, packet, packet_len);
    b0->current_data = 0;
    b0->current_length = packet_len;
    b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

    vnet_buffer(b0)->sw_if_index[VLIB_RX] = 0;  
    vnet_buffer(b0)->sw_if_index[VLIB_TX] = ~0; 

    // ：IPv6 -> UDP -> IOAM -> Payload
    ip6_header_t *ip6 = vlib_buffer_get_current(b0);
    udp_header_t *udp = (udp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
    //isft_hdr_t *isft = (isft_hdr_t *)((u8 *)udp + sizeof(udp_header_t));

    int bogus;
    udp->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b0, ip6, &bogus);
    ASSERT(bogus == 0);
    if (udp->checksum == 0)
        udp->checksum = 0xffff;  
        
    vlib_cli_output(vm, "udp->checksum: %x\n", udp->checksum);

    *to_next = buffers[0];
    nf->n_vectors++;
    to_next++;

    vlib_put_frame_to_node(vm, next_node->index, nf);
}

