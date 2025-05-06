
#include <vnet/vnet.h>
#include <vlib/vlib.h>

#include "gpcapng.h"
#include <time.h>

/* Define PCAPng format related constants */
#define PCAPNG_BLOCK_TYPE_SHB 0x0A0D0D0A /* Section Header Block */
#define PCAPNG_BLOCK_TYPE_IDB 0x00000001 /* Interface Description Block */
#define PCAPNG_BLOCK_TYPE_EPB 0x00000006 /* Enhanced Packet Block */
// #define PCAPNG_BLOCK_TYPE_SPB        0x00000003  /* Simple Packet Block */

static_always_inline u8 *
get_pcapng_shb_vec () // gpcapng_dest_t *out, void *context)
{
  // pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  struct
  {
    u32 block_type;
    u32 block_len;
    u32 magic;
    u16 major_version;
    u16 minor_version;
    u64 section_len;
    u32 block_len_copy;
  } __attribute__ ((packed)) shb;

  memset (&shb, 0, sizeof (shb));
  shb.block_type = PCAPNG_BLOCK_TYPE_SHB;
  shb.block_len = sizeof (shb);
  shb.magic = 0x1A2B3C4D; /* Byte order magic */
  shb.major_version = 1;
  shb.minor_version = 0;
  shb.section_len = 0xFFFFFFFFFFFFFFFF; /* Unknown length */
  shb.block_len_copy = sizeof (shb);

  u8 *rvec = 0;
  vec_add (rvec, &shb, sizeof (shb));
  return rvec;
}

static_always_inline u8 *
get_pcapng_idb (u8 **orig_block, u32 if_index, const char *if_name)
{
  // pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  u32 name_len, pad_len, total_len;
  u8 *block;

  /* Calculate the padded name length (must be 32-bit aligned) */
  name_len = strlen (if_name) + 1; /* Include null terminator */
  pad_len = (4 - (name_len % 4)) % 4;

  /* Total length of the IDB block */
  total_len = 20 + name_len + pad_len + 4;

  vec_add2 (*orig_block, block, total_len);
  if (!block)
    return 0;

  /* Fill in the IDB block */
  *(u32 *) (block) = PCAPNG_BLOCK_TYPE_IDB;
  *(u32 *) (block + 4) = total_len;
  *(u16 *) (block + 8) = 1;	    /* Link type: LINKTYPE_ETHERNET */
  *(u16 *) (block + 10) = 0;	    /* Reserved */
  *(u32 *) (block + 12) = 0;	    /* SnapLen: no limit */
  *(u16 *) (block + 16) = 2;	    /* ifname */
  *(u16 *) (block + 18) = name_len; /* ifname len */

  /* Copy interface name to the options section */
  memcpy (block + 20, if_name, name_len - 1);
  block[20 + name_len - 1] = 0; /* Ensure null termination */

  /* Add padding bytes */
  memset (block + 20 + name_len, 0, pad_len);

  /* Add block length at the end */
  *(u32 *) (block + total_len - 4) = total_len;

  return block;
}

static_always_inline int
get_pcapng_epb (vlib_main_t *vm, u8 **buffer, u32 if_index, u64 timestamp,
		vlib_buffer_t *b0, u32 capture_len, void *comment,
		u32 comment_len)
{
  u32 pad_len, total_len, options_len;
  u8 *block, *options_ptr;

  u32 orig_len = vlib_buffer_length_in_chain (vm, b0);

  u32 packet_len = capture_len > orig_len ? orig_len : capture_len;


  /* Calculate padding length for packet data (must be 32-bit aligned) */
  pad_len = (4 - (packet_len % 4)) % 4;

  u32 opt3_data_len = comment_len;
  u32 opt3_pad = (4 - (opt3_data_len % 4)) % 4;
  u32 opt3_len = opt3_data_len > 0 ? 4 + opt3_data_len + opt3_pad : 0;

  // End of options marker (4 bytes)
  u32 opt_end_len = 4;

  options_len = opt3_len + opt_end_len;

  /* Total length of the EPB block */
  total_len = 28 + packet_len + pad_len + options_len + 4;

  vec_add2 (*buffer, block, total_len);

  /* Fill in the EPB block header */
  *(u32 *) (block) = PCAPNG_BLOCK_TYPE_EPB;
  *(u32 *) (block + 4) = total_len;
  *(u32 *) (block + 8) = if_index;
  *(u32 *) (block + 12) = timestamp >> 32;	  /* Timestamp (high) */
  *(u32 *) (block + 16) = timestamp & 0xFFFFFFFF; /* Timestamp (low) */
  *(u32 *) (block + 20) = packet_len;		  /* Captured length */
  *(u32 *) (block + 24) = orig_len;		  /* Original length */

  /* Copy packet data - as much as we want to capture */
  // memcpy (block + 28, packet_data, packet_len);
  vlib_buffer_t *buf_iter = b0;
  u32 rem_len = packet_len;
  u32 offset = 0;
  while (buf_iter && rem_len)
         {
              u32 len = buf_iter->current_length > rem_len ? buf_iter->current_length : rem_len;
              clib_memcpy_fast (block + 28 + offset, vlib_buffer_get_current (buf_iter), len);
              offset += len;
              rem_len -= len;
              buf_iter = buf_iter->flags & VLIB_BUFFER_NEXT_PRESENT ?
                    vlib_get_buffer (vm, buf_iter->next_buffer) : 0;
         }


  /* Add padding bytes for packet data */
  memset (block + 28 + packet_len, 0, pad_len);

  /* Add options after packet data and padding */
  options_ptr = block + 28 + packet_len + pad_len;

  /* Option 3: Comment option with JSON (standard option code 1) */
  if (opt3_len)
    {
      *(u16 *) (options_ptr) = 1;			/* opt_comment */
      *(u16 *) (options_ptr + 2) = opt3_data_len;	/* Option length */
      memcpy (options_ptr + 4, comment, opt3_data_len); /* JSON data */
      memset (options_ptr + 4 + opt3_data_len, 0, opt3_pad); /* Padding */
      options_ptr += opt3_len;
    }

  /* End of options marker */
  *(u16 *) (options_ptr) = 0;	  /* opt_endofopt */
  *(u16 *) (options_ptr + 2) = 0; /* Length 0 */
  options_ptr += opt_end_len;

  /* Add block length at the end */
  *(u32 *) (options_ptr) = total_len;

  /* Write the block to file */
  // result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  return (block - *buffer);
}

static_always_inline int
vec_add_pcapng_epb (vlib_main_t *vm, u8 **vec_out, void *context, u32 if_index, u64 timestamp,
		    vlib_buffer_t *b0, u32 capture_len)
{
  gpcapng_worker_context_common_t *common_ctx = context;

  char json_comment[100] = ""; // = "{\"app_id\": \"dummy_json\", \"flow_id\":
			       // 12345, \"custom_field\": \"value\"}";
  if (common_ctx->packet_counter > common_ctx->last_sent_packet_counter + 1)
    {
      sprintf (json_comment, "{\"missed packets\": %ld}",
	       common_ctx->packet_counter -
		 common_ctx->last_sent_packet_counter);
    }

  return get_pcapng_epb (vm, vec_out, if_index, timestamp, b0,
			 capture_len, json_comment, strlen (json_comment));
}

