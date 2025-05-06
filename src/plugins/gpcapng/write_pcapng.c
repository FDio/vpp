#include <vnet/vnet.h>
#include <vlib/vlib.h>


#include "gpcapng.h"


/* Define PCAPng format related constants */
#define PCAPNG_BLOCK_TYPE_SHB        0x0A0D0D0A  /* Section Header Block */
#define PCAPNG_BLOCK_TYPE_IDB        0x00000001  /* Interface Description Block */
#define PCAPNG_BLOCK_TYPE_EPB        0x00000006  /* Enhanced Packet Block */
// #define PCAPNG_BLOCK_TYPE_SPB        0x00000003  /* Simple Packet Block */


static int
file_write_pcapng_shb (gpcapng_dest_t *out, void *context)
{
  // pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  struct {
    u32 block_type;
    u32 block_len;
    u32 magic;
    u16 major_version;
    u16 minor_version;
    u64 section_len;
    u32 block_len_copy;
  } __attribute__ ((packed)) shb;

  if (!context)
    return -1;
    
  memset (&shb, 0, sizeof (shb));
  shb.block_type = PCAPNG_BLOCK_TYPE_SHB;
  shb.block_len = sizeof (shb);
  shb.magic = 0x1A2B3C4D;  /* Byte order magic */
  shb.major_version = 1;
  shb.minor_version = 0;
  shb.section_len = 0xFFFFFFFFFFFFFFFF;  /* Unknown length */
  shb.block_len_copy = sizeof (shb);
  
  return out->chunk_write(context, &shb, sizeof (shb));
}

static int
file_write_pcapng_idb (gpcapng_dest_t *out, void *context, u32 if_index, const char *if_name)
{
  // pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  u32 name_len, pad_len, total_len;
  u8 *block;
  int result;
  
  if (!context)
    return -1;
    
  /* Calculate the padded name length (must be 32-bit aligned) */
  name_len = strlen (if_name) + 1;  /* Include null terminator */
  pad_len = (4 - (name_len % 4)) % 4;
  
  /* Total length of the IDB block */
  total_len = 20 + name_len + pad_len + 4;
  
  block = clib_mem_alloc (total_len);
  if (!block)
    return -1;
  
  /* Fill in the IDB block */
  *(u32 *)(block) = PCAPNG_BLOCK_TYPE_IDB;
  *(u32 *)(block + 4) = total_len;
  *(u16 *)(block + 8) = 1;  /* Link type: LINKTYPE_ETHERNET */
  *(u16 *)(block + 10) = 0; /* Reserved */
  *(u32 *)(block + 12) = 0; /* SnapLen: no limit */
  *(u16 *)(block + 16) = 2; /* ifname */
  *(u16 *)(block + 18) = name_len; /* ifname len */
  
  /* Copy interface name to the options section */
  memcpy (block + 20, if_name, name_len - 1);
  block[20 + name_len - 1] = 0;  /* Ensure null termination */
  
  /* Add padding bytes */
  memset (block + 20 + name_len, 0, pad_len);
  
  /* Add block length at the end */
  *(u32 *)(block + total_len - 4) = total_len;
  
  /* Write the block to file */
  // result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  result = out->chunk_write(context, block, total_len);
  
  clib_mem_free (block);
  return result;
}

static int
file_write_pcapng_epb (gpcapng_dest_t *out, void *context, u32 if_index, u64 timestamp,
                       u32 orig_len, void *packet_data, u32 packet_len)
{
  u32 pad_len, total_len, options_len;
  u8 *block, *options_ptr;
  int result;

  if (!context)
    return -1;

  /* Calculate padding length for packet data (must be 32-bit aligned) */
  pad_len = (4 - (packet_len % 4)) % 4;

  // Option 3: Comment option with JSON (4 bytes option header + JSON length + padding)
  char json_comment[] = "{\"app_id\": \"dummy_json\", \"flow_id\": 12345, \"custom_field\": \"value\"}";
  u32 opt3_data_len = strlen(json_comment);
  u32 opt3_pad = (4 - (opt3_data_len % 4)) % 4;
  u32 opt3_len = 4 + opt3_data_len + opt3_pad;

  // End of options marker (4 bytes)
  u32 opt_end_len = 4;

  options_len = opt3_len + opt_end_len;

  /* Total length of the EPB block */
  total_len = 28 + packet_len + pad_len + options_len + 4;

  block = clib_mem_alloc (total_len);
  if (!block)
    return -1;

  /* Fill in the EPB block header */
  *(u32 *)(block) = PCAPNG_BLOCK_TYPE_EPB;
  *(u32 *)(block + 4) = total_len;
  *(u32 *)(block + 8) = if_index;
  *(u32 *)(block + 12) = timestamp >> 32;  /* Timestamp (high) */
  *(u32 *)(block + 16) = timestamp & 0xFFFFFFFF;  /* Timestamp (low) */
  *(u32 *)(block + 20) = packet_len;  /* Captured length */
  *(u32 *)(block + 24) = orig_len;    /* Original length */

  /* Copy packet data */
  memcpy (block + 28, packet_data, packet_len);

  /* Add padding bytes for packet data */
  memset (block + 28 + packet_len, 0, pad_len);

  /* Add options after packet data and padding */
  options_ptr = block + 28 + packet_len + pad_len;

  /* Option 3: Comment option with JSON (standard option code 1) */
  *(u16 *)(options_ptr) = 1;  /* opt_comment */
  *(u16 *)(options_ptr + 2) = opt3_data_len;  /* Option length */
  memcpy(options_ptr + 4, json_comment, opt3_data_len);  /* JSON data */
  memset(options_ptr + 4 + opt3_data_len, 0, opt3_pad);  /* Padding */
  options_ptr += opt3_len;

  /* End of options marker */
  *(u16 *)(options_ptr) = 0;  /* opt_endofopt */
  *(u16 *)(options_ptr + 2) = 0;  /* Length 0 */
  options_ptr += opt_end_len;

  /* Add block length at the end */
  *(u32 *)(options_ptr) = total_len;

  /* Write the block to file */
  // result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  result = out->chunk_write(context, block, total_len);

  clib_mem_free (block);
  return result;
}

void set_write_pcapng(gpcapng_dest_t *output) {
  output->write_pcapng_shb = file_write_pcapng_shb;
  output->write_pcapng_idb = file_write_pcapng_idb;
  output->write_pcapng_epb = file_write_pcapng_epb;

}

