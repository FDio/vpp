#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vppinfra/atomics.h>
#include <vlib/unix/unix.h>
#include <vppinfra/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "gpcapng.h"


/* File-based output implementation */
typedef struct {
  FILE *file;
  char *filename;
} pcapfile_dest_ctx_t;

/******************************************************************************
 * PCAPng file format utilities
 ******************************************************************************/

static void *
file_output_init (gpcapng_dest_t *output, u16 worker_index, u16 destination_index) 
{
  pcapfile_dest_ctx_t *ctx;

  ctx = clib_mem_alloc_aligned (sizeof (pcapfile_dest_ctx_t), CLIB_CACHE_LINE_BYTES);
  memset (ctx, 0, sizeof (*ctx));

  /* Create a unique filename per worker */
  ctx->filename = (void *)format (0, "%v-%u.pcapng%c", output->arg, worker_index, 0);

  
  ctx->file = fopen ((char *) ctx->filename, "wb+");
  if (!ctx->file)
    {
      clib_warning ("Failed to create PCAPng file: %s", ctx->filename);
      vec_free (ctx->filename);
      clib_mem_free (ctx);
      return NULL;
    }
  else {
    clib_warning("File is open: %s. file handle: %p", ctx->filename, ctx->file);
  }
  
  return ctx;
}

static int
file_chunk_write (void *context, const void *chunk, size_t chunk_size)
{
  pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  if (!ctx->file) {
      return -1;
  }
  int result = fwrite (chunk, 1, chunk_size, ctx->file) == chunk_size ? 0 : -1;
  return result;
}

static void
file_output_flush (void *context)
{
  pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  ASSERT(ctx->file);
  fflush (ctx->file);  /* Ensure data is written to disk */
}

static void
file_output_cleanup (void *context)
{
  pcapfile_dest_ctx_t *ctx = (pcapfile_dest_ctx_t *) context;
  
  if (!ctx)
    return;
    
  if (ctx->file) {
    clib_warning("closing the file");
    fclose (ctx->file);
  }
    
  vec_free (ctx->filename);
  clib_mem_free (ctx);
}

void set_pcapng_output_file(gpcapng_dest_t *output) {
  output->init = file_output_init;
  output->cleanup = file_output_cleanup;
  output->chunk_write = file_chunk_write;
  output->flush = file_output_flush;
}

