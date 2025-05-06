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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <isa-l/igzip_lib.h> // Using only igzip headers

#include "gpcapng.h"

#define CHUNK_SIZE (1 << 20) // 1MB buffer


typedef struct {
    char *filename;
    int fd;
    // Using direct igzip structures
    struct isal_zstream stream;
    struct isal_gzip_header gzip_hdr;

    unsigned char *out_buf;
    unsigned char *level_buf;
} igzfile_dest_ctx_t;

void set_pcapng_output_igzip(gpcapng_dest_t *output);


void* pcapng_igzip_start(gpcapng_dest_t *output, u16 worker_index, u16 destination_index) {
  igzfile_dest_ctx_t *ctx;
  
  ctx = clib_mem_alloc_aligned (sizeof (igzfile_dest_ctx_t), CLIB_CACHE_LINE_BYTES);
  memset (ctx, 0, sizeof (*ctx));

  ctx->filename = (void *)format (0, "%v-%u.pcapng.gz%c", output->arg, worker_index, 0);

    if (!ctx) {
        return NULL;
    }

    // Open the file with appropriate flags for syncing
    int fd = open(ctx->filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        clib_mem_free(ctx);
        return NULL;
    }
    ctx->fd = fd;

    // Initialize header
    isal_gzip_header_init(&ctx->gzip_hdr);

    // Initialize compression stream directly
    isal_deflate_init(&ctx->stream);
    ctx->stream.end_of_stream = 0;
    ctx->stream.flush = NO_FLUSH;
    ctx->stream.gzip_flag = IGZIP_GZIP; // Using gzip format
    ctx->stream.level = 1; // Fastest compression
    // Allocate memory buffers
    ctx->out_buf = clib_mem_alloc(CHUNK_SIZE);
    ctx->level_buf = malloc(ISAL_DEF_LVL1_DEFAULT);
/*
    if (!in_buf || !out_buf || !level_buf) {
        perror("Memory allocation failed");
        return 1;
    }
    */
    
    // Setup level buffer - critical for performance
    ctx->stream.level_buf = ctx->level_buf;
    ctx->stream.level_buf_size = ISAL_DEF_LVL1_DEFAULT;
    
    // Setup output buffer
    ctx->stream.avail_out = CHUNK_SIZE;
    ctx->stream.next_out = ctx->out_buf;
    
    // Direct CPU feature detection for optimal performance
    // This isn't in the standard API but is available in igzip internals
    #ifdef HAVE_CPUID
    // Use CPU dispatch directly, forces optimal code path selection
    struct inflate_state *state = &ctx->stream.internal_state;
    state->crc_fold_model = determine_igzip_hufftables();
    #endif

    return ctx;
}

int pcapng_igzip_write_chunk(void *context, const void *chunk, size_t chunk_size) {
     igzfile_dest_ctx_t *ctx = context;
     ctx->stream.avail_in = chunk_size;
     ctx->stream.next_in = (uint8_t *) chunk;

     /*
     // Set end of stream flag on last chunk
        if (bytes_read < CHUNK_SIZE)
            stream.end_of_stream = 1; 
      */
        // Compress data - direct call to core function
     int ret = isal_deflate(&ctx->stream);
     if (ret != ISAL_DECOMP_OK) {
         fprintf(stderr, "Error during compression: %d\n", ret);
         return 1;
     }
        
        // Write compressed output
     size_t bytes_compressed = CHUNK_SIZE - ctx->stream.avail_out;
     int result = write(ctx->fd, ctx->out_buf, bytes_compressed);
     if (result != bytes_compressed) {
        return -1;
     }
        
        // Reset output buffer for next chunk
     ctx->stream.next_out = ctx->out_buf;
     ctx->stream.avail_out = CHUNK_SIZE;
/*
    
    // Flush any remaining data if needed
    if (stream.internal_state.state != ZSTATE_END) {
        do {
            // Direct call to flush remaining data
            int ret = isal_deflate(&stream);
            if (ret != ISAL_DECOMP_OK) {
                fprintf(stderr, "Error during flush: %d\n", ret);
                break;
            }
            
            // Write any output generated
            size_t bytes_compressed = CHUNK_SIZE - stream.avail_out;
            if (bytes_compressed > 0) {
                write(out_fd, out_buf, bytes_compressed);
                stream.next_out = out_buf;
                stream.avail_out = CHUNK_SIZE;
            }
        } while (stream.internal_state.state != ZSTATE_END);
    }
*/
    return 0;

}

static void
pcapng_igzip_flush(void *context) {
}

static void pcapng_igzip_finish(void *context) {
    igzfile_dest_ctx_t *writer = context;
    if (!writer) {
        return;
    }

    // Free resources
    clib_mem_free(writer->filename);
    clib_mem_free(writer);

    return;
}


void set_pcapng_output_igzip(gpcapng_dest_t *output) {
  output->init = pcapng_igzip_start;
  output->cleanup = pcapng_igzip_finish;
  output->chunk_write = pcapng_igzip_write_chunk;
  output->flush = pcapng_igzip_flush;
}

