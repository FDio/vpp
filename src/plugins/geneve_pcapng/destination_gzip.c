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

#include "geneve_pcapng.h"


typedef struct {
    gzFile gz_file;
    char *filename;
    int fd;
} cgzfile_dest_ctx_t;


/*******
 * GZ file utilities
 ******/
/**
 * Initialize a new PCAPNG gzip writer
 *
 * @param filename The output filename to write to
 * @return A pointer to the initialized writer or NULL on error
 */
void* pcapng_gzip_start(u32 worker_index) {
    cgzfile_dest_ctx_t *ctx;
    char filename[256];
  
  ctx = clib_mem_alloc_aligned (sizeof (cgzfile_dest_ctx_t), CLIB_CACHE_LINE_BYTES);
  memset (ctx, 0, sizeof (*ctx));

  /* Create a unique filename per worker */
  snprintf (filename, sizeof (filename), "/tmp/geneve_capture_worker%u.pcapng.gz", worker_index);
  ctx->filename = (void *)format (0, "%s%c", filename, 0);

    if (!ctx) {
        return NULL;
    }

    // Open the file with appropriate flags for syncing
    int fd = open(ctx->filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        clib_mem_free(ctx);
        return NULL;
    }

    // Open the gzip file with file descriptor
    gzFile gz_file = gzdopen(fd, "wb");
    if (!gz_file) {
        close(fd);
        clib_mem_free(ctx);
        return NULL;
    }

    // Set buffer size to 0 to make gzwrite flush immediately
    // This ensures file is always in a valid state
    // gzbuffer(gz_file, 0);

    ctx->gz_file = gz_file;
    ctx->fd = fd;

    return ctx;
}

/**
 * Write a chunk of PCAPNG data to the gzipped file
 *
 * @param writer The writer to use
 * @param chunk The chunk data to write
 * @param chunk_size The size of the chunk in bytes
 * @return 0 on success, -1 on error
 */
int pcapng_gzip_write_chunk(void *context, const void *chunk, size_t chunk_size) {
    cgzfile_dest_ctx_t *writer = context;
    if (!writer || !writer->gz_file) {
        return -1;
    }

    // Write the chunk
    int bytes_written = gzwrite(writer->gz_file, chunk, chunk_size);
    if (bytes_written != chunk_size) {
        return -1;
    }
    return 0;
}

static void
pcapng_gzip_flush(void *context) {
// Explicitly flush to ensure file is in a valid state

/*
    cgzfile_dest_ctx_t *writer = context;
    if (gzflush(writer->gz_file, Z_SYNC_FLUSH) != Z_OK) {
        return;
    }

    // Force a sync to disk
    fsync(writer->fd);
    */
}

/**
 * Close the gzip writer and free resources
 *
 * @param writer The writer to close
 * @return 0 on success, -1 on error
 */
static void pcapng_gzip_finish(void *context) {
    cgzfile_dest_ctx_t *writer = context;
    if (!writer) {
        return;
    }

    // Close the gzip file (which also flushes)
    if (gzclose(writer->gz_file) != Z_OK) {
        clib_warning("Could not call gzclose");
    }

    // Free resources
    clib_mem_free(writer->filename);
    clib_mem_free(writer);

    return;
}


void set_pcapng_output_gzip(geneve_output_t *output) {
  output->init = pcapng_gzip_start;
  output->cleanup = pcapng_gzip_finish;
  output->chunk_write = pcapng_gzip_write_chunk;
  output->flush = pcapng_gzip_flush;
}

