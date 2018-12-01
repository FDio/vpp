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

#ifndef __vcl_test_h__
#define __vcl_test_h__

#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <vcl/vppcom.h>

#define vtfail(_fn, _rv)						\
{									\
  errno = -_rv;								\
  perror ("ERROR when calling " _fn);					\
  fprintf (stderr, "\nERROR: " _fn " failed (errno = %d)!\n", -_rv);	\
  exit (1);								\
}

#define vterr(_fn, _rv)							\
{									\
  errno = -_rv;								\
  fprintf (stderr, "\nERROR: " _fn " failed (errno = %d)!\n", -_rv);	\
}

#define vtwrn(_fmt, _args...)						\
  fprintf (stderr, "\nERROR: " _fmt "\n", ##_args)			\

#define vtinf(_fmt, _args...)						\
  fprintf (stdout, "vt<w%u>: " _fmt "\n", __wrk_index, ##_args)

#define vt_atomic_add(_ptr, _val) 					\
  __atomic_fetch_add (_ptr, _val, __ATOMIC_RELEASE)

#define VCL_TEST_TOKEN_HELP           	"#H"
#define VCL_TEST_TOKEN_EXIT           	"#X"
#define VCL_TEST_TOKEN_VERBOSE        	"#V"
#define VCL_TEST_TOKEN_TXBUF_SIZE     	"#T:"
#define VCL_TEST_TOKEN_NUM_TEST_SESS 	"#I:"
#define VCL_TEST_TOKEN_NUM_WRITES     	"#N:"
#define VCL_TEST_TOKEN_RXBUF_SIZE     	"#R:"
#define VCL_TEST_TOKEN_SHOW_CFG       	"#C"
#define VCL_TEST_TOKEN_RUN_UNI        	"#U"
#define VCL_TEST_TOKEN_RUN_BI         	"#B"

#define VCL_TEST_SERVER_PORT         	22000
#define VCL_TEST_LOCALHOST_IPADDR    	"127.0.0.1"

#define VCL_TEST_CFG_CTRL_MAGIC      	0xfeedface
#define VCL_TEST_CFG_NUM_WRITES_DEF  	1000000
#define VCL_TEST_CFG_TXBUF_SIZE_DEF  	8192
#define VCL_TEST_CFG_RXBUF_SIZE_DEF  	(64*VCL_TEST_CFG_TXBUF_SIZE_DEF)
#define VCL_TEST_CFG_BUF_SIZE_MIN    	128
#define VCL_TEST_CFG_MAX_TEST_SESS 	32
#define VCL_TEST_CFG_MAX_EPOLL_EVENTS 	16

#define VCL_TEST_DELAY_DISCONNECT	1
#define VCL_TEST_SEPARATOR_STRING 	\
  "  -----------------------------\n"
typedef enum
{
  VCL_TEST_TYPE_NONE,
  VCL_TEST_TYPE_ECHO,
  VCL_TEST_TYPE_UNI,
  VCL_TEST_TYPE_BI,
  VCL_TEST_TYPE_EXIT,
} vcl_test_t;

typedef struct __attribute__ ((packed))
{
  uint32_t magic;
  uint32_t seq_num;
  uint32_t test;
  uint32_t ctrl_handle;
  uint32_t num_test_sessions;
  uint32_t verbose;
  uint32_t address_ip6;
  uint32_t transport_udp;
  uint32_t transport_tls;
  uint64_t rxbuf_size;
  uint64_t txbuf_size;
  uint64_t num_writes;
  uint64_t total_bytes;
} vcl_test_cfg_t;

typedef struct
{
  uint64_t rx_xacts;
  uint64_t rx_bytes;
  uint32_t rx_eagain;
  uint32_t rx_incomp;
  uint64_t tx_xacts;
  uint64_t tx_bytes;
  uint32_t tx_eagain;
  uint32_t tx_incomp;
  struct timespec start;
  struct timespec stop;
} vcl_test_stats_t;

typedef struct
{
  int fd;
  uint32_t txbuf_size;
  char *txbuf;
  uint32_t rxbuf_size;
  char *rxbuf;
  vcl_test_cfg_t cfg;
  vcl_test_stats_t stats;
} vcl_test_session_t;


/*
 * TLS server cert and keys to be used for testing only
 */
char vcl_test_crt_rsa[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIID5zCCAs+gAwIBAgIJALeMYCEHrTtJMA0GCSqGSIb3DQEBCwUAMIGJMQswCQYD\r\n"
  "VQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMQ4wDAYDVQQK\r\n"
  "DAVDaXNjbzEOMAwGA1UECwwFZmQuaW8xFjAUBgNVBAMMDXRlc3R0bHMuZmQuaW8x\r\n"
  "IjAgBgkqhkiG9w0BCQEWE3ZwcC1kZXZAbGlzdHMuZmQuaW8wHhcNMTgwMzA1MjEx\r\n"
  "NTEyWhcNMjgwMzAyMjExNTEyWjCBiTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB\r\n"
  "MREwDwYDVQQHDAhTYW4gSm9zZTEOMAwGA1UECgwFQ2lzY28xDjAMBgNVBAsMBWZk\r\n"
  "LmlvMRYwFAYDVQQDDA10ZXN0dGxzLmZkLmlvMSIwIAYJKoZIhvcNAQkBFhN2cHAt\r\n"
  "ZGV2QGxpc3RzLmZkLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
  "4C1k8a1DuStgggqT4o09fP9sJ2dC54bxhS/Xk2VEfaIZ222WSo4X/syRVfVy9Yah\r\n"
  "cpI1zJ/RDxaZSFhgA+nPZBrFMsrULkrdAOpOVj8eDEp9JuWdO2ODSoFnCvLxcYWB\r\n"
  "Yc5kHryJpEaGJl1sFQSesnzMFty/59ta0stk0Fp8r5NhIjWvSovGzPo6Bhz+VS2c\r\n"
  "ebIZh4x1t2hHaFcgm0qJoJ6DceReWCW8w+yOVovTolGGq+bpb2Hn7MnRSZ2K2NdL\r\n"
  "+aLXpkZbS/AODP1FF2vTO1mYL290LO7/51vJmPXNKSDYMy5EvILr5/VqtjsFCwRL\r\n"
  "Q4jcM/+GeHSAFWx4qIv0BwIDAQABo1AwTjAdBgNVHQ4EFgQUWa1SOB37xmT53tZQ\r\n"
  "aXuLLhRI7U8wHwYDVR0jBBgwFoAUWa1SOB37xmT53tZQaXuLLhRI7U8wDAYDVR0T\r\n"
  "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoUht13W4ya27NVzQuCMvqPWL3VM4\r\n"
  "3xbPFk02FaGz/WupPu276zGlzJAZrbuDcQowwwU1Ni1Yygxl96s1c2M5rHDTrOKG\r\n"
  "rK0hbkSFBo+i6I8u4HiiQ4rYmG0Hv6+sXn3of0HsbtDPGgWZoipPWDljPYEURu3e\r\n"
  "3HRe/Dtsj9CakBoSDzs8ndWaBR+f4sM9Tk1cjD46Gq2T/qpSPXqKxEUXlzhdCAn4\r\n"
  "twub17Bq2kykHpppCwPg5M+v30tHG/R2Go15MeFWbEJthFk3TZMjKL7UFs7fH+x2\r\n"
  "wSonXb++jY+KmCb93C+soABBizE57g/KmiR2IxQ/LMjDik01RSUIaM0lLA==\r\n"
  "-----END CERTIFICATE-----\r\n";
uint32_t vcl_test_crt_rsa_len = sizeof (vcl_test_crt_rsa);

char vcl_test_key_rsa[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDgLWTxrUO5K2CC\r\n"
  "CpPijT18/2wnZ0LnhvGFL9eTZUR9ohnbbZZKjhf+zJFV9XL1hqFykjXMn9EPFplI\r\n"
  "WGAD6c9kGsUyytQuSt0A6k5WPx4MSn0m5Z07Y4NKgWcK8vFxhYFhzmQevImkRoYm\r\n"
  "XWwVBJ6yfMwW3L/n21rSy2TQWnyvk2EiNa9Ki8bM+joGHP5VLZx5shmHjHW3aEdo\r\n"
  "VyCbSomgnoNx5F5YJbzD7I5Wi9OiUYar5ulvYefsydFJnYrY10v5otemRltL8A4M\r\n"
  "/UUXa9M7WZgvb3Qs7v/nW8mY9c0pINgzLkS8guvn9Wq2OwULBEtDiNwz/4Z4dIAV\r\n"
  "bHioi/QHAgMBAAECggEBAMzGipP8+oT166U+NlJXRFifFVN1DvdhG9PWnOxGL+c3\r\n"
  "ILmBBC08WQzmHshPemBvR6DZkA1H23cV5JTiLWrFtC00CvhXsLRMrE5+uWotI6yE\r\n"
  "iofybMroHvD6/X5R510UX9hQ6MHu5ShLR5VZ9zXHz5MpTmB/60jG5dLx+jgcwBK8\r\n"
  "LuGv2YB/WCUwT9QJ3YU2eaingnXtz/MrFbkbltrqlnBdlD+kTtw6Yac9y1XuuQXc\r\n"
  "BPeulLNDuPolJVWbUvDBZrpt2dXTgz8ws1sv+wCNE0xwQJsqW4Nx3QkpibUL9RUr\r\n"
  "CVbKlNfa9lopT6nGKlgX69R/uH35yh9AOsfasro6w0ECgYEA82UJ8u/+ORah+0sF\r\n"
  "Q0FfW5MTdi7OAUHOz16pUsGlaEv0ERrjZxmAkHA/VRwpvDBpx4alCv0Hc39PFLIk\r\n"
  "nhSsM2BEuBkTAs6/GaoNAiBtQVE/hN7awNRWVmlieS0go3Y3dzaE9IUMyj8sPOFT\r\n"
  "5JdJ6BM69PHKCkY3dKdnnfpFEuECgYEA68mRpteunF1mdZgXs+WrN+uLlRrQR20F\r\n"
  "ZyMYiUCH2Dtn26EzA2moy7FipIIrQcX/j+KhYNGM3e7MU4LymIO29E18mn8JODnH\r\n"
  "sQOXzBTsf8A4yIVMkcuQD3bfb0JiUGYUPOidTp2N7IJA7+6Yc3vQOyb74lnKnJoO\r\n"
  "gougPT2wS+cCgYAn7muzb6xFsXDhyW0Tm6YJYBfRS9yAWEuVufINobeBZPSl2cN1\r\n"
  "Jrnw+HlrfTNbrJWuJmjtZJXUXQ6cVp2rUbjutNyRV4vG6iRwEXYQ40EJdkr1gZpi\r\n"
  "CHQhuShuuPih2MNAy7EEbM+sXrDjTBR3bFqzuHPzu7dp+BshCFX3lRfAAQKBgGQt\r\n"
  "K5i7IhCFDjb/+3IPLgOAK7mZvsvZ4eXD33TQ2eZgtut1PXtBtNl17/b85uv293Fm\r\n"
  "VDISVcsk3eLNS8zIiT6afUoWlxAwXEs0v5WRfjl4radkGvgGiJpJYvyeM67877RB\r\n"
  "EDSKc/X8ESLfOB44iGvZUEMG6zJFscx9DgN25iQZAoGAbyd+JEWwdVH9/K3IH1t2\r\n"
  "PBkZX17kNWv+iVM1WyFjbe++vfKZCrOJiyiqhDeEqgrP3AuNMlaaduC3VRC3G5oV\r\n"
  "Mj1tlhDWQ/qhvKdCKNdIVQYDE75nw+FRWV8yYkHAnXYW3tNoweDIwixE0hkPR1bc\r\n"
  "oEjPLVNtx8SOj/M4rhaPT3I=\r\n" "-----END PRIVATE KEY-----\r\n";
uint32_t vcl_test_key_rsa_len = sizeof (vcl_test_key_rsa);

static inline void
vcl_test_stats_accumulate (vcl_test_stats_t * accum, vcl_test_stats_t * incr)
{
  accum->rx_xacts += incr->rx_xacts;
  accum->rx_bytes += incr->rx_bytes;
  accum->rx_eagain += incr->rx_eagain;
  accum->rx_incomp += incr->rx_incomp;
  accum->tx_xacts += incr->tx_xacts;
  accum->tx_bytes += incr->tx_bytes;
  accum->tx_eagain += incr->tx_eagain;
  accum->tx_incomp += incr->tx_incomp;
}

static inline void
vcl_test_cfg_init (vcl_test_cfg_t * cfg)
{
  cfg->magic = VCL_TEST_CFG_CTRL_MAGIC;
  cfg->test = VCL_TEST_TYPE_NONE;
  cfg->ctrl_handle = ~0;
  cfg->num_test_sessions = 1;
  cfg->verbose = 0;
  cfg->rxbuf_size = VCL_TEST_CFG_RXBUF_SIZE_DEF;
  cfg->num_writes = VCL_TEST_CFG_NUM_WRITES_DEF;
  cfg->txbuf_size = VCL_TEST_CFG_TXBUF_SIZE_DEF;
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
}

static inline int
vcl_test_cfg_verify (vcl_test_cfg_t * cfg, vcl_test_cfg_t * valid_cfg)
{
  /* Note: txbuf & rxbuf on server are the same buffer,
   *       so txbuf_size is not included in this check.
   */
  return ((cfg->magic == valid_cfg->magic)
	  && (cfg->test == valid_cfg->test)
	  && (cfg->verbose == valid_cfg->verbose)
	  && (cfg->rxbuf_size == valid_cfg->rxbuf_size)
	  && (cfg->num_writes == valid_cfg->num_writes)
	  && (cfg->total_bytes == valid_cfg->total_bytes));
}

static inline void
vcl_test_buf_alloc (vcl_test_cfg_t * cfg, uint8_t is_rxbuf, uint8_t ** buf,
		    uint32_t * bufsize)
{
  uint32_t alloc_size = is_rxbuf ? cfg->rxbuf_size : cfg->txbuf_size;
  uint8_t *lb = realloc (*buf, (size_t) alloc_size);

  if (lb)
    {
      if (is_rxbuf)
	cfg->rxbuf_size = *bufsize = alloc_size;
      else
	cfg->txbuf_size = *bufsize = alloc_size;

      *buf = lb;
    }
  else
    {
      vtwrn ("realloc failed. using buffer size %d instead of %u",
	     *bufsize, alloc_size);
    }
}

static inline void
vcl_test_session_buf_alloc (vcl_test_session_t * socket)
{
  socket->rxbuf_size = socket->cfg.rxbuf_size;
  socket->txbuf_size = socket->cfg.txbuf_size;
  vcl_test_buf_alloc (&socket->cfg, 0 /* is_rxbuf */ ,
		      (uint8_t **) & socket->txbuf, &socket->txbuf_size);
  vcl_test_buf_alloc (&socket->cfg, 1 /* is_rxbuf */ ,
		      (uint8_t **) & socket->rxbuf, &socket->rxbuf_size);
}

static inline char *
vcl_test_type_str (vcl_test_t t)
{
  switch (t)
    {
    case VCL_TEST_TYPE_NONE:
      return "NONE";

    case VCL_TEST_TYPE_ECHO:
      return "ECHO";

    case VCL_TEST_TYPE_UNI:
      return "UNI";

    case VCL_TEST_TYPE_BI:
      return "BI";

    case VCL_TEST_TYPE_EXIT:
      return "EXIT";

    default:
      return "Unknown";
    }
}

static inline void
vcl_test_cfg_dump (vcl_test_cfg_t * cfg, uint8_t is_client)
{
  char *spc = "     ";

  printf ("  test config (%p):\n"
	  VCL_TEST_SEPARATOR_STRING
	  "                 magic:  0x%08x\n"
	  "               seq_num:  0x%08x\n"
	  "%-5s             test:  %s (%d)\n"
	  "           ctrl handle:  %d (0x%x)\n"
	  "%-5s num test sockets:  %u (0x%08x)\n"
	  "%-5s          verbose:  %s (%d)\n"
	  "%-5s       rxbuf size:  %lu (0x%08lx)\n"
	  "%-5s       txbuf size:  %lu (0x%08lx)\n"
	  "%-5s       num writes:  %lu (0x%08lx)\n"
	  "       client tx bytes:  %lu (0x%08lx)\n"
	  VCL_TEST_SEPARATOR_STRING,
	  (void *) cfg, cfg->magic, cfg->seq_num,
	  is_client && (cfg->test == VCL_TEST_TYPE_UNI) ?
	  "'" VCL_TEST_TOKEN_RUN_UNI "'" :
	  is_client && (cfg->test == VCL_TEST_TYPE_BI) ?
	  "'" VCL_TEST_TOKEN_RUN_BI "'" : spc,
	  vcl_test_type_str (cfg->test), cfg->test,
	  cfg->ctrl_handle, cfg->ctrl_handle,
	  is_client ? "'" VCL_TEST_TOKEN_NUM_TEST_SESS "'" : spc,
	  cfg->num_test_sessions, cfg->num_test_sessions,
	  is_client ? "'" VCL_TEST_TOKEN_VERBOSE "'" : spc,
	  cfg->verbose ? "on" : "off", cfg->verbose,
	  is_client ? "'" VCL_TEST_TOKEN_RXBUF_SIZE "'" : spc,
	  cfg->rxbuf_size, cfg->rxbuf_size,
	  is_client ? "'" VCL_TEST_TOKEN_TXBUF_SIZE "'" : spc,
	  cfg->txbuf_size, cfg->txbuf_size,
	  is_client ? "'" VCL_TEST_TOKEN_NUM_WRITES "'" : spc,
	  cfg->num_writes, cfg->num_writes,
	  cfg->total_bytes, cfg->total_bytes);
}

static inline void
vcl_test_stats_dump (char *header, vcl_test_stats_t * stats,
		     uint8_t show_rx, uint8_t show_tx, uint8_t verbose)
{
  struct timespec diff;
  double duration, rate;
  uint64_t total_bytes;

  if ((stats->stop.tv_nsec - stats->start.tv_nsec) < 0)
    {
      diff.tv_sec = stats->stop.tv_sec - stats->start.tv_sec - 1;
      diff.tv_nsec = stats->stop.tv_nsec - stats->start.tv_nsec + 1e9;
    }
  else
    {
      diff.tv_sec = stats->stop.tv_sec - stats->start.tv_sec;
      diff.tv_nsec = stats->stop.tv_nsec - stats->start.tv_nsec;
    }
  duration = (double) diff.tv_sec + (1e-9 * diff.tv_nsec);

  total_bytes = stats->tx_bytes + stats->rx_bytes;
  rate = (double) total_bytes *8 / duration / 1e9;
  printf ("\n%s: Streamed %lu bytes\n"
	  "  in %lf seconds (%lf Gbps %s-duplex)!\n",
	  header, total_bytes, duration, rate,
	  (show_rx && show_tx) ? "full" : "half");

  if (show_tx)
    {
      printf (VCL_TEST_SEPARATOR_STRING
	      "  tx stats (0x%p):\n"
	      VCL_TEST_SEPARATOR_STRING
	      "         writes:  %lu (0x%08lx)\n"
	      "       tx bytes:  %lu (0x%08lx)\n"
	      "      tx eagain:  %u (0x%08x)\n"
	      "  tx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->tx_xacts, stats->tx_xacts,
	      stats->tx_bytes, stats->tx_bytes,
	      stats->tx_eagain, stats->tx_eagain,
	      stats->tx_incomp, stats->tx_incomp);
    }
  if (show_rx)
    {
      printf (VCL_TEST_SEPARATOR_STRING
	      "  rx stats (0x%p):\n"
	      VCL_TEST_SEPARATOR_STRING
	      "          reads:  %lu (0x%08lx)\n"
	      "       rx bytes:  %lu (0x%08lx)\n"
	      "      rx eagain:  %u (0x%08x)\n"
	      "  rx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->rx_xacts, stats->rx_xacts,
	      stats->rx_bytes, stats->rx_bytes,
	      stats->rx_eagain, stats->rx_eagain,
	      stats->rx_incomp, stats->rx_incomp);
    }
  if (verbose)
    printf ("   start.tv_sec:  %ld\n"
	    "  start.tv_nsec:  %ld\n"
	    "    stop.tv_sec:  %ld\n"
	    "   stop.tv_nsec:  %ld\n",
	    stats->start.tv_sec, stats->start.tv_nsec,
	    stats->stop.tv_sec, stats->stop.tv_nsec);

  printf (VCL_TEST_SEPARATOR_STRING);
}

static inline int
vcl_comp_tspec (struct timespec *a, struct timespec *b)
{
  if (a->tv_sec < b->tv_sec)
    return -1;
  else if (a->tv_sec > b->tv_sec)
    return 1;
  else if (a->tv_nsec < b->tv_nsec)
    return -1;
  else if (a->tv_nsec > b->tv_nsec)
    return 1;
  else
    return 0;
}

static inline int
vcl_test_read (int fd, uint8_t * buf, uint32_t nbytes,
	       vcl_test_stats_t * stats)
{
  int rx_bytes, errno_val;

  do
    {
      if (stats)
	stats->rx_xacts++;
      rx_bytes = vppcom_session_read (fd, buf, nbytes);

      if (rx_bytes < 0)
	{
	  errno = -rx_bytes;
	  rx_bytes = -1;
	}
      if (stats)
	{
	  if ((rx_bytes == 0) ||
	      ((rx_bytes < 0)
	       && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
	    stats->rx_eagain++;
	  else if (rx_bytes < nbytes)
	    stats->rx_incomp++;
	}
    }
  while ((rx_bytes == 0) ||
	 ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));

  if (rx_bytes < 0)
    {
      vterr ("vppcom_session_read()", -errno);
    }
  else if (stats)
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vcl_test_read_ds (int fd, vppcom_data_segments_t ds, vcl_test_stats_t * stats)
{
  int rx_bytes, errno_val;

  do
    {
      if (stats)
	stats->rx_xacts++;
      rx_bytes = vppcom_session_read_segments (fd, ds);

      if (rx_bytes < 0)
	{
	  errno = -rx_bytes;
	  rx_bytes = -1;
	}
      if (stats)
	{
	  if ((rx_bytes == 0) ||
	      ((rx_bytes < 0)
	       && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
	    stats->rx_eagain++;
	}
    }
  while ((rx_bytes == 0) ||
	 ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));

  if (rx_bytes < 0)
    {
      vterr ("vppcom_session_read()", -errno);
    }
  else if (stats)
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vcl_test_write (int fd, uint8_t * buf, uint32_t nbytes,
		vcl_test_stats_t * stats, uint32_t verbose)
{
  int tx_bytes = 0, nbytes_left = nbytes, rv;

  do
    {
      if (stats)
	stats->tx_xacts++;
      rv = vppcom_session_write (fd, buf, nbytes_left);
      if (rv < 0)
	{
	  errno = -rv;
	  rv = -1;
	}
      if (rv < 0)
	{
	  if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
	    {
	      if (stats)
		stats->tx_eagain++;
	      break;
	    }
	  else
	    break;
	}
      tx_bytes += rv;

      if (tx_bytes != nbytes)
	{
	  nbytes_left = nbytes_left - rv;
	  if (stats)
	    stats->tx_incomp++;
	}

    }
  while (tx_bytes != nbytes);

  if (tx_bytes < 0)
    {
      vterr ("vpcom_session_write", -errno);
    }
  else if (stats)
    stats->tx_bytes += tx_bytes;

  return (tx_bytes);
}

#endif /* __vcl_test_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
