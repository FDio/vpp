/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <hs_apps/vcl/vcl_test.h>
#include <http/http.h>
#include <http/http_content_types.h>

typedef enum vcl_test_http_state_
{
  VCL_TEST_HTTP_IDLE = 0,
  VCL_TEST_HTTP_IN_PROGRESS,
  VCL_TEST_HTTP_COMPLETED,
} vcl_test_http_state_t;

typedef struct vcl_test_http_ctx_t
{
  u8 is_server;
  vcl_test_http_state_t test_state;
  u64 rem_data;
} vcl_test_http_ctx_t;

static int
vt_tcp_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TCP, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  ts->done = vcl_test_is_done;

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);
    }

  return 0;
}

static int
vt_tcp_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TCP, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}

static int
vt_tcp_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }
  ts->fd = client_fd;
  ts->is_open = 1;
  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  ts->done = vcl_test_is_done;

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_tcp = {
  .open = vt_tcp_connect,
  .listen = vt_tcp_listen,
  .accept = vt_tcp_accept,
  .close = vcl_test_close_nop,
  .reset = vcl_test_reset_nop,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_TCP, vcl_test_tcp);

/* For efficiencty, udp should write more than one dgram as the calling app
 * might potentailly poll vcl for new events which in turn might involve
 * syscalls like epoll_wait */
static int
vcl_test_write_udp (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  uint64_t max_burst = 32 << 10, nbytes_left;
  vcl_test_stats_t *stats = &ts->stats;
  uint32_t nbytes_dgram;
  int rv;

  max_burst = (max_burst / nbytes) * nbytes;
  nbytes_left = ts->cfg.total_bytes - ts->stats.tx_bytes;
  nbytes_left = nbytes_left < max_burst ? nbytes_left : max_burst;
  max_burst = nbytes_left;

  while (nbytes_left)
    {
      while (1)
	{
	  stats->tx_xacts++;
	  nbytes_dgram = nbytes < nbytes_left ? nbytes : nbytes_left;
	  rv = vppcom_session_write (ts->fd, buf, nbytes_dgram);
	  if (rv < 0)
	    {
	      errno = -rv;
	      if (!((errno == EAGAIN || errno == EWOULDBLOCK)))
		vterr ("vpcom_session_write", -errno);
	      stats->tx_eagain++;
	      continue;
	    }
	  if (rv != nbytes_dgram)
	    {
	      vtwrn ("vppcom_session_write - incomplete write?");
	    }
	  break;
	}
      nbytes_left -= rv;
    }
  stats->tx_bytes += max_burst;
  return max_burst;
}

static int
vt_udp_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_UDP, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write_udp;
  ts->done = vcl_test_is_done;

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);
    }

  return 0;
}

static int
vt_udp_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_UDP, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CONNECTED, 0, 0);

  /* Listen is implicit */
  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  return 0;
}

static int
vt_udp_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }
  ts->fd = client_fd;
  ts->is_open = 1;
  ts->read = vcl_test_read;
  ts->write = vcl_test_write_udp;
  ts->done = vcl_test_is_done;

  /* Help client sessions migrate if need be */
  if (!ts->cfg.test_bytes)
    {
      char *buf[1];
      ts->write (ts, buf, 1);
    }

  return 0;
}

static int
vt_udp_reset (vcl_test_session_t *ts)
{
  vtinf ("Test session %d (fd %d) reset (ICMP destination unreachable "
	 "received - client closed UDP session).",
	 ts->session_index, ts->fd);
  return 0;
}

static const vcl_test_proto_vft_t vcl_test_udp = {
  .open = vt_udp_connect,
  .listen = vt_udp_listen,
  .accept = vt_udp_accept,
  .close = vcl_test_close_nop,
  .reset = vt_udp_reset,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_UDP, vcl_test_udp);

/*
 * TLS server cert and keys to be used for testing only
 */
static char vcl_test_crt_rsa[] =
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
static uint32_t vcl_test_crt_rsa_len = sizeof (vcl_test_crt_rsa);

static char vcl_test_key_rsa[] =
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
  "oEjPLVNtx8SOj/M4rhaPT3I=\r\n"
  "-----END PRIVATE KEY-----\r\n";
static uint32_t vcl_test_key_rsa_len = sizeof (vcl_test_key_rsa);

static int
vt_add_cert_key_pair ()
{
  vcl_test_main_t *vt = &vcl_test_main;
  vppcom_cert_key_pair_t ckpair;
  int ckp_index;

  vtinf ("Adding tls certs ...");

  ckpair.cert = vcl_test_crt_rsa;
  ckpair.key = vcl_test_key_rsa;
  ckpair.cert_len = vcl_test_crt_rsa_len;
  ckpair.key_len = vcl_test_key_rsa_len;
  ckp_index = vppcom_add_cert_key_pair (&ckpair);
  if (ckp_index < 0)
    {
      vterr ("vppcom_add_cert_key_pair()", ckp_index);
      return ckp_index;
    }

  vt->ckpair_index = ckp_index;
  return 0;
}

static int
vt_tls_init (hs_test_cfg_t *cfg)
{
  return vt_add_cert_key_pair ();
}

static int
vt_tls_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t flags, flen, ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TLS, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  ts->done = vcl_test_is_done;

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);
    }

  return 0;
}

static int
vt_tls_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TLS, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}

static int
vt_tls_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }
  ts->fd = client_fd;
  ts->is_open = 1;
  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  ts->done = vcl_test_is_done;

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_tls = {
  .init = vt_tls_init,
  .open = vt_tls_connect,
  .listen = vt_tls_listen,
  .accept = vt_tls_accept,
  .close = vcl_test_close_nop,
  .reset = vcl_test_reset_nop,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_TLS, vcl_test_tls);

static int
vt_dtls_init (hs_test_cfg_t *cfg)
{
  return vt_add_cert_key_pair ();
}

static int
vt_dtls_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t flags, flen, ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_DTLS, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  ts->done = vcl_test_is_done;

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);
    }

  return 0;
}

static int
vt_dtls_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_DTLS, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}

static int
vt_dtls_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }
  ts->fd = client_fd;
  ts->is_open = 1;
  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  ts->done = vcl_test_is_done;

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_dtls = {
  .init = vt_dtls_init,
  .open = vt_dtls_connect,
  .listen = vt_dtls_listen,
  .accept = vt_dtls_accept,
  .close = vcl_test_close_nop,
  .reset = vcl_test_reset_nop,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_DTLS, vcl_test_dtls);

static int
vt_quic_init (hs_test_cfg_t *cfg)
{
  vcl_test_main_t *vt = &vcl_test_main;

  if (cfg)
    vt->cfg = *cfg;

  vt->server_data_source = VT_TEST_DATA_SOURCE;

  return vt_add_cert_key_pair ();
}

typedef enum vt_quic_flags_
{
  VT_QUIC_F_SERVER = (1 << 0),
  VT_QUIC_F_HALF_CLOSED = (1 << 1),
  VT_QUIC_F_RESET = (1 << 2),
} vt_quic_flags_t;

#define VT_QUIC_SERVER_ERROR ((uint64_t) 0xDEAD)
#define VT_QUIC_CLIENT_ERROR ((uint64_t) 0xFACE)

typedef struct vt_quic_ctx_
{
  vt_quic_flags_t flags;
} vt_quic_ctx_t;

static void
vt_quic_session_init (vcl_test_session_t *ts, u8 is_server)
{
  vt_quic_ctx_t *quic_ctx;

  quic_ctx = malloc (sizeof (vt_quic_ctx_t));
  memset (quic_ctx, 0, sizeof (*quic_ctx));
  quic_ctx->flags |= is_server ? VT_QUIC_F_SERVER : 0;
  ts->opaque = quic_ctx;
}

static inline vcl_test_session_t *
vt_quic_stream_get_qsession (vcl_test_session_t *ts)
{
  vcl_test_main_t *vt = &vcl_test_main;
  vcl_test_wrk_t *wrk;

  /* client use different pool for quic connections (qsessions), streams are
   * distributed evenly */
  wrk = &vt->wrk[vcl_test_worker_index ()];
  return &wrk->qsessions[ts->session_index / vt->cfg.num_test_sessions_perq];
}

static int
vt_quic_maybe_init_wrk (vcl_test_main_t *vt, vcl_test_wrk_t *wrk,
			vppcom_endpt_t *endpt)
{
  uint32_t size, i, flags, flen, ckp_len;
  vcl_test_session_t *tq;
  int rv;

  /* Test already initialized */
  if (wrk->n_qsessions == vt->cfg.num_test_qsessions)
    return 0;

  /* Make sure pool is large enough */
  if (!wrk->qsessions)
    {
      wrk->qsessions =
	calloc (vt->cfg.num_test_qsessions, sizeof (vcl_test_session_t));
    }
  else
    {
      size = vt->cfg.num_test_qsessions * sizeof (vcl_test_session_t);
      wrk->qsessions = realloc (wrk->qsessions, size);
    }

  if (!wrk->qsessions)
    {
      vterr ("failed to alloc Qsessions", -errno);
      return errno;
    }

  for (i = 0; i < vt->cfg.num_test_qsessions; i++)
    {
      tq = &wrk->qsessions[i];
      tq->fd =
	vppcom_session_create (VPPCOM_PROTO_QUIC, 0 /* is_nonblocking */);
      tq->session_index = i;
      if (tq->fd < 0)
	{
	  vterr ("vppcom_session_create()", tq->fd);
	  return tq->fd;
	}

      ckp_len = sizeof (vt->ckpair_index);
      vppcom_session_attr (tq->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
			   &ckp_len);

      /* Connect is blocking */
      rv = vppcom_session_connect (tq->fd, endpt);
      if (rv < 0)
	{
	  vterr ("vppcom_session_connect()", rv);
	  return rv;
	}
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (tq->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test Qsession %d (fd %d) connected.", i, tq->fd);
    }
  wrk->n_qsessions = vt->cfg.num_test_qsessions;

  return 0;
}

static void
vt_quic_set_app_proto_err_code (int fd, uint64_t app_err_code)
{
  uint32_t elen = sizeof (app_err_code);
  vppcom_session_attr (fd, VPPCOM_ATTR_SET_APP_PROTO_ERR_CODE, &app_err_code,
		       &elen);
}

static uint64_t
vt_quic_get_app_proto_err_code (vcl_test_session_t *ts)
{
  uint64_t app_err_code = 0xFEFE;
  uint32_t elen = sizeof (app_err_code);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_GET_APP_PROTO_ERR_CODE,
		       &app_err_code, &elen);
  vtinf ("%s %d app proto error code 0x%lx",
	 vppcom_session_is_stream (ts->fd) ? "stream" : "connection", ts->fd,
	 app_err_code);
  return app_err_code;
}

static int
vt_quic_bidi_is_done (vcl_test_session_t *ts, uint8_t check_rx)
{
  return 0;
}

static int
vt_quic_client_bidi_write (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  int rv;
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;

  if (quic_ctx->flags & VT_QUIC_F_HALF_CLOSED)
    return 0;

  rv = vcl_test_write (ts, buf, nbytes);

  if (ts->stats.tx_bytes >= ts->cfg.total_bytes)
    {
      vppcom_session_shutdown (ts->fd, SHUT_WR);
      quic_ctx->flags |= VT_QUIC_F_HALF_CLOSED;
    }

  return rv;
}

static int
vt_quic_client_write_and_rst (vcl_test_session_t *ts, void *buf,
			      uint32_t nbytes)
{
  int rv;
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;

  if (quic_ctx->flags & VT_QUIC_F_RESET)
    return 0;

  if ((ts->stats.tx_bytes << 1) >= ts->cfg.total_bytes)
    {
      vtinf ("going to reset stream %d (fd %d)", ts->session_index, ts->fd);
      vt_quic_set_app_proto_err_code (ts->fd, VT_QUIC_CLIENT_ERROR);
      vppcom_session_terminate (ts->fd);
      quic_ctx->flags |= VT_QUIC_F_RESET;
      return 0;
    }

  rv = vcl_test_write (ts, buf, nbytes);

  return rv;
}

static int
vt_quic_client_read_server_rst (vcl_test_session_t *ts, void *buf,
				uint32_t nbytes)
{
  vcl_test_stats_t *stats = &ts->stats;
  int rv, rx_bytes = 0;

  do
    {
      stats->rx_xacts++;
      rv = vppcom_session_read (ts->fd, buf, nbytes);
      if (rv <= 0)
	{
	  errno = -rv;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    {
	      stats->rx_eagain++;
	      continue;
	    }
	  /* in case we do not process event yet */
	  if (errno == ECONNRESET)
	    break;

	  vterr ("vppcom_session_read()", -errno);
	  return -1;
	}

      rx_bytes = rv;
      if (rv < nbytes)
	stats->rx_incomp++;
    }
  while (!rx_bytes);

  stats->rx_bytes += rx_bytes;

  return rx_bytes;
}

static int
vt_quic_client_write_and_close (vcl_test_session_t *ts, void *buf,
				uint32_t nbytes)
{
  int rv;
  vcl_test_session_t *tq;
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;

  if (quic_ctx->flags & VT_QUIC_F_RESET)
    return 0;

  /* close connection prematurely in the middle of the stream data transfer */
  if ((ts->stats.tx_bytes << 1) >= ts->cfg.total_bytes)
    {
      /* grab qession (connection) for stream, set application errror code and
       * close it, stream is destroyed/closed within quic */
      tq = vt_quic_stream_get_qsession (ts);
      vtinf ("going to close connection %d (fd %d)", tq->session_index,
	     tq->fd);
      vt_quic_set_app_proto_err_code (tq->fd, VT_QUIC_CLIENT_ERROR);
      vppcom_session_close (tq->fd);
      /* mark stream so we will not send more data, flag is used also as done
       * signal */
      quic_ctx->flags |= VT_QUIC_F_RESET;
      return 0;
    }

  rv = vcl_test_write (ts, buf, nbytes);

  return rv;
}

static int
vt_quic_rst_is_done (vcl_test_session_t *ts, uint8_t check_rx)
{
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;

  if (quic_ctx->flags & VT_QUIC_F_RESET)
    return 1;

  return 0;
}

static int
vt_quic_close_is_done (vcl_test_session_t *ts, uint8_t check_rx)
{
  return ts->is_done;
}

static int
vt_quic_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t wrk_index, flags, flen;
  vcl_test_session_t *tq;
  vcl_test_wrk_t *wrk;
  int rv;

  wrk_index = vcl_test_worker_index ();
  wrk = &vt->wrk[wrk_index];

  /* Make sure qsessions are initialized */
  vt_quic_maybe_init_wrk (vt, wrk, endpt);

  ts->fd = vppcom_session_create (VPPCOM_PROTO_QUIC, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  if (vt->cfg.test == HS_TEST_TYPE_UNI)
    {
      flags = VPPCOM_STREAM_F_UNIDIRECTIONAL;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_STREAM_FLAGS, &flags,
			   &flen);
    }

  /* Choose qession to use for stream */
  tq = vt_quic_stream_get_qsession (ts);

  rv = vppcom_session_stream_connect (ts->fd, tq->fd);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_stream_connect()", rv);
      return rv;
    }

  if (vt->cfg.test_param == HS_TEST_PARAM_SERVER_RST_STREAM)
    {
      ts->read = vt_quic_client_read_server_rst;
      ts->write = vcl_test_write;
      ts->done = vt_quic_close_is_done;
    }
  else if (vt->cfg.test_param == HS_TEST_PARAM_CLIENT_RST_STREAM)
    {
      ts->read = vcl_test_read;
      ts->write = vt_quic_client_write_and_rst;
      ts->done = vt_quic_rst_is_done;
    }
  else if (vt->cfg.test_param == HS_TEST_PARAM_CLIENT_CLOSE_CONN)
    {
      ts->read = vcl_test_read;
      ts->write = vt_quic_client_write_and_close;
      ts->done = vt_quic_rst_is_done;
    }
  else if (ts->cfg.test_param == HS_TEST_PARAM_SERVER_CLOSE_CONN)
    {
      ts->read = vcl_test_read;
      ts->write = vcl_test_write;
      ts->done = vt_quic_rst_is_done;
    }
  else if (vt->cfg.test == HS_TEST_TYPE_BI)
    {
      ts->read = vcl_test_read;
      ts->write = vt_quic_client_bidi_write;
      ts->done = vt_quic_bidi_is_done;
    }
  else
    {
      ts->read = vcl_test_read;
      ts->write = vcl_test_write;
      ts->done = vcl_test_is_done;
    }

  vt_quic_session_init (ts, 0);

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test (quic stream) session %d (fd %d) connected.",
	     ts->session_index, ts->fd);
    }

  return 0;
}

static int
vt_quic_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_QUIC, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}

static int
vt_quic_server_bidi_write (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  if (!vppcom_session_is_stream (ts->fd))
    return 0;

  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;
  int rv = 0;

  if (quic_ctx->flags & VT_QUIC_F_HALF_CLOSED &&
      ts->stats.tx_bytes < ts->cfg.total_bytes)
    {
      rv = vcl_test_write (ts, ts->txbuf, ts->cfg.txbuf_size);
      if (ts->stats.tx_bytes >= ts->cfg.total_bytes)
	{
	  vppcom_session_close (ts->fd);
	  free (quic_ctx);
	  ts->is_open = 0;
	  ts->opaque = 0;
	}
    }

  return rv;
}

static int
vt_quic_server_write_nop (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  return 0;
}

static int
vt_quic_server_read_and_rst (vcl_test_session_t *ts, void *buf,
			     uint32_t nbytes)
{
  int rv;
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;

  if ((ts->stats.rx_bytes << 1) >= ts->cfg.total_bytes)
    {
      vtinf ("going to reset stream %d (fd %d)", ts->session_index, ts->fd);
      vt_quic_set_app_proto_err_code (ts->fd, VT_QUIC_SERVER_ERROR);
      vppcom_session_terminate (ts->fd);
      free (quic_ctx);
      ts->is_open = 0;
      ts->opaque = 0;
      return 0;
    }

  rv = vcl_test_read (ts, buf, nbytes);

  return rv;
}

static int
vt_quic_server_read_and_close (vcl_test_session_t *ts, void *buf,
			       uint32_t nbytes)
{
  int rv;

  /* close connection prematurely in the middle of the stream data transfer */
  if ((ts->stats.rx_bytes << 1) >= ts->cfg.total_bytes)
    {
      /* grab connection (parent) session for stream, for quic it is stored as
       * listener, set application errror code and close it, stream is
       * destroyed/closed within quic */
      int conn_fd = vppcom_session_listener (ts->fd);
      if (conn_fd == VPPCOM_EBADFD)
	return 0;
      vtinf ("going to close connection %d", conn_fd);
      vt_quic_set_app_proto_err_code (conn_fd, VT_QUIC_SERVER_ERROR);
      vppcom_session_close (conn_fd);
      return 0;
    }

  rv = vcl_test_read (ts, buf, nbytes);

  return rv;
}

static int
vt_quic_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;
  uint32_t flags, flen;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      if (client_fd != VPPCOM_EAGAIN)
	vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }

  if (vppcom_session_is_stream (client_fd))
    {
      flen = sizeof (flags);
      vppcom_session_attr (client_fd, VPPCOM_ATTR_GET_STREAM_FLAGS, &flags,
			   &flen);
      if (ts->cfg.test == HS_TEST_TYPE_UNI &&
	  !(flags & VPPCOM_STREAM_F_UNIDIRECTIONAL))
	{
	  vtwrn ("expected unidirectional stream");
	  vppcom_session_close (client_fd);
	  return VPPCOM_EINVAL;
	}
    }

  flen = sizeof (flags);
  flags = O_NONBLOCK;
  vppcom_session_attr (client_fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);

  ts->fd = client_fd;
  ts->is_open = 1;

  if (ts->cfg.test_param == HS_TEST_PARAM_SERVER_RST_STREAM)
    {
      ts->read = vt_quic_server_read_and_rst;
      ts->write = vt_quic_server_write_nop;
      ts->done = vt_quic_rst_is_done;
    }
  else if (ts->cfg.test_param == HS_TEST_PARAM_CLIENT_CLOSE_CONN)
    {
      ts->read = vcl_test_read;
      ts->write = vt_quic_server_write_nop;
      ts->done = vcl_test_is_done;
    }
  else if (ts->cfg.test_param == HS_TEST_PARAM_SERVER_CLOSE_CONN)
    {
      ts->read = vt_quic_server_read_and_close;
      ts->write = vt_quic_server_write_nop;
      ts->done = vcl_test_is_done;
    }
  else if (ts->cfg.test == HS_TEST_TYPE_BI)
    {
      ts->read = vcl_test_read;
      ts->write = vt_quic_server_bidi_write;
      ts->done = vt_quic_bidi_is_done;
    }
  else
    {
      ts->read = vcl_test_read;
      ts->write = vcl_test_write;
      ts->done = vcl_test_is_done;
    }

  vt_quic_session_init (ts, 1);

  return 0;
}

static int
vt_quic_cleanup (vcl_test_session_t *ts)
{
  if (!vppcom_session_is_stream (ts->fd))
    return 0;

  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;

  if (!quic_ctx)
    return 0;

  if (quic_ctx->flags & VT_QUIC_F_SERVER)
    {
      int listener_fd = vppcom_session_listener (ts->fd);
      if (listener_fd == VPPCOM_EBADFD)
	return 0;
      if ((vppcom_session_n_accepted (listener_fd) == 0) &&
	  vppcom_session_is_connectable_listener (listener_fd))
	{
	  vtinf ("Connected Listener fd %x has no more sessions", listener_fd);
	  vppcom_session_close (listener_fd);
	}
    }

  if (ts->opaque)
    free (ts->opaque);

  return 0;
}

static int
vt_quic_close (vcl_test_session_t *ts, uint32_t events)
{
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;
  uint64_t app_err_code;

  if (quic_ctx->flags & VT_QUIC_F_SERVER)
    {
      if (vppcom_session_is_stream (ts->fd))
	{
	  if (events & EPOLLERR)
	    {
	      if (quic_ctx->flags & VT_QUIC_F_RESET)
		return 1;
	      vtinf ("stream %u reset by client", ts->fd);
	      app_err_code = vt_quic_get_app_proto_err_code (ts);
	      if (app_err_code != VT_QUIC_CLIENT_ERROR)
		vtwrn ("invalid application error code 0x%lx, expected 0x%lx",
		       app_err_code, VT_QUIC_CLIENT_ERROR);
	      quic_ctx->flags |= VT_QUIC_F_RESET;
	      ts->stats.reset_count = 1;
	      return 1;
	    }
	  else if (events & EPOLLRDHUP)
	    {
	      if (ts->cfg.test_param == HS_TEST_PARAM_CLIENT_CLOSE_CONN ||
		  ts->cfg.test_param == HS_TEST_PARAM_SERVER_CLOSE_CONN)
		return 1;
	      quic_ctx->flags |= VT_QUIC_F_HALF_CLOSED;
	      vtinf ("stream %u half-closed", ts->fd);
	      return 0;
	    }
	}
      else
	{
	  app_err_code = vt_quic_get_app_proto_err_code (ts);
	  vtinf ("connection %u closed by client", ts->fd);
	  if (app_err_code != VT_QUIC_CLIENT_ERROR)
	    vtwrn ("invalid application error code 0x%lx, expected 0x%lx",
		   app_err_code, VT_QUIC_CLIENT_ERROR);
	  ts->stats.close_count = 1;
	}
      return 1;
    }
  else
    {
      if (vppcom_session_is_stream (ts->fd))
	{
	  if (events & EPOLLERR &&
	      ts->cfg.test_param == HS_TEST_PARAM_SERVER_RST_STREAM)
	    {
	      vtinf ("stream %u reset by server", ts->fd);
	      app_err_code = vt_quic_get_app_proto_err_code (ts);
	      if (app_err_code != VT_QUIC_SERVER_ERROR)
		vtwrn ("invalid application error code 0x%lx, expected 0x%lx",
		       app_err_code, VT_QUIC_SERVER_ERROR);
	      quic_ctx->flags |= VT_QUIC_F_RESET;
	      ts->stats.reset_count = 1;
	      return 1;
	    }
	  if (ts->cfg.test_param == HS_TEST_PARAM_SERVER_CLOSE_CONN)
	    {
	      vtinf ("stream %u closed", ts->fd);
	      ts->is_done = 1;
	      /* client don't get events for quic connections, they are also in
	       * different pool, so just check if connection has error code set
	       */
	      vcl_test_session_t *tq = vt_quic_stream_get_qsession (ts);
	      app_err_code = vt_quic_get_app_proto_err_code (tq);
	      if (app_err_code != VT_QUIC_SERVER_ERROR)
		vtwrn ("invalid application error code 0x%lx, expected 0x%lx",
		       app_err_code, VT_QUIC_SERVER_ERROR);
	      ts->stats.close_count = 1;
	      return 1;
	    }
	  if (ts->cfg.test == HS_TEST_TYPE_BI)
	    {
	      if (ts->stats.rx_bytes >= ts->cfg.total_bytes)
		{
		  vtinf ("stream %u closed - done", ts->fd);
		  ts->is_done = 1;
		  return 1;
		}
	    }
	}
      else
	{
	  vtinf ("connection %u closed by server", ts->fd);
	  ts->stats.close_count = 1;
	}
      return 0;
    }
}

static int
vt_quic_reset (vcl_test_session_t *ts)
{
  vt_quic_ctx_t *quic_ctx = (vt_quic_ctx_t *) ts->opaque;
  uint64_t app_err_code;

  if (quic_ctx->flags & VT_QUIC_F_SERVER &&
      ts->cfg.test_param == HS_TEST_PARAM_CLIENT_RST_STREAM)
    {
      vtinf ("stream %u reset by client", ts->fd);
      app_err_code = vt_quic_get_app_proto_err_code (ts);
      if (app_err_code != VT_QUIC_CLIENT_ERROR)
	vtwrn ("invalid application error code 0x%lx, expected 0x%lx",
	       app_err_code, VT_QUIC_CLIENT_ERROR);
      quic_ctx->flags |= VT_QUIC_F_RESET;
      ts->stats.reset_count = 1;
      return 0;
    }

  return 1;
}

static const vcl_test_proto_vft_t vcl_test_quic = {
  .init = vt_quic_init,
  .open = vt_quic_connect,
  .listen = vt_quic_listen,
  .accept = vt_quic_accept,
  .cleanup = vt_quic_cleanup,
  .close = vt_quic_close,
  .reset = vt_quic_reset,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_QUIC, vcl_test_quic);

static unsigned char test_key[46] = {
  0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c,
  0x06, 0xde, 0x41, 0x39, 0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
  0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6, 0xc1, 0x73, 0xc3, 0x17, 0xf2, 0xda,
  0xbe, 0x35, 0x77, 0x93, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};

typedef struct
{
  unsigned char cc : 4;
  unsigned char x : 1;
  unsigned char p : 1;
  unsigned char version : 2;
  unsigned char pt : 7;
  unsigned char m : 1;
  uint16_t seq;
  uint32_t ts;
  uint32_t ssrc;
} rtp_hdr_t;

typedef struct
{
  rtp_hdr_t tx_hdr;
  rtp_hdr_t rx_hdr;
} rtp_headers_t;

typedef struct transport_endpt_cfg_srtp_policy
{
  uint32_t ssrc_type;
  uint32_t ssrc_value;
  uint32_t window_size;
  uint8_t allow_repeat_tx;
  uint8_t key_len;
  uint8_t key[46];
} transport_endpt_cfg_srtp_policy_t;

typedef struct transport_endpt_cfg_srtp
{
  transport_endpt_cfg_srtp_policy_t policy[2];
} transport_endpt_cfg_srtp_t;

static void
vt_session_add_srtp_policy (vcl_test_session_t *ts, int is_connect)
{
  transport_endpt_cfg_srtp_t *srtp_cfg;
  transport_endpt_cfg_srtp_policy_t *test_policy;
  uint32_t rx_ssrc, tx_ssrc;
  uint32_t cfg_size;

  rx_ssrc = is_connect ? 0xcafebeef : 0xbeefcafe;
  tx_ssrc = is_connect ? 0xbeefcafe : 0xcafebeef;

  cfg_size = sizeof (transport_endpt_cfg_srtp_t);
  srtp_cfg = malloc (cfg_size);
  memset (srtp_cfg, 0, cfg_size);

  test_policy = &srtp_cfg->policy[0];
  test_policy->ssrc_type = 1 /* ssrc_specific */;
  test_policy->ssrc_value = rx_ssrc;
  memcpy (test_policy->key, test_key, sizeof (test_key));
  test_policy->key_len = sizeof (test_key);
  test_policy->window_size = 128;
  test_policy->allow_repeat_tx = 1;

  test_policy = &srtp_cfg->policy[1];
  test_policy->ssrc_type = 1 /* ssrc_specific */;
  test_policy->ssrc_value = tx_ssrc;
  memcpy (test_policy->key, test_key, sizeof (test_key));
  test_policy->key_len = sizeof (test_key);
  test_policy->window_size = 128;
  test_policy->allow_repeat_tx = 1;

  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_ENDPT_EXT_CFG, srtp_cfg,
		       &cfg_size);
  free (srtp_cfg);
}

static void
vt_srtp_session_init (vcl_test_session_t *ts, int is_connect)
{
  uint32_t rx_ssrc, tx_ssrc;
  rtp_headers_t *rtp_hdrs;
  rtp_hdr_t *hdr;

  rx_ssrc = is_connect ? 0xcafebeef : 0xbeefcafe;
  tx_ssrc = is_connect ? 0xbeefcafe : 0xcafebeef;

  rtp_hdrs = malloc (sizeof (rtp_headers_t));
  memset (rtp_hdrs, 0, sizeof (*rtp_hdrs));
  ts->opaque = rtp_hdrs;

  hdr = &rtp_hdrs->rx_hdr;
  hdr->version = 2;
  hdr->p = 0;
  hdr->x = 0;
  hdr->cc = 0;
  hdr->m = 0;
  hdr->pt = 0x1;
  hdr->seq = 0;
  hdr->ts = 0;
  hdr->ssrc = htonl (rx_ssrc);

  hdr = &rtp_hdrs->tx_hdr;
  hdr->version = 2;
  hdr->p = 0;
  hdr->x = 0;
  hdr->cc = 0;
  hdr->m = 0;
  hdr->pt = 0x1;
  hdr->seq = 0;
  hdr->ts = 0;
  hdr->ssrc = htonl (tx_ssrc);
}

static int
vt_srtp_write (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  int tx_bytes = 0, nbytes_left = nbytes, rv;
  vcl_test_stats_t *stats = &ts->stats;
  rtp_hdr_t *hdr;

  hdr = &((rtp_headers_t *) ts->opaque)->tx_hdr;
  hdr->seq = htons (ntohs (hdr->seq) + 1);
  hdr->ts = htonl (ntohl (hdr->ts) + 1);

  memcpy (buf, hdr, sizeof (*hdr));

  do
    {
      stats->tx_xacts++;
      rv = vppcom_session_write (ts->fd, buf, nbytes_left);
      if (rv < 0)
	{
	  if ((rv == VPPCOM_EAGAIN || rv == VPPCOM_EWOULDBLOCK))
	    stats->tx_eagain++;
	  break;
	}
      tx_bytes += rv;
      nbytes_left = nbytes_left - rv;
      buf += rv;
      stats->tx_incomp++;
    }
  while (tx_bytes != nbytes);

  if (tx_bytes < 0)
    return 0;

  stats->tx_bytes += tx_bytes;

  return (tx_bytes);
}

static inline int
vt_srtp_read (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  vcl_test_stats_t *stats = &ts->stats;
  rtp_hdr_t *hdr;
  int rx_bytes;

  stats->rx_xacts++;
  rx_bytes = vppcom_session_read (ts->fd, buf, nbytes);

  if (rx_bytes <= 0)
    {
      if (rx_bytes == VPPCOM_EAGAIN || rx_bytes == VPPCOM_EWOULDBLOCK)
	stats->rx_eagain++;
      else
	return -1;
    }

  if (rx_bytes < nbytes)
    stats->rx_incomp++;

  stats->rx_bytes += rx_bytes;

  hdr = &((rtp_headers_t *) ts->opaque)->rx_hdr;
  if (((rtp_hdr_t *) buf)->ssrc != hdr->ssrc)
    hdr->ssrc = ((rtp_hdr_t *) buf)->ssrc;
  return (rx_bytes);
}

static int
vt_srtp_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_SRTP, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  vt_session_add_srtp_policy (ts, 1 /* is connect */);

  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vt_srtp_read;
  ts->write = vt_srtp_write;
  ts->done = vcl_test_is_done;

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);
    }

  vt_srtp_session_init (ts, 1 /* is connect */);

  return 0;
}

static int
vt_srtp_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_SRTP, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  vt_session_add_srtp_policy (ts, 0 /* is connect */);

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}

static int
vt_srtp_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }
  ts->fd = client_fd;
  ts->is_open = 1;
  ts->read = vt_srtp_read;
  ts->write = vt_srtp_write;
  ts->done = vcl_test_is_done;

  vt_srtp_session_init (ts, 0 /* is connect */);

  return 0;
}

static int
vt_srtp_cleanup (vcl_test_session_t *ts)
{
  free (ts->opaque);
  return 0;
}

static const vcl_test_proto_vft_t vcl_test_srtp = {
  .open = vt_srtp_connect,
  .listen = vt_srtp_listen,
  .accept = vt_srtp_accept,
  .cleanup = vt_srtp_cleanup,
  .close = vcl_test_close_nop,
  .reset = vcl_test_reset_nop,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_SRTP, vcl_test_srtp);

static void
vt_http_session_init (vcl_test_session_t *ts, u8 is_server)
{
  vcl_test_http_ctx_t *http_ctx;

  http_ctx = malloc (sizeof (vcl_test_http_ctx_t));
  memset (http_ctx, 0, sizeof (*http_ctx));
  http_ctx->is_server = is_server;
  ts->opaque = http_ctx;
}

static inline void
vt_http_send_reply_msg (vcl_test_session_t *ts, http_status_code_t status)
{
  http_msg_t msg;
  int rv = 0;

  memset (&msg, 0, sizeof (http_msg_t));
  msg.type = HTTP_MSG_REPLY;
  msg.code = status;

  vppcom_data_segment_t segs[1] = { { (u8 *) &msg, sizeof (msg) } };

  do
    {
      rv = vppcom_session_write_segments (ts->fd, segs, 1);

      if (rv < 0)
	{
	  errno = -rv;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    continue;

	  vterr ("vppcom_session_write()", -errno);
	  break;
	}
    }
  while (rv <= 0);
}

static inline int
vt_process_http_server_read_msg (vcl_test_session_t *ts, void *buf,
				 uint32_t nbytes)
{
  http_msg_t msg;
  u8 *target_path = 0;
  vcl_test_http_ctx_t *vcl_test_http_ctx = (vcl_test_http_ctx_t *) ts->opaque;
  vcl_test_stats_t *stats = &ts->stats;
  int rv = 0;

  do
    {
      stats->rx_xacts++;
      rv = vppcom_session_read (ts->fd, buf, nbytes);

      if (rv <= 0)
	{
	  errno = -rv;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    {
	      stats->rx_eagain++;
	      continue;
	    }

	  vterr ("vppcom_session_read()", -errno);
	  return 0;
	}

      if (PREDICT_TRUE (vcl_test_http_ctx->test_state ==
			VCL_TEST_HTTP_IN_PROGRESS))
	{
	  vcl_test_http_ctx->rem_data -= rv;

	  if (vcl_test_http_ctx->rem_data == 0)
	    {
	      vcl_test_http_ctx->test_state = VCL_TEST_HTTP_COMPLETED;
	      vt_http_send_reply_msg (ts, HTTP_STATUS_OK);
	    }
	}
      else if (PREDICT_FALSE (vcl_test_http_ctx->test_state ==
			      VCL_TEST_HTTP_IDLE))
	{
	  msg = *(http_msg_t *) buf;

	  /* verify that we have received http post request from client */
	  if (msg.type != HTTP_MSG_REQUEST || msg.method_type != HTTP_REQ_POST)
	    {
	      vt_http_send_reply_msg (ts, HTTP_STATUS_METHOD_NOT_ALLOWED);
	      vterr ("error! only POST requests allowed from client", 0);
	      return 0;
	    }

	  /* validate target path syntax */
	  if (msg.data.target_path_len)
	    {
	      vec_validate (target_path, msg.data.target_path_len - 1);
	      memcpy (target_path, buf + sizeof (msg) + msg.data.target_path_offset,
		      msg.data.target_path_len);
	      if (http_validate_abs_path_syntax (target_path, 0))
		{
		  vt_http_send_reply_msg (ts, HTTP_STATUS_BAD_REQUEST);
		  vterr ("error! target path is not absolute", 0);
		  vec_free (target_path);
		  return 0;
		}
	      vec_free (target_path);
	    }

	  /* read body */
	  if (msg.data.body_len)
	    {
	      vcl_test_http_ctx->rem_data = msg.data.body_len;
	      /* | <http_msg_t> | <target> | <headers> | <body> | */
	      vcl_test_http_ctx->rem_data -=
		(rv - sizeof (msg) - msg.data.body_offset);
	      vcl_test_http_ctx->test_state = VCL_TEST_HTTP_IN_PROGRESS;
	    }
	}

      if (rv < nbytes)
	stats->rx_incomp++;
    }
  while (rv <= 0);

  stats->rx_bytes += rv;
  return (rv);
}

static inline int
vt_process_http_client_read_msg (vcl_test_session_t *ts, void *buf,
				 uint32_t nbytes)
{
  http_msg_t msg;
  int rv = 0;

  do
    {
      rv = vppcom_session_read (ts->fd, buf, nbytes);

      if (rv < 0)
	{
	  errno = -rv;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    continue;

	  vterr ("vppcom_session_read()", -errno);
	  break;
	}
    }
  while (!rv);

  msg = *(http_msg_t *) buf;

  if (msg.type == HTTP_MSG_REPLY && msg.code == HTTP_STATUS_OK)
    vtinf ("received 200 OK from server");
  else
    vterr ("received unexpected reply from server", 0);

  return (rv);
}

static inline int
vt_process_http_client_write_msg (vcl_test_session_t *ts, void *buf,
				  uint32_t nbytes)
{
  http_msg_t msg;
  http_headers_ctx_t req_headers;
  u8 *headers_buf = 0;
  u8 *target;
  vcl_test_http_ctx_t *vcl_test_http_ctx = (vcl_test_http_ctx_t *) ts->opaque;
  vcl_test_stats_t *stats = &ts->stats;
  int rv = 0;

  if (PREDICT_TRUE (vcl_test_http_ctx->test_state ==
		    VCL_TEST_HTTP_IN_PROGRESS))
    {
      do
	{
	  rv = vppcom_session_write (
	    ts->fd, buf, clib_min (nbytes, vcl_test_http_ctx->rem_data));

	  if (rv <= 0)
	    {
	      errno = -rv;
	      if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
		  stats->tx_eagain++;
		  continue;
		}

	      vterr ("vppcom_session_write()", -errno);
	      return 0;
	    }

	  vcl_test_http_ctx->rem_data -= rv;

	  if (vcl_test_http_ctx->rem_data == 0)
	    {
	      vcl_test_http_ctx->test_state = VCL_TEST_HTTP_COMPLETED;
	      vtinf ("client finished sending %ld bytes of data",
		     ts->cfg.total_bytes);
	    }

	  if (rv < nbytes)
	    stats->tx_incomp++;
	}
      while (rv <= 0);
    }

  else if (PREDICT_FALSE (vcl_test_http_ctx->test_state == VCL_TEST_HTTP_IDLE))
    {
      vec_validate (headers_buf, 63);
      http_init_headers_ctx (&req_headers, headers_buf, vec_len (headers_buf));
      http_add_header (
	&req_headers, HTTP_HEADER_CONTENT_TYPE,
	http_content_type_token (HTTP_CONTENT_APP_OCTET_STREAM));

      memset (&msg, 0, sizeof (http_msg_t));
      msg.type = HTTP_MSG_REQUEST;
      msg.method_type = HTTP_REQ_POST;

      /* target */
      target = (u8 *) "/vcl_test_http\0";
      msg.data.target_path_len = strlen ((char *) target);

      /* headers */
      msg.data.headers_offset = msg.data.target_path_len;
      msg.data.headers_len = req_headers.tail_offset;

      /* body */
      msg.data.body_offset = msg.data.headers_offset + msg.data.headers_len;
      msg.data.body_len = ts->cfg.total_bytes;

      msg.data.len =
	msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;
      msg.data.type = HTTP_MSG_DATA_INLINE;

      vppcom_data_segment_t segs[3] = { { (u8 *) &msg, sizeof (msg) },
					{ target, strlen ((char *) target) },
					{ headers_buf,
					  msg.data.headers_len } };

      do
	{
	  rv = vppcom_session_write_segments (ts->fd, segs, 3);

	  if (rv <= 0)
	    {
	      errno = -rv;
	      if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
		  stats->tx_eagain++;
		  continue;
		}

	      vterr ("vppcom_session_write_segments()", -errno);
	      vec_free (headers_buf);
	      return 0;
	    }
	}
      while (rv <= 0);

      vcl_test_http_ctx->test_state = VCL_TEST_HTTP_IN_PROGRESS;
      vcl_test_http_ctx->rem_data = ts->cfg.total_bytes;
      vec_free (headers_buf);
    }

  stats->tx_bytes += rv;
  return (rv);
}

static inline int
vt_process_http_server_write_msg (vcl_test_session_t *ts, void *buf,
				  uint32_t nbytes)
{
  return 0;
}

static inline int
vt_http_read (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  vcl_test_http_ctx_t *vcl_test_http_ctx = (vcl_test_http_ctx_t *) ts->opaque;

  if (vcl_test_http_ctx->is_server)
    return vt_process_http_server_read_msg (ts, buf, nbytes);
  else
    return vt_process_http_client_read_msg (ts, buf, nbytes);
}

static inline int
vt_http_write (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  vcl_test_http_ctx_t *vcl_test_http_ctx = (vcl_test_http_ctx_t *) ts->opaque;

  if (vcl_test_http_ctx->is_server)
    return vt_process_http_server_write_msg (ts, buf, nbytes);
  else
    return vt_process_http_client_write_msg (ts, buf, nbytes);
}

static int
vt_http_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_HTTP, ts->noblk_connect);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0 && rv != VPPCOM_EINPROGRESS)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vt_http_read;
  ts->write = vt_http_write;
  ts->done = vcl_test_is_done;

  if (!ts->noblk_connect)
    {
      flags = O_NONBLOCK;
      flen = sizeof (flags);
      vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
      vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);
    }

  vt_http_session_init (ts, 0 /* is_server */);

  return 0;
}

static int
vt_http_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_HTTP, 1 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}

static int
vt_http_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return client_fd;
    }

  ts->fd = client_fd;
  ts->is_open = 1;
  ts->read = vt_http_read;
  ts->write = vt_http_write;
  ts->done = vcl_test_is_done;

  vt_http_session_init (ts, 1 /* is_server */);

  return 0;
}

static int
vt_http_cleanup (vcl_test_session_t *ts)
{
  free (ts->opaque);
  return 0;
}

static const vcl_test_proto_vft_t vcl_test_http = {
  .open = vt_http_connect,
  .listen = vt_http_listen,
  .accept = vt_http_accept,
  .cleanup = vt_http_cleanup,
  .close = vcl_test_close_nop,
  .reset = vcl_test_reset_nop,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_HTTP, vcl_test_http);
