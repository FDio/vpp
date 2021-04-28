/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <hs_apps/vcl/vcl_test.h>

static int
vt_tcp_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  /* Connect is blocking */
  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  flags = O_NONBLOCK;
  flen = sizeof (flags);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
  vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);

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

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_tcp = {
  .open = vt_tcp_connect,
  .listen = vt_tcp_listen,
  .accept = vt_tcp_accept,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_TCP, vcl_test_tcp);

static int
vt_udp_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  /* Connect is blocking */
  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  flags = O_NONBLOCK;
  flen = sizeof (flags);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
  vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);

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
  ts->write = vcl_test_write;

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_udp = {
  .open = vt_udp_connect,
  .listen = vt_udp_listen,
  .accept = vt_udp_accept,
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
vt_tls_init (vcl_test_cfg_t *cfg)
{
  return vt_add_cert_key_pair ();
}

static int
vt_tls_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t flags, flen, ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TLS, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  /* Connect is blocking */
  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  flags = O_NONBLOCK;
  flen = sizeof (flags);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
  vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);

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

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_tls = {
  .init = vt_tls_init,
  .open = vt_tls_connect,
  .listen = vt_tls_listen,
  .accept = vt_tls_accept,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_TLS, vcl_test_tls);

static int
vt_dtls_init (vcl_test_cfg_t *cfg)
{
  return vt_add_cert_key_pair ();
}

static int
vt_dtls_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t flags, flen, ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_DTLS, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  ckp_len = sizeof (vt->ckpair_index);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_CKPAIR, &vt->ckpair_index,
		       &ckp_len);

  /* Connect is blocking */
  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;
  flags = O_NONBLOCK;
  flen = sizeof (flags);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);
  vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);

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

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_dtls = {
  .init = vt_dtls_init,
  .open = vt_dtls_connect,
  .listen = vt_dtls_listen,
  .accept = vt_dtls_accept,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_DTLS, vcl_test_dtls);

static int
vt_quic_init (vcl_test_cfg_t *cfg)
{
  vcl_test_main_t *vt = &vcl_test_main;

  if (cfg)
    vt->cfg = *cfg;

  return vt_add_cert_key_pair ();
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

  ts->fd = vppcom_session_create (VPPCOM_PROTO_QUIC, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  /* Choose qession to use for stream */
  tq = &wrk->qsessions[ts->session_index / vt->cfg.num_test_sessions_perq];

  rv = vppcom_session_stream_connect (ts->fd, tq->fd);
  if (rv < 0)
    {
      vterr ("vppcom_session_stream_connect()", rv);
      return rv;
    }

  flags = O_NONBLOCK;
  flen = sizeof (flags);
  vppcom_session_attr (ts->fd, VPPCOM_ATTR_SET_FLAGS, &flags, &flen);

  ts->read = vcl_test_read;
  ts->write = vcl_test_write;

  vtinf ("Test (quic stream) session %d (fd %d) connected.", ts->session_index,
	 ts->fd);

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
vt_quic_accept (int listen_fd, vcl_test_session_t *ts)
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

  return 0;
}

static int
vt_quic_close (vcl_test_session_t *ts)
{
  int listener_fd = vppcom_session_listener (ts->fd);

  if ((vppcom_session_n_accepted (listener_fd) == 0) &
      vppcom_session_is_connectable_listener (listener_fd))
    {
      vtinf ("Connected Listener fd %x has no more sessions", listener_fd);
      vppcom_session_close (listener_fd);
    }

  return 0;
}

static const vcl_test_proto_vft_t vcl_test_quic = {
  .init = vt_quic_init,
  .open = vt_quic_connect,
  .listen = vt_quic_listen,
  .accept = vt_quic_accept,
  .close = vt_quic_close,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_QUIC, vcl_test_quic);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
