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

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
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

  ts->fd = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
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

static int
vt_tls_init (vcl_test_cfg_t *cfg)
{
  vcl_test_main_t *vt = &vcl_test_main;
  vppcom_cert_key_pair_t ckpair;
  uint32_t ckp_len;
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
  ckp_len = sizeof (ckp_index);

  return 0;
}

static int
vt_tls_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TLS, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  uint32_t ckp_len = sizeof (vt->ckpair_index);
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

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TLS, 0 /* is_nonblocking */);
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
  vcl_test_main_t *vt = &vcl_test_main;
  vppcom_cert_key_pair_t ckpair;
  uint32_t ckp_len;
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
  ckp_len = sizeof (ckp_index);

  return 0;
}

static int
vt_dtls_connect (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t flags, flen;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_DTLS, 0 /* is_nonblocking */);
  if (ts->fd < 0)
    {
      vterr ("vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  uint32_t ckp_len = sizeof (vt->ckpair_index);
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

  ts->fd = vppcom_session_create (VPPCOM_PROTO_DTLS, 0 /* is_nonblocking */);
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
  vppcom_cert_key_pair_t ckpair;
  uint32_t ckp_len;
  int ckp_index;

  if (cfg)
    vt->cfg = *cfg;

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
  ckp_len = sizeof (ckp_index);
  return 0;
}

static int
vt_quic_maybe_init_wrk (vcl_test_main_t *vt, vcl_test_wrk_t *wrk, vppcom_endpt_t *endpt)
{
  uint32_t size, i, flags, flen;
  vcl_test_session_t *tq;
  int rv;

  /* Test already initialized */
  if (wrk->n_qsessions == vt->cfg.num_test_qsessions)
    return 0;

  /* Make sure pool is large enough */
  if (!wrk->qsessions)
    {
      wrk->qsessions = calloc (vt->cfg.num_test_qsessions,
                               sizeof (vcl_test_session_t));
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
      tq->fd = vppcom_session_create (VPPCOM_PROTO_QUIC, 0 /* is_nonblocking */ );
      tq->session_index = i;
      if (tq->fd < 0)
	{
	  vterr ("vppcom_session_create()", tq->fd);
	  return tq->fd;
	}

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
  vcl_test_session_t *tq;
  vcl_test_wrk_t *wrk;
  uint32_t wrk_index;
  int rv;

  wrk_index = vcl_test_worker_index ();
  wrk = &vt->wrk[wrk_index];

  /* Make sure qsessions are initialized */
  vt_quic_maybe_init_wrk (vt, wrk, endpt);

  ts->fd = vppcom_session_create (VPPCOM_PROTO_QUIC, 1 /* is_nonblocking */ );
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
      vterr("vppcom_session_stream_connect()", rv);
      return rv;
    }

  vtinf ("Test session %d (fd %d) connected.", ts->session_index, ts->fd);

  return 0;
}

static int
vt_quic_listen (vcl_test_session_t *ts, vppcom_endpt_t *endpt)
{
  vcl_test_main_t *vt = &vcl_test_main;
  uint32_t ckp_len;
  int rv;

  ts->fd = vppcom_session_create (VPPCOM_PROTO_QUIC, 0 /* is_nonblocking */);
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
