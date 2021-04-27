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

  ts->fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */ );
  if (ts->fd < 0)
    {
      vterr ("tcp vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  /* Connect is blocking */
  rv = vppcom_session_connect (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("tcp vppcom_session_connect()", rv);
      return rv;
    }

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
      vterr ("tcp vppcom_session_create()", ts->fd);
      return ts->fd;
    }

  rv = vppcom_session_bind (ts->fd, endpt);
  if (rv < 0)
    {
      vterr ("tcp vppcom_session_bind()", rv);
      return rv;
    }

  rv = vppcom_session_listen (ts->fd, 10);
  if (rv < 0)
    {
      vterr ("tcp vppcom_session_listen()", rv);
      return rv;
    }

  return 0;
}


int
vt_tcp_accept (int listen_fd, vcl_test_session_t *ts)
{
  int client_fd;

  client_fd = vppcom_session_accept (listen_fd, &ts->endpt, 0);
  if (client_fd < 0)
    {
      vterr("tcp vppcom_session_accept()", client_fd);
      return 0;
    }
  ts->fd = client_fd;
  ts->is_open = 1;

  return 0;
}

static vcl_test_proto_vft_t vcl_test_tcp = {
    .open = vt_tcp_connect,
    .listen = vt_tcp_listen,
    .accept = vt_tcp_accept,
};

VCL_TEST_REGISTER_PROTO (VPPCOM_PROTO_TCP, vcl_test_tcp);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */



