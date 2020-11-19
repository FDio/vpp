/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <openssl/bio.h>
#include <openssl/err.h>

#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

static inline session_t *
bio_session (BIO * bio)
{
  return session_get_from_handle (pointer_to_uword (BIO_get_data (bio)));
}

static int
bio_dtls_alloc (BIO * bio)
{
  BIO_set_init (bio, 0);
  BIO_set_data (bio, 0);
  BIO_set_flags (bio, 0);
  BIO_set_shutdown (bio, 0);
  return 1;
}

static int
bio_dtls_free (BIO * bio)
{
  if (!bio)
    return 0;

  if (BIO_get_shutdown (bio))
    {
      if (BIO_get_init (bio))
	session_close (bio_session (bio));
      BIO_set_init (bio, 0);
      BIO_set_flags (bio, 0);
    }
  return 1;
}

static int
bio_dtls_read (BIO * b, char *out, int outl)
{
  app_session_transport_t at;
  session_t *s;
  int rv;

  if (PREDICT_FALSE (!out))
    return 0;

  s = bio_session (b);
  if (!s)
    {
      clib_warning ("no session");
      errno = EBADFD;
      return -1;
    }

  rv = app_recv_dgram_raw (s->rx_fifo, (u8 *) out, outl, &at,
			   0 /* clear evt */ , 0 /* peek */ );

  if (rv < 0)
    {
      BIO_set_retry_read (b);
      errno = EAGAIN;
      return -1;
    }

  if (svm_fifo_is_empty_cons (s->rx_fifo))
    svm_fifo_unset_event (s->rx_fifo);

  BIO_clear_retry_flags (b);

  return rv;
}

static int
bio_dtls_write (BIO * b, const char *in, int inl)
{
  app_session_transport_t at;
  svm_msg_q_t *mq;
  session_t *s;
  int rv;

  if (PREDICT_FALSE (!in))
    return 0;

  s = bio_session (b);
  if (!s)
    {
      clib_warning ("no session");
      errno = EBADFD;
      return -1;
    }

  mq = session_main_get_vpp_event_queue (s->thread_index);
  rv = app_send_dgram_raw (s->tx_fifo, &at, mq, (u8 *) in, inl,
			   SESSION_IO_EVT_TX, 1 /* do_evt */ ,
			   0 /* noblock */ );

  if (rv < 0)
    {
      BIO_set_retry_read (b);
      errno = EAGAIN;
      return -1;
    }

  BIO_clear_retry_flags (b);

  return rv;
}

static int
dtls_dgram_overhead (BIO * b)
{
  session_t *s = bio_session (b);
  if (session_type_is_ip4 (s->session_type))
    /* 20B ip 8B udp */
    return 28;
  else
    /* 40B ip 8B udp */
    return 48;
}

long
bio_dtls_ctrl (BIO * b, int cmd, long larg, void *parg)
{
  long ret = 1;

  switch (cmd)
    {
    case BIO_C_SET_FD:
      os_panic ();
      break;
    case BIO_C_GET_FD:
      os_panic ();
      break;
    case BIO_CTRL_GET_CLOSE:
      ret = BIO_get_shutdown (b);
      break;
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown (b, (int) larg);
      break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
      ret = 0;
      break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      ret = 1;
      break;
    case BIO_CTRL_DGRAM_QUERY_MTU:
      ret = 1460;
      break;
    case BIO_CTRL_DGRAM_SET_MTU:
      ret = 0;
      break;
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
      ret = 0;
      break;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
      ret = dtls_dgram_overhead (b);
      break;
    default:
      clib_warning ("unknown %u", cmd);
      ret = 0;
      break;
    }
  return ret;
}

BIO *
BIO_new_dtls (session_handle_t sh)
{
  static BIO_METHOD *dtls_bio_method;
  BIO *b;

  if (!dtls_bio_method)
    {
      dtls_bio_method = BIO_meth_new (BIO_TYPE_SOCKET, "dtls_bio");
      BIO_meth_set_write (dtls_bio_method, bio_dtls_write);
      BIO_meth_set_read (dtls_bio_method, bio_dtls_read);
      BIO_meth_set_create (dtls_bio_method, bio_dtls_alloc);
      BIO_meth_set_destroy (dtls_bio_method, bio_dtls_free);
      BIO_meth_set_ctrl (dtls_bio_method, bio_dtls_ctrl);
    }

  b = BIO_new (dtls_bio_method);

  /* Initialize the BIO */
  BIO_set_data (b, uword_to_pointer (sh, void *));
  BIO_set_init (b, 1);

  return b;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
