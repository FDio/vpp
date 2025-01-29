/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <openssl/pem.h>

#include <vppinfra/error.h>

#include <quic_quicly/ptls_certs.h>

int
ptls_compare_separator_line (const char *line, const char *begin_or_end,
                             const char *label)
{
  int ret = strncmp (line, "-----", 5);
  size_t text_index = 5;

  if (ret == 0)
    {
      size_t begin_or_end_length = strlen (begin_or_end);
      ret = strncmp (line + text_index, begin_or_end, begin_or_end_length);
      text_index += begin_or_end_length;
    }

  if (ret == 0)
    {
      ret = line[text_index] - ' ';
      text_index++;
    }

  if (ret == 0)
    {
      size_t label_length = strlen (label);
      ret = strncmp (line + text_index, label, label_length);
      text_index += label_length;
    }

  if (ret == 0)
    {
      ret = strncmp (line + text_index, "-----", 5);
    }

  return ret;
}

int
ptls_get_bio_pem_object (BIO * bio, const char *label, ptls_buffer_t * buf)
{
  int ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
  char line[256];
  ptls_base64_decode_state_t state;

  /* Get the label on a line by itself */
  while (BIO_gets (bio, line, 256))
    {
      if (ptls_compare_separator_line (line, "BEGIN", label) == 0)
        {
          ret = 0;
          ptls_base64_decode_init (&state);
          break;
        }
    }
  /* Get the data in the buffer */
  while (ret == 0 && BIO_gets (bio, line, 256))
    {
      if (ptls_compare_separator_line (line, "END", label) == 0)
        {
          if (state.status == PTLS_BASE64_DECODE_DONE
              || (state.status == PTLS_BASE64_DECODE_IN_PROGRESS
                  && state.nbc == 0))
            {
              ret = 0;
            }
          else
            {
              ret = PTLS_ERROR_INCORRECT_BASE64;
            }
          break;
        }
      else
        {
          ret = ptls_base64_decode (line, &state, buf);
        }
    }

  return ret;
}

int
ptls_load_bio_pem_objects (BIO * bio, const char *label, ptls_iovec_t * list,
                           size_t list_max, size_t * nb_objects)
{
  int ret = 0;
  size_t count = 0;

  *nb_objects = 0;

  if (ret == 0)
    {
      while (count < list_max)
        {
          ptls_buffer_t buf;

          ptls_buffer_init (&buf, "", 0);

          ret = ptls_get_bio_pem_object (bio, label, &buf);

          if (ret == 0)
            {
              if (buf.off > 0 && buf.is_allocated)
                {
                  list[count].base = buf.base;
                  list[count].len = buf.off;
                  count++;
                }
              else
                {
                  ptls_buffer_dispose (&buf);
                }
            }
          else
            {
              ptls_buffer_dispose (&buf);
              break;
            }
        }
    }

  if (ret == PTLS_ERROR_PEM_LABEL_NOT_FOUND && count > 0)
    {
      ret = 0;
    }

  *nb_objects = count;

  return ret;
}

#define PTLS_MAX_CERTS_IN_CONTEXT 16

int
ptls_load_bio_certificates (ptls_context_t * ctx, BIO * bio)
{
  int ret = 0;

  ctx->certificates.list =
    (ptls_iovec_t *) malloc (PTLS_MAX_CERTS_IN_CONTEXT *
                             sizeof (ptls_iovec_t));

  if (ctx->certificates.list == NULL)
    {
      ret = PTLS_ERROR_NO_MEMORY;
    }
  else
    {
      ret =
        ptls_load_bio_pem_objects (bio, "CERTIFICATE", ctx->certificates.list,
                                   PTLS_MAX_CERTS_IN_CONTEXT,
                                   &ctx->certificates.count);
    }

  return ret;
}

int
load_bio_certificate_chain (ptls_context_t * ctx, const char *cert_data)
{
  BIO *cert_bio;
  cert_bio = BIO_new_mem_buf (cert_data, -1);
  if (ptls_load_bio_certificates (ctx, cert_bio) != 0)
    {
      BIO_free (cert_bio);
      return -1;
    }
  BIO_free (cert_bio);
  return 0;
}

int
load_bio_private_key (ptls_context_t * ctx, const char *pk_data)
{
  static ptls_openssl_sign_certificate_t sc;
  EVP_PKEY *pkey;
  BIO *key_bio;

  key_bio = BIO_new_mem_buf (pk_data, -1);
  pkey = PEM_read_bio_PrivateKey (key_bio, NULL, NULL, NULL);
  BIO_free (key_bio);

  if (pkey == NULL)
    return -1;

  ptls_openssl_init_sign_certificate (&sc, pkey);
  EVP_PKEY_free (pkey);

  ctx->sign_certificate = &sc.super;
  return 0;
}
