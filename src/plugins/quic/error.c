/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <quic/quic.h>

#include <quicly.h>
#include <quicly/constants.h>

u8 *
quic_format_err (u8 * s, va_list * args)
{
  u64 code = va_arg (*args, u64);
  switch (code)
    {
    case 0:
      s = format (s, "no error");
      break;
      /* app errors */
    case QUIC_ERROR_FULL_FIFO:
      s = format (s, "full fifo");
      break;
    case QUIC_APP_ERROR_CLOSE_NOTIFY:
      s = format (s, "QUIC_APP_ERROR_CLOSE_NOTIFY");
      break;
    case QUIC_APP_ALLOCATION_ERROR:
      s = format (s, "QUIC_APP_ALLOCATION_ERROR");
      break;
    case QUIC_APP_ACCEPT_NOTIFY_ERROR:
      s = format (s, "QUIC_APP_ACCEPT_NOTIFY_ERROR");
      break;
    case QUIC_APP_CONNECT_NOTIFY_ERROR:
      s = format (s, "QUIC_APP_CONNECT_NOTIFY_ERROR");
      break;
      /* quicly errors */
    case QUICLY_ERROR_PACKET_IGNORED:
      s = format (s, "QUICLY_ERROR_PACKET_IGNORED");
      break;
    case QUICLY_ERROR_SENDBUF_FULL:
      s = format (s, "QUICLY_ERROR_SENDBUF_FULL");
      break;
    case QUICLY_ERROR_FREE_CONNECTION:
      s = format (s, "QUICLY_ERROR_FREE_CONNECTION");
      break;
    case QUICLY_ERROR_RECEIVED_STATELESS_RESET:
      s = format (s, "QUICLY_ERROR_RECEIVED_STATELESS_RESET");
      break;
    case QUICLY_TRANSPORT_ERROR_NONE:
      s = format (s, "QUICLY_TRANSPORT_ERROR_NONE");
      break;
    case QUICLY_TRANSPORT_ERROR_INTERNAL:
      s = format (s, "QUICLY_TRANSPORT_ERROR_INTERNAL");
      break;
    case QUICLY_TRANSPORT_ERROR_CONNECTION_REFUSED:
      s = format (s, "QUICLY_TRANSPORT_ERROR_CONNECTION_REFUSED");
      break;
    case QUICLY_TRANSPORT_ERROR_FLOW_CONTROL:
      s = format (s, "QUICLY_TRANSPORT_ERROR_FLOW_CONTROL");
      break;
    case QUICLY_TRANSPORT_ERROR_STREAM_LIMIT:
      s = format (s, "QUICLY_TRANSPORT_ERROR_STREAM_LIMIT");
      break;
    case QUICLY_TRANSPORT_ERROR_STREAM_STATE:
      s = format (s, "QUICLY_TRANSPORT_ERROR_STREAM_STATE");
      break;
    case QUICLY_TRANSPORT_ERROR_FINAL_SIZE:
      s = format (s, "QUICLY_TRANSPORT_ERROR_FINAL_SIZE");
      break;
    case QUICLY_TRANSPORT_ERROR_FRAME_ENCODING:
      s = format (s, "QUICLY_TRANSPORT_ERROR_FRAME_ENCODING");
      break;
    case QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER:
      s = format (s, "QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER");
      break;
    case QUICLY_ERROR_NO_COMPATIBLE_VERSION:
      s = format (s, "QUICLY_ERROR_NO_COMPATIBLE_VERSION");
      break;
    case QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION:
      s = format (s, "QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION");
      break;
    case QUICLY_TRANSPORT_ERROR_CRYPTO_BUFFER_EXCEEDED:
      s = format (s, "QUICLY_TRANSPORT_ERROR_CRYPTO_BUFFER_EXCEEDED");
      break;
      /* picotls errors */
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_CLOSE_NOTIFY):
      s =
        format (s, "PTLS_ALERT_CLOSE_NOTIFY");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_UNEXPECTED_MESSAGE):
      s =
        format (s, "PTLS_ALERT_UNEXPECTED_MESSAGE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_BAD_RECORD_MAC):
      s =
        format (s, "PTLS_ALERT_BAD_RECORD_MAC");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_HANDSHAKE_FAILURE):
      s =
        format (s, "PTLS_ALERT_HANDSHAKE_FAILURE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_BAD_CERTIFICATE):
      s =
        format (s, "PTLS_ALERT_BAD_CERTIFICATE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_CERTIFICATE_REVOKED):
      s =
        format (s, "PTLS_ALERT_CERTIFICATE_REVOKED");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_CERTIFICATE_EXPIRED):
      s =
        format (s, "PTLS_ALERT_CERTIFICATE_EXPIRED");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_CERTIFICATE_UNKNOWN):
      s =
        format (s, "PTLS_ALERT_CERTIFICATE_UNKNOWN");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_ILLEGAL_PARAMETER):
      s =
        format (s, "PTLS_ALERT_ILLEGAL_PARAMETER");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_UNKNOWN_CA):
      s =
        format (s, "PTLS_ALERT_UNKNOWN_CA");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_DECODE_ERROR):
      s =
        format (s, "PTLS_ALERT_DECODE_ERROR");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_DECRYPT_ERROR):
      s =
        format (s, "PTLS_ALERT_DECRYPT_ERROR");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_PROTOCOL_VERSION):
      s =
        format (s, "PTLS_ALERT_PROTOCOL_VERSION");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_INTERNAL_ERROR):
      s =
        format (s, "PTLS_ALERT_INTERNAL_ERROR");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_USER_CANCELED):
      s =
        format (s, "PTLS_ALERT_USER_CANCELED");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_MISSING_EXTENSION):
      s =
        format (s, "PTLS_ALERT_MISSING_EXTENSION");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_UNRECOGNIZED_NAME):
      s =
        format (s, "PTLS_ALERT_UNRECOGNIZED_NAME");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_CERTIFICATE_REQUIRED):
      s =
        format (s, "PTLS_ALERT_CERTIFICATE_REQUIRED");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ALERT_NO_APPLICATION_PROTOCOL):
      s =
        format (s, "PTLS_ALERT_NO_APPLICATION_PROTOCOL");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_NO_MEMORY):
      s =
        format (s, "PTLS_ERROR_NO_MEMORY");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_IN_PROGRESS):
      s =
        format (s, "PTLS_ERROR_IN_PROGRESS");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_LIBRARY):
      s =
        format (s, "PTLS_ERROR_LIBRARY");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCOMPATIBLE_KEY):
      s =
        format (s, "PTLS_ERROR_INCOMPATIBLE_KEY");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_SESSION_NOT_FOUND):
      s =
        format (s, "PTLS_ERROR_SESSION_NOT_FOUND");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_STATELESS_RETRY):
      s =
        format (s, "PTLS_ERROR_STATELESS_RETRY");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_NOT_AVAILABLE):
      s =
        format (s, "PTLS_ERROR_NOT_AVAILABLE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_COMPRESSION_FAILURE):
      s =
        format (s, "PTLS_ERROR_COMPRESSION_FAILURE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_BER_INCORRECT_ENCODING):
      s =
        format (s, "PTLS_ERROR_BER_INCORRECT_ENCODING");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_BER_MALFORMED_TYPE):
      s =
        format (s, "PTLS_ERROR_BER_MALFORMED_TYPE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_BER_MALFORMED_LENGTH):
      s =
        format (s, "PTLS_ERROR_BER_MALFORMED_LENGTH");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_BER_EXCESSIVE_LENGTH):
      s =
        format (s, "PTLS_ERROR_BER_EXCESSIVE_LENGTH");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_BER_ELEMENT_TOO_SHORT):
      s =
        format (s, "PTLS_ERROR_BER_ELEMENT_TOO_SHORT");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_BER_UNEXPECTED_EOC):
      s =
        format (s, "PTLS_ERROR_BER_UNEXPECTED_EOC");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_DER_INDEFINITE_LENGTH):
      s =
        format (s, "PTLS_ERROR_DER_INDEFINITE_LENGTH");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCORRECT_ASN1_SYNTAX):
      s =
        format (s, "PTLS_ERROR_INCORRECT_ASN1_SYNTAX");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCORRECT_PEM_KEY_VERSION):
      s =
        format (s, "PTLS_ERROR_INCORRECT_PEM_KEY_VERSION");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCORRECT_PEM_ECDSA_KEY_VERSION):
      s =
        format (s, "PTLS_ERROR_INCORRECT_PEM_ECDSA_KEY_VERSION");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCORRECT_PEM_ECDSA_CURVE):
      s =
        format (s, "PTLS_ERROR_INCORRECT_PEM_ECDSA_CURVE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCORRECT_PEM_ECDSA_KEYSIZE):
      s =
        format (s, "PTLS_ERROR_INCORRECT_PEM_ECDSA_KEYSIZE");
      break;
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE + PTLS_ERROR_TO_ALERT (PTLS_ERROR_INCORRECT_ASN1_ECDSA_KEY_SYNTAX):
      s =
        format (s, "PTLS_ERROR_INCORRECT_ASN1_ECDSA_KEY_SYNTAX");
      break;
    default:
      s = format (s, "unknown error 0x%lx", code);
      break;
    }
  return s;
}
