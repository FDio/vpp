/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef vapi_common_h_included
#define vapi_common_h_included

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
  VAPI_OK = 0,	      /**< success */
  VAPI_EINVAL,	      /**< invalid value encountered */
  VAPI_EAGAIN,	      /**< operation would block */
  VAPI_ENOTSUP,	      /**< operation not supported */
  VAPI_ENOMEM,	      /**< out of memory */
  VAPI_ENORESP,	      /**< no response to request */
  VAPI_EMAP_FAIL,     /**< failure while mapping api */
  VAPI_ECON_FAIL,     /**< failure while connecting to vpp */
  VAPI_EINCOMPATIBLE, /**< fundamental incompatibility while connecting to vpp
                           (control ping/control ping reply mismatch) */
  VAPI_MUTEX_FAILURE, /**< failure manipulating internal mutex(es) */
  VAPI_EUSER,	      /**< user error used for breaking dispatch,
                           never used by VAPI */
} vapi_error_e;

typedef enum
{
  VAPI_MODE_BLOCKING = 1,    /**< operations block until response received */
  VAPI_MODE_NONBLOCKING = 2, /**< operations never block */
} vapi_mode_e;

typedef enum
{
  VAPI_WAIT_FOR_READ,	     /**< wait until some message is readable */
  VAPI_WAIT_FOR_WRITE,	     /**< wait until a message can be written */
  VAPI_WAIT_FOR_READ_WRITE,  /**< wait until a read or write can be done */
} vapi_wait_mode_e;

typedef unsigned int vapi_msg_id_t;

#define INVALID_MSG_ID ((vapi_msg_id_t)(~0))

#ifdef __cplusplus
}
#endif

#endif
