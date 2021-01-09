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

#ifndef SRC_PLUGINS_TLSOPENSSL_TLS_BIO_H_
#define SRC_PLUGINS_TLSOPENSSL_TLS_BIO_H_

#include <vnet/session/session_types.h>

BIO *BIO_new_tls (session_handle_t sh);
BIO *BIO_new_dtls (session_handle_t sh);

#endif /* SRC_PLUGINS_TLSOPENSSL_TLS_BIO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
