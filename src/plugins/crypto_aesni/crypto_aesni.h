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

#ifndef included_aesni_h
#define included_aesni_h

vnet_crypto_queue_handler_t aesni_queue_enc_aes_cbc_128;
vnet_crypto_queue_handler_t aesni_queue_dec_aes_cbc_128;

vnet_crypto_ops_handler_t aesni_ops_enc_aes_cbc_128;
vnet_crypto_ops_handler_t aesni_ops_enc_aes_cbc_192;
vnet_crypto_ops_handler_t aesni_ops_enc_aes_cbc_256;
vnet_crypto_ops_handler_t aesni_ops_dec_aes_cbc_128;
vnet_crypto_ops_handler_t aesni_ops_dec_aes_cbc_192;
vnet_crypto_ops_handler_t aesni_ops_dec_aes_cbc_256;

#endif /* included_aesni_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
