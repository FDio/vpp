/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#define NETCP_VERSION 1

#define foreach_netcp_type                      \
_(SEND_FILE, send_file)                         \
_(DATA, data)                                   \
_(ACK, ack)

typedef enum {
#define _(a,b) NETCP_TYPE_##a,
  foreach_netcp_type
#undef _
  NETCP_N_TYPES,
} netcp_header_type_t;

typedef CLIB_PACKED (struct {
  u8 netcp_version;
  u8 type;
  u32 session_id;
}) netcp_header_t;

/* 
 * type 0: take this file, please
 * $$$ maybe fix PATH_MAX later. For now: fragments need apply 
 */
#define NETCP_PATH_MAX	512

typedef CLIB_PACKED (struct {
  u8 dst_filename[NETCP_PATH_MAX];
  u16 segment_size;
  u64 size_in_bytes;
  
  /* $$$$ more options */
}) netcp_send_file_header_t;

/* 
 * type 1: data
 */
typedef CLIB_PACKED (struct {
  u64 offset;
  u8 data[0];
}) nectp_data_header_t;

/* 
 * type 2: ack
 */
typedef CLIB_PACKED (struct {
  i32 retval;
  u64 offset;
}) nectp_ack_header_t;

