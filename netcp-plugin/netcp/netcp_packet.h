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

typedef enum {
  NETCP_TYPE_DATA = 0,
  NETCP_TYPE_SEND_FILE,
  NETCP_TYPE_SEND_FILE_REPLY,
  NETCP_TYPE_RESEND_FROM_OFFSET,
  NETCP_TYPE_DONE,
} netcp_header_type_t;

typedef CLIB_PACKED (struct {
  u8 netcp_version;
  u8 type;
  u32 session_id;
}) netcp_header_t;

/* 
 * type 0: data
 */
typedef CLIB_PACKED (struct {
  u64 offset;
  u8 data[0];
}) nectp_data_header_t;

/* 
 * type 1: take this file, please
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
 * type 2: rv = 0 => OK, otherwise error
 */
typedef CLIB_PACKED (struct {
  i8 rv;
  u16 segment_size;
  /* $$$$ more options */
}) netcp_send_file_reply_header_t;

/* 
 * type 3: resend from offset, 
 */
typedef CLIB_PACKED (struct {
  u64 offset;
  u32 nsegments;
}) netcp_backup_header_t;

/* 
 * type 4: done rv = 0 => OK, otherwise error
 */
typedef CLIB_PACKED (struct {
  i8 rv;
}) netcp_backup_header_t;

