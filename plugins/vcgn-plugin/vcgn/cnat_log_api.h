/*
 *------------------------------------------------------------------
 * cnat_log_api.h
 * Declraes the common APIs for logging (both syslog and NFV9)
 * Copyright (c) 2013, 20122 Cisco and/or its affiliates.
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

#ifndef __CNAT_LOG_API_H__ 
#define __CNAT_LOG_API_H__ 

#include "cnat_logging.h"

static inline void cnat_log_ds_lite_mapping_delete(cnat_main_db_entry_t *db,
    dslite_table_entry_t *dslite_entry
#ifndef NO_BULK_LOGGING
     , int bulk_alloc
#endif
    )
{
    return;
}

static inline void cnat_log_ds_lite_mapping_create(cnat_main_db_entry_t *db,
    dslite_table_entry_t *dslite_entry
#ifndef NO_BULK_LOGGING
     , int bulk_alloc
#endif
    )
{
    return;
}

static inline void cnat_log_ds_lite_port_limit_exceeded(
    dslite_key_t   * key,
    dslite_table_entry_t *dslite_entry_ptr)
{
    return;

}

static inline void cnat_log_nat44_port_limit_exceeded(
    cnat_key_t   * key,
    cnat_vrfmap_t *vrfmap)
{
    return;
}
static inline void cnat_log_nat44_mapping_create(cnat_main_db_entry_t *db,
    cnat_vrfmap_t *vrfmap
#ifndef NO_BULK_LOGGING
     , int bulk_alloc
#endif
    )
{
    return;
}

static inline void cnat_log_nat44_mapping_delete(cnat_main_db_entry_t *db,
    cnat_vrfmap_t *vrfmap
#ifndef NO_BULK_LOGGING
     , int bulk_alloc
#endif
    )
{
    return;
}

/* Session Logging API for nat44 */
static inline void cnat_session_log_nat44_mapping_create (
		cnat_main_db_entry_t *db,
                cnat_session_entry_t *sdb,
    		cnat_vrfmap_t *vrfmap )
{
    return;
}

static inline void cnat_session_log_nat44_mapping_delete (
                cnat_main_db_entry_t *db,
                cnat_session_entry_t *sdb,
                cnat_vrfmap_t *vrfmap )
{
    return;
}

/* Session Logging API for dslite */
static inline void cnat_session_log_ds_lite_mapping_create (
                cnat_main_db_entry_t *db,
                dslite_table_entry_t *dslite_entry,
                cnat_session_entry_t *sdb ) 
{
    return;
}

static inline void cnat_session_log_ds_lite_mapping_delete (
                cnat_main_db_entry_t *db,
                dslite_table_entry_t *dslite_entry,
                cnat_session_entry_t *sdb )
{
    return;
}

#endif /* #ifndef __CNAT_LOG_API_H__  */

