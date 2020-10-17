/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <gm_metric.h>

#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <svm/svmdb.h>
#include <errno.h>

mmodule vpp_module;
static svmdb_client_t *svmdb_client;

static int vpp_metric_init (apr_pool_t *p)
{
    const char* str_params = vpp_module.module_params;
    apr_array_header_t *list_params = vpp_module.module_params_list;
    mmparam *params;
    char *chroot_path = 0;
    svmdb_map_args_t _ma, *ma= &_ma;
    int i;

    if (str_params) {
        clib_warning("[mod_vpp]Received string params: %s", str_params);
    }
    /* Multiple name/value pair parameters. */
    if (list_params) {
        clib_warning("[mod_vpp]Received following params list: ");
        params = (mmparam*) list_params->elts;
        for(i=0; i< list_params->nelts; i++) {
            clib_warning("\tParam: %s = %s", params[i].name, params[i].value);
        }
    }

    memset (ma, 0, sizeof (*ma));
    ma->root_path = (char *)chroot_path;

    svmdb_client = svmdb_map (ma);


    /* Initialize the metadata storage for each of the metrics and then
     *  store one or more key/value pairs.  The define MGROUPS defines
     *  the key for the grouping attribute. */
    for (i = 0; vpp_module.metrics_info[i].name != NULL; i++) {
        MMETRIC_INIT_METADATA(&(vpp_module.metrics_info[i]),p);
	MMETRIC_ADD_METADATA(&(vpp_module.metrics_info[i]),MGROUP,"VPP");
    }

    return 0;
}

static void vpp_metric_cleanup (void)
{
    svmdb_unmap (svmdb_client);
}

static g_val_t vpp_metric_handler (int metric_index)
{
    g_val_t val;
    pid_t *vpp_pidp;
    f64 *vector_ratep, *vpp_rx_ratep, *sig_error_ratep;

    switch (metric_index) {
    case 0:
        vector_ratep = svmdb_local_get_vec_variable 
            (svmdb_client, "vpp_vector_rate", sizeof (*vector_ratep));
        if (vector_ratep) {
            val.d = *vector_ratep;
            vec_free (vector_ratep);
        }
        else
            val.d = 0.0;
        break;
    case 1:
        vpp_pidp = svmdb_local_get_vec_variable 
            (svmdb_client, 
             "vpp_pid", sizeof (*vpp_pidp));
        if (vpp_pidp && *vpp_pidp) {
	    if (kill(*vpp_pidp, 0) == 0 || errno != ESRCH) {
	        val.d = 1.0;
	    } else {
                val.d = 0.0;
		}
            vec_free (vpp_pidp);
	} else 
            val.d = 0;
        break;

    case 2:
        vpp_rx_ratep = svmdb_local_get_vec_variable 
            (svmdb_client, "vpp_input_rate", sizeof (*vector_ratep));
        if (vpp_rx_ratep) {
            val.d = *vpp_rx_ratep;
            vec_free (vpp_rx_ratep);
        } else
            val.d = 0.0;
        break;

    case 3:
        sig_error_ratep = svmdb_local_get_vec_variable 
            (svmdb_client, "vpp_sig_error_rate", sizeof (*vector_ratep));
        if (sig_error_ratep) {
            val.d = *sig_error_ratep;
            vec_free (sig_error_ratep);
        } else
            val.d = 0.0;
        break;

    default:
        val.d = 0.0; 
    }

    return val;
}

static Ganglia_25metric vpp_metric_info[] = 
{
    {0, "Vector_Rate", 100, GANGLIA_VALUE_DOUBLE, "Packets/Frame", 
     "both", "%.1f", 
     UDP_HEADER_SIZE+8, "VPP Vector Rate"},
    {0, "VPP_State", 100, GANGLIA_VALUE_DOUBLE, "Run=1", "both", "%.0f", 
     UDP_HEADER_SIZE+8, "VPP State"},
    {0, "Input_Rate", 100, GANGLIA_VALUE_DOUBLE, "5 sec RX rate", 
     "both", "%.1f", 
     UDP_HEADER_SIZE+8, "VPP Aggregate RX Rate"},
    {0, "Sig_Error_Rate", 100, GANGLIA_VALUE_DOUBLE, 
     "5 sec significant error rate", 
     "both", "%.1f", 
     UDP_HEADER_SIZE+8, "VPP Significant Error Rate"},
    {0, NULL}
};

mmodule vpp_module =
{
    STD_MMODULE_STUFF,
    vpp_metric_init,
    vpp_metric_cleanup,
    vpp_metric_info,
    vpp_metric_handler,
};
