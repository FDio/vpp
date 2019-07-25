/*
 * unittest.c - vpp unit-test plugin
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

/* FIXME: Register all the API handler functions. */

static void
vl_api_get_f64_endian_value_t_handler (vl_api_get_f64_endian_value_t * mp)
{
  int rv = 0;
  f64 one = 1.0;
  vl_api_get_f64_endian_value_reply_t *rmp;
  if (1.0 != clib_net_to_host_f64 (mp->f64_one))
    rv = VNET_API_ERROR_API_ENDIAN_FAILED;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_F64_ENDIAN_VALUE_REPLY,
  ({
    rmp->f64_one_result = clib_host_to_net_f64 (one);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_f64_increment_by_one_t_handler (vl_api_get_f64_increment_by_one_t *
					   mp)
{
  int rv = 0;
  vl_api_get_f64_increment_by_one_reply_t *rmp;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_F64_INCREMENT_BY_ONE_REPLY,
  ({
    rmp->f64_value = clib_host_to_net_f64 (clib_net_to_host_f64(mp->f64_value) + 1.0);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_wait_with_barrier_t_handler (vl_api_wait_with_barrier_t * mp)
{
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();
  f64 t0, t1, t2, t3;
  vl_api_wait_with_barrier_reply_t *rmp;

  t0 = vlib_time_now (vm);
  vl_msg_api_barrier_sync ();
  t1 = vlib_time_now (vm);
  vlib_time_wait (vm, mp->wait);
  t2 = vlib_time_now (vm);
  vl_msg_api_barrier_release ();
  t3 = vlib_time_now (vm);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WAIT_WITH_BARRIER_REPLY,
  ({
    rmp->inner_time = clib_host_to_net_f64 (t2 - t1);
    rmp->outer_time = clib_host_to_net_f64 (t3 - t0);
  }));
  /* *INDENT-ON* */
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "C unit tests",
  .default_disabled = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
