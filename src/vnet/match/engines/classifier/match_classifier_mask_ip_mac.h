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

#ifndef _MATCH_ENGINE_CLASSIFIER_MASK_IP_MAC_H__
#define _MATCH_ENGINE_CLASSIFIER_MASK_IP_MAC_H__

#include <vnet/match/engines/classifier/match_classifier_types.h>

/**
 * A mask 'class' requires its own classifier set
 */
typedef struct match_classifier_mask_class_key_mask_ip_mac_t_
{
  mac_address_t mcmck_mac;
  u8 mcmck_ip;
  ethernet_type_t mcmck_proto;
  match_set_tag_flags_t mcmck_flag;
  match_orientation_t mcmck_orientation;
} match_classifier_mask_class_key_mask_ip_mac_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
