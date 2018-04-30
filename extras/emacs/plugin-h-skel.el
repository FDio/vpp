;;; plugin-h-skel.el - vpp engine plug-in "main.c" skeleton
;;;
;;; Copyright (c) 2016 Cisco and/or its affiliates.
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at:
;;;
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

(require 'skeleton)

(define-skeleton skel-plugin-h
"Insert a plug-in 'main.c' skeleton "
nil
'(if (not (boundp 'plugin-name))
     (setq plugin-name (read-string "Plugin name: ")))
'(setq PLUGIN-NAME (upcase plugin-name))
'(setq capital-oh-en "ON")
"
/*
 * " plugin-name ".h - skeleton vpp engine plug-in header file 
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_" plugin-name "_h__
#define __included_" plugin-name "_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* on/off switch for the periodic function */
    u8 periodic_timer_enabled;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
} " plugin-name "_main_t;

" plugin-name "_main_t " plugin-name "_main;

vlib_node_registration_t " plugin-name "_node;
vlib_node_registration_t " plugin-name "_periodic_node;

/* Periodic function events */
#define " PLUGIN-NAME "_EVENT1 1
#define " PLUGIN-NAME "_EVENT2 2
#define " PLUGIN-NAME "_EVENT_PERIODIC_ENABLE_DISABLE 3

#endif /* __included_" plugin-name "_h__ */

/*
 * fd.io coding-style-patch-verification: " capital-oh-en "
 *
 * Local Variables:
 * eval: (c-set-style \"gnu\")
 * End:
 */

")
