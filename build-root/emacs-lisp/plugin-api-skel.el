;;; plugin-api-skel.el - vpp engine plug-in "all-apih.c" skeleton
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

(define-skeleton skel-plugin-api
"Insert a plug-in '<name>.api' skeleton "
nil
'(if (not (boundp 'plugin-name))
     (setq plugin-name (read-string "Plugin name: ")))
'(setq PLUGIN-NAME (upcase plugin-name))
"
/* Define a simple enable-disable binary API to control the feature */

define " plugin-name "_enable_disable {
    /* Client identifier, set from api_main.my_client_index */
    u32 client_index;

    /* Arbitrary context, so client can match reply to request */
    u32 context;

    /* Enable / disable the feature */
    u8 enable_disable;

    /* Interface handle */
    u32 sw_if_index;
};

define " plugin-name "_enable_disable_reply {
    /* From the request */
    u32 context;

    /* Return value, zero means all OK */
    i32 retval;
};
")
