;;; plugin-setup-skel.el - debug CLI + pg setup
;;;
;;; Copyright (c) 2018 Cisco and/or its affiliates.
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

(define-skeleton skel-plugin-setup
"Insert a debug cli / pg skeleton "
nil
'(if (not (boundp 'plugin-name))
     (setq plugin-name (read-string "Plugin name: ")))
'(setq PLUGIN-NAME (upcase plugin-name))
'(setq capital-oh-en "ON")
"
comment { simple debug CLI setup script w/ packet generator test vector }
set term page off
loop create
set int ip address loop0 192.168.1.1/24
set int state loop0 up

comment { Packet generator script. Src MAC 00:de:ad:be:ef:01 }
comment { Dst mac 01:ba:db:ab:be:01 ethtype 0800 }
packet-generator new {
    name simple
    limit 1
    size 128-128
    interface loop0
    node " plugin-name "
    data {
        hex 0x00deadbeef0001badbabbe010800 
        incrementing 30
    }
}
")
