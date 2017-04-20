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

;; plugin all-in-1 program

(load-file "./plugin.el")

;; list of clib / vlib / vnet / vpp skeleton files

(load-file "./cli-cmd-skel.el")
(load-file "./config-skel.el")
(load-file "./dual-loop-skel.el")
(load-file "./periodic-skel.el")
(load-file "./pipe-skel.el")
(load-file "./plugin-all-apih-skel.el")
(load-file "./plugin-am-skel.el")
(load-file "./plugin-api-skel.el")
(load-file "./plugin-h-skel.el")
(load-file "./plugin-main-skel.el")
(load-file "./plugin-msg-enum-skel.el")
(load-file "./plugin-node-skel.el")
(load-file "./plugin-test-skel.el")
(load-file "./tunnel-c-skel.el")
(load-file "./tunnel-decap-skel.el")
(load-file "./tunnel-encap-skel.el")
(load-file "./tunnel-h-skel.el")
(load-file "./elog-4-int-skel.el")
(load-file "./elog-4-int-track-skel.el")
(load-file "./elog-enum-skel.el")
(load-file "./elog-one-datum-skel.el")
