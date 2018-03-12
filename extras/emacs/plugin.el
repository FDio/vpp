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

(defun make-plugin ()
  "Create a plugin"
  (interactive)
  (save-excursion
    (let (cd-args cmd-args start-dir)
      (setq start-dir default-directory)
      (makunbound 'plugin-name)
      (makunbound 'PLUGIN-NAME)
      (setq plugin-name (read-string "Plugin name: "))
      (setq PLUGIN-NAME (upcase plugin-name))
      (find-file (concat plugin-name ".am"))
      (skel-plugin-makefile-am-fragment)
      (setq cmd-args (concat "mkdir -p " plugin-name))
      (shell-command cmd-args)
      (setq cd-args (concat start-dir "/" plugin-name))
      (setq default-directory cd-args)
      (find-file (concat plugin-name ".api"))
      (skel-plugin-api)
      (find-file (concat plugin-name "_all_api_h.h"))
      (skel-plugin-all-apih)
      (find-file (concat plugin-name ".h"))
      (skel-plugin-h)
      (find-file (concat plugin-name ".c"))
      (skel-plugin-main)
      (find-file (concat plugin-name "_msg_enum.h"))
      (skel-plugin-msg-enum)
      (find-file "node.c")
      (skel-plugin-node)
      (find-file (concat plugin-name "_test.c"))
      (skel-plugin-test)
      (cd start-dir))))

