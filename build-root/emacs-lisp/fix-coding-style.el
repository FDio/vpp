#!/usr/bin/emacs --script

;; Insert style boilerplate
;;
;; Breaking the string in half keeps emacs
;; from trying to interpret the local variable
;; settings e.g. when it reads the lisp source code

(defun insert-style-boilerplate () (interactive)
       (save-excursion (goto-char (point-max))
                       (insert "
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Var" "iables:
 * eval: (c-set-style \"gnu\")
 * End:
 */")))

;; Insert indent-off ... indent-on brackets around
;; a certain xxx_foreach macro, etc. which "indent"
;; completely screws up. Doesn't handle nesting, of which there
;; are few examples (fortunately).

(defun fix-initializer (what) (interactive)
       (save-excursion 
         (goto-char (point-min))
         (while (search-forward-regexp what (point-max) t)
           (move-beginning-of-line nil)
           (open-line 1)
           (c-indent-line-or-region)
           (insert "/* *INDENT-OFF* */")
           (search-forward "{")
           (backward-char)
           (forward-sexp)
           (move-end-of-line nil)
           (newline 1)
           (c-indent-line-or-region)
           (insert "/* *INDENT-ON* */"))))

(defun fix-pool-foreach () (interactive)
       (fix-initializer "pool_foreach *("))

(defun fix-pool-foreach-index () (interactive)
       (fix-initializer "pool_foreach_index *("))

(defun fix-hash-foreach () (interactive)
       (fix-initializer "hash_foreach *("))

(defun fix-hash-foreach-pair () (interactive)
       (fix-initializer "hash_foreach_pair *("))

(defun fix-hash-foreach-mem () (interactive)
       (fix-initializer "hash_foreach_mem *("))

(defun fix-clib-fifo-foreach () (interactive)
       (fix-initializer "clib_fifo_foreach *("))

(defun fix-clib-bitmap-foreach () (interactive)
       (fix-initializer "clib_bitmap_foreach *("))

(defun fix-foreach-ip-interface-address () (interactive)
       (fix-initializer "foreach_ip_interface_address *("))

(defun fix-vlib-register-thread () (interactive)
       (fix-initializer "VLIB_REGISTER_THREAD *("))

(defun fix-vlib-cli-command () (interactive)
       (fix-initializer "VLIB_CLI_COMMAND *("))

(defun fix-vlib-register-node () (interactive)
       (fix-initializer "VLIB_REGISTER_NODE *("))

(defun fix-reply-macro2 () (interactive)
       (fix-initializer "REPLY_MACRO2 *("))

(defun fix-vnet-device-class () (interactive)
       (fix-initializer "VNET_DEVICE_CLASS *("))

(defun fix-vnet-hw-interface-class () (interactive)
       (fix-initializer "VNET_HW_INTERFACE_CLASS *("))

;; Driver routine which runs the set of functions
;; defined above, as well as the bottom boilerplate function

(defun fd-io-styleify () (interactive)
       (fix-pool-foreach)
       (fix-pool-foreach-index)
       (fix-hash-foreach)
       (fix-hash-foreach-pair)
       (fix-hash-foreach-mem)
       (fix-foreach-ip-interface-address)
       (fix-clib-fifo-foreach)
       (fix-clib-bitmap-foreach)
       (fix-vlib-register-thread)
       (fix-vlib-cli-command)
       (fix-vlib-register-node)
       (fix-reply-macro2)
       (fix-vnet-device-class)
       (fix-vnet-hw-interface-class)
       (insert-style-boilerplate))


;; When run as a script, this sexp
;; walks the list of files supplied on the command line.
;; 
;; (elt argv index) returns nil if you M-x eval-buffer
;; or M-x load-file the file, so we won't accidentally
;; evaluate (save-buffers-kill-emacs)...

(let ((index 0))
  (if (elt argv index)
      (while (elt argv index)
        (message "Processing %s..." (elt argv index))
        (find-file (elt argv index))
        (fd-io-styleify)
        (setq index (1+ index))))
  (if (> index 0)
      (save-buffers-kill-emacs t)))
  

