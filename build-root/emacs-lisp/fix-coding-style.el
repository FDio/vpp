#!/usr/bin/emacs --script

;; Insert style boilerplate if it's not already there
;;
;; Breaking the string in half keeps emacs
;; from trying to interpret the local variable
;; settings e.g. when it reads the lisp source code

(defun insert-style-boilerplate () (interactive)
       (save-excursion 
         (goto-char (point-min))
         (if (eq nil (search-forward "coding-style-patch-verification" 
                                     (point-max) t))
             (let ((junk 0)) (goto-char (point-max))
              (insert "
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Var" "iables:
 * eval: (c-set-style \"gnu\")
 * End:
 */")))))

;; (cons xxx <list>) means insert xxx at the head of <list>
;; Build a sorted list of *INDENT-OFF* lines, by searching
;; backwards. The initial (setq indent-offset-list nil)
;; results in (cdr <last-cell>) nil, which makes it a proper list

(defun find-indent-offs () (interactive)
       (save-excursion
         (if (boundp 'indent-offset-list)
             (makunbound 'indent-offset-list))
         (setq indent-offset-list nil)
         (goto-char (point-max))
         (while (search-backward "*INDENT-OFF*" (point-min) t)
           (move-beginning-of-line nil)
           (setq indent-offset-list (cons (point) indent-offset-list))
           (previous-line))))

;; Insert indent-off ... indent-on brackets around
;; a certain xxx_foreach macro, etc. which "indent"
;; completely screws up. Doesn't handle nesting, of which there
;; are few examples (fortunately).

(defun fix-initializer (what) (interactive)
       (find-indent-offs)
       (save-excursion 
         (goto-char (point-min))
         (while (search-forward-regexp what (point-max) t)
           (move-beginning-of-line nil)
           (previous-line)
           (let ((index 0)(pointval 0))
             (while (and (< pointval (point))(elt indent-offset-list index))
               (setq pointval (elt indent-offset-list index))
               (setq index (1+ index)))
             (if (not (eq pointval (point)))
                 (let ((junk 0))
                   (next-line)
                   (open-line 1)
                   (c-indent-line-or-region)
                   (insert "/* *INDENT-OFF* */")
                   (search-forward "{")
                   (backward-char)
                   (forward-sexp)
                   (move-end-of-line nil)
                   (newline 1)
                   (c-indent-line-or-region)
                   (insert "/* *INDENT-ON* */")
                   (find-indent-offs))
               (search-forward "*INDENT-ON*"))))))

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

(defun fix-clib-packed () (interactive)
       (fix-initializer "CLIB_PACKED *("))
(defun fix-vl-api-packed () (interactive)
       (fix-initializer "VL_API_PACKED *("))

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
       (fix-clib-packed)
       (fix-vl-api-packed)
       (insert-style-boilerplate)
       (if (boundp 'indent-offset-list)
           (makunbound 'indent-offset-list)))

;; When run as a script, this sexp
;; walks the list of files supplied on the command line.
;; 
;; (elt argv index) returns nil if you M-x eval-buffer
;; or M-x load-file the file, so we won't accidentally
;; evaluate (save-buffers-kill-emacs)...

(let ((file-index 0))
  (if (elt argv file-index)
      (while (elt argv file-index)
        (find-file (elt argv file-index))
        (fd-io-styleify)
        (message "Done %s..." (elt argv file-index))
        (setq file-index (1+ file-index))))
  (if (> file-index 0)
      (let ((junk 0))
        (message "Save and quit...")
        (save-buffers-kill-emacs t))))
  

