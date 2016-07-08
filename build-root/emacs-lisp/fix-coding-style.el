#!/usr/bin/emacs --script

;; insert style boilerplate
(defun insert-style-boilerplate () (interactive)
       (save-excursion (goto-char (point-max))
                       (insert "
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style \"gnu\")
 * End:
 */")))

;;
(defun fix-foreach () (interactive)
       (save-excursion (goto-char (point-min))
                       (while (search-forward-regexp 
                               "[pool|hash|clib_fifo|clib_bitmap]_foreach"
                               (point-max) t)
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

(defun fix-vlib-register-thread () (interactive)
       (fix-initializer "VLIB_REGISTER_THREAD *("))

(defun fix-vlib-cli-command () (interactive)
       (fix-initializer "VLIB_CLI_COMMAND *("))

(defun fix-vlib-register-node () (interactive)
       (fix-initializer "VLIB_REGISTER_NODE *("))


;; Driver routine which runs the set of keyboard macros
;; defined above, as well as the bottom boilerplate lisp fn.

(defun fd-io-styleify () (interactive)
       (fix-foreach)
       (fix-vlib-register-thread)
       (fix-vlib-cli-command)
       (fix-vlib-register-node)
       (insert-style-boilerplate))

(setq index 0)
(while (elt argv index)
  (message "Processing %s..." (elt argv index))
  (find-file (elt argv index))
  (fd-io-styleify)
  (setq index (1+ index)))
(save-buffers-kill-emacs t)
