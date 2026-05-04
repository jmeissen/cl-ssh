;;;; ~/.ssh/config parser.
;;;;
;;;; Parses the OpenSSH client configuration file and resolves per-host
;;;; settings for a given hostname alias.
;;;;
;;;; Supported keywords:
;;;;   HostName              StrictHostKeyChecking
;;;;   Port                  UserKnownHostsFile
;;;;   User
;;;;   IdentityFile          (multiple allowed, accumulated in order)
;;;;
;;;; Unsupported keywords are silently ignored.
;;;;
;;;; Semantics follow OpenSSH: blocks are evaluated in file order, and
;;;; for every key except IdentityFile the first matching value wins.
;;;; Negated patterns (!pattern) are honoured.

(uiop:define-package :ssh/config
  (:use :cl)
  (:export
   #:resolve-host
   #:ssh-config
   #:ssh-config-hostname
   #:ssh-config-port
   #:ssh-config-user
   #:ssh-config-identity-files
   #:ssh-config-strict-host-checking
   #:ssh-config-known-hosts-file))

(in-package :ssh/config)

;;;; Result struct

(defstruct ssh-config
  "Resolved configuration for one SSH connection target."
  (hostname             nil)      ; string or NIL
  (port                 nil)      ; integer or NIL
  (user                 nil)      ; string or NIL
  (identity-files       '())      ; list of strings (pathnames), in config order
  (strict-host-checking :default) ; :yes :no :accept-new :default
  (known-hosts-file     nil))     ; string or NIL

;;;; Helpers

(defun default-config-path ()
  (merge-pathnames #p".ssh/config" (user-homedir-pathname)))

(defun expand-tilde (s)
  "Expand a leading ~ to the user home directory."
  (cond
    ((string= s "~")
     (namestring (user-homedir-pathname)))
    ((and (>= (length s) 2)
          (char= (char s 0) #\~)
          (char= (char s 1) #\/))
     (namestring (merge-pathnames (subseq s 2) (user-homedir-pathname))))
    (t s)))

(defun split-whitespace (s)
  "Split S on runs of spaces/tabs, returning a list of non-empty tokens."
  (loop with len = (length s)
        for start = 0 then (1+ end)
        for end = (position-if (lambda (c) (or (char= c #\Space) (char= c #\Tab)))
                               s :start start)
        for tok = (subseq s start (or end len))
        unless (zerop (length tok)) collect tok
        while end))

;;;; Glob matching

(defun glob-match-p (pattern string)
  "Case-insensitive glob match: * matches any sequence, ? any single char."
  (let ((p    (string-upcase pattern))
        (s    (string-upcase string))
        (plen (length pattern))
        (slen (length string)))
    (labels ((match (pp ss)
               (cond
                 ((= pp plen)           (= ss slen))
                 ((char= (char p pp) #\*)
                  (loop for i from ss to slen
                        thereis (match (1+ pp) i)))
                 ((= ss slen)           nil)
                 ((or (char= (char p pp) #\?)
                      (char= (char p pp) (char s ss)))
                  (match (1+ pp) (1+ ss)))
                 (t nil))))
      (match 0 0))))

(defun patterns-match-p (patterns alias)
  "Return T when ALIAS matches the list of PATTERNS from one Host line.

   A pattern starting with ! negates the match.  The block matches when
   at least one non-negated pattern matches and no negated pattern matches."
  (let (matched negated)
    (dolist (p patterns)
      (if (and (plusp (length p)) (char= (char p 0) #\!))
          (when (glob-match-p (subseq p 1) alias) (setf negated t))
          (when (glob-match-p p alias)             (setf matched t))))
    (and matched (not negated))))

;;;; Config file parsing

(defun parse-kv (line)
  "Parse a config line into (KEY . VALUE), both as strings, or NIL."
  (let* ((trimmed (string-trim '(#\Space #\Tab) line))
         (len     (length trimmed)))
    (when (zerop len) (return-from parse-kv nil))
    (when (char= (char trimmed 0) #\#) (return-from parse-kv nil))
    ;; Find the first = or whitespace separator
    (let* ((sep (loop for i below len
                      when (or (char= (char trimmed i) #\=)
                               (char= (char trimmed i) #\Space)
                               (char= (char trimmed i) #\Tab))
                        return i))
           (key (string-upcase
                 (string-trim '(#\Space #\Tab)
                              (subseq trimmed 0 (or sep len)))))
           (val (if sep
                    (string-trim '(#\Space #\Tab #\=)
                                 (subseq trimmed sep))
                    "")))
      (when (plusp (length key))
        (cons key val)))))

(defun parse-config-file (path)
  "Parse an SSH config file at PATH.
   Returns a list of (patterns . settings-alist) cons cells in file order."
  (unless (probe-file path)
    (return-from parse-config-file '()))
  (let (blocks current-patterns current-settings)
    (flet ((flush ()
             (when current-patterns
               (push (cons (reverse current-patterns)
                           (reverse current-settings))
                     blocks)
               (setf current-patterns nil
                     current-settings nil))))
      (with-open-file (f path :direction :input)
        (loop for line = (read-line f nil nil)
              while line
              for kv = (parse-kv line)
              when kv
                do (if (string= (car kv) "HOST")
                       (progn
                         (flush)
                         (setf current-patterns (split-whitespace (cdr kv))))
                       (push kv current-settings))))
      (flush))
    (nreverse blocks)))

;;;; Setting application

(defun apply-setting (cfg key value)
  "Apply one KEY / VALUE pair to CFG, respecting first-match-wins semantics."
  (cond
    ((string= key "HOSTNAME")
     (unless (ssh-config-hostname cfg)
       (setf (ssh-config-hostname cfg) value)))

    ((string= key "PORT")
     (unless (ssh-config-port cfg)
       (let ((n (parse-integer value :junk-allowed t)))
         (when n (setf (ssh-config-port cfg) n)))))

    ((string= key "USER")
     (unless (ssh-config-user cfg)
       (setf (ssh-config-user cfg) value)))

    ;; IdentityFile accumulates in order; duplicates are skipped.
    ((string= key "IDENTITYFILE")
     (let ((expanded (expand-tilde value)))
       (unless (member expanded (ssh-config-identity-files cfg) :test #'string=)
         (setf (ssh-config-identity-files cfg)
               (append (ssh-config-identity-files cfg) (list expanded))))))

    ((string= key "STRICTHOSTKEYCHECKING")
     (when (eq (ssh-config-strict-host-checking cfg) :default)
       (setf (ssh-config-strict-host-checking cfg)
             (cond ((member value '("yes") :test #'string-equal)         :yes)
                   ((member value '("no" "off") :test #'string-equal)    :no)
                   ((string-equal value "accept-new")                    :accept-new)
                   (t                                                     :default)))))

    ((string= key "USERKNOWNHOSTSFILE")
     (unless (ssh-config-known-hosts-file cfg)
       (setf (ssh-config-known-hosts-file cfg) (expand-tilde value))))))

;;;; Public entry point

(defun resolve-host (alias &key (config-path (default-config-path)))
  "Look up ALIAS in the SSH config file and return an SSH-CONFIG struct.

   Settings are accumulated across all matching Host blocks in file order
   with first-match-wins semantics (except IdentityFile which accumulates).
   Returns a struct with all slots NIL / :default when nothing matches."
  (let ((blocks (parse-config-file config-path))
        (cfg    (make-ssh-config)))
    (dolist (block blocks)
      (when (patterns-match-p (car block) alias)
        (dolist (kv (cdr block))
          (apply-setting cfg (car kv) (cdr kv)))))
    cfg))
