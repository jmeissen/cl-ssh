;;;; SSH protocol constants: message numbers, algorithm names, reason codes.
;;;; Sources: RFC 4250, 4251, 4252, 4253, 4254, and the IANA SSH registry.

(uiop:define-package ssh/constants
  (:use #:cl)
  (:export
   ;; Transport layer (RFC 4253)
   #:+msg-disconnect+
   #:+msg-ignore+
   #:+msg-unimplemented+
   #:+msg-debug+
   #:+msg-service-request+
   #:+msg-service-accept+
   #:+msg-kexinit+
   #:+msg-newkeys+
   #:+msg-ext-info+
   ;; KEX ECDH — curve25519-sha256 and generic ECDH (RFC 5656)
   #:+msg-kex-ecdh-init+
   #:+msg-kex-ecdh-reply+
   ;; User authentication (RFC 4252, RFC 4256)
   #:+msg-userauth-request+
   #:+msg-userauth-failure+
   #:+msg-userauth-success+
   #:+msg-userauth-banner+
   #:+msg-userauth-pk-ok+
   #:+msg-userauth-info-request+
   #:+msg-userauth-info-response+
   ;; Connection protocol (RFC 4254)
   #:+msg-global-request+
   #:+msg-request-success+
   #:+msg-request-failure+
   #:+msg-channel-open+
   #:+msg-channel-open-confirmation+
   #:+msg-channel-open-failure+
   #:+msg-channel-window-adjust+
   #:+msg-channel-data+
   #:+msg-channel-extended-data+
   #:+msg-channel-eof+
   #:+msg-channel-close+
   #:+msg-channel-request+
   #:+msg-channel-success+
   #:+msg-channel-failure+
   ;; Extended data stream types (RFC 4254)
   #:+extended-data-stderr+
   ;; Disconnect reason codes (RFC 4253 §11.1)
   #:+disconnect-host-not-allowed-to-connect+
   #:+disconnect-protocol-error+
   #:+disconnect-key-exchange-failed+
   #:+disconnect-mac-error+
   #:+disconnect-compression-error+
   #:+disconnect-service-not-available+
   #:+disconnect-protocol-version-not-supported+
   #:+disconnect-host-key-not-verifiable+
   #:+disconnect-connection-lost+
   #:+disconnect-by-application+
   #:+disconnect-too-many-connections+
   #:+disconnect-auth-cancelled-by-user+
   #:+disconnect-no-more-auth-methods-available+
   #:+disconnect-illegal-user-name+
   ;; Channel open failure codes (RFC 4254 §5.1)
   #:+open-administratively-prohibited+
   #:+open-connect-failed+
   #:+open-unknown-channel-type+
   #:+open-resource-shortage+
   ;; Algorithm name strings
   #:+kex-curve25519-sha256+
   #:+kex-curve25519-sha256-libssh+
   #:+kex-dh-group14-sha256+
   #:+host-key-ed25519+
   #:+host-key-rsa-sha2-256+
   #:+host-key-rsa-sha2-512+
   #:+cipher-aes128-ctr+
   #:+cipher-aes256-ctr+
   #:+mac-hmac-sha2-256+
   #:+mac-hmac-sha2-512+
   #:+compression-none+
   #:+ext-info-c+
   #:+ext-info-s+
   ;; Service names
   #:+service-userauth+
   #:+service-connection+
   ;; Auth method names
   #:+auth-none+
   #:+auth-password+
   #:+auth-publickey+
   #:+auth-keyboard-interactive+
   ;; Channel type names
   #:+channel-session+
   #:+channel-direct-tcpip+
   ;; Session request type names
   #:+request-pty+
   #:+request-shell+
   #:+request-exec+
   #:+request-subsystem+
   #:+request-env+
   #:+request-window-change+
   ;; Our identification string
   #:+client-version-string+))

(in-package #:ssh/constants)

;;; Transport layer messages (RFC 4253 §12)
(defconstant +msg-disconnect+      1)
(defconstant +msg-ignore+          2)
(defconstant +msg-unimplemented+   3)
(defconstant +msg-debug+           4)
(defconstant +msg-service-request+ 5)
(defconstant +msg-service-accept+  6)
(defconstant +msg-kexinit+        20)
(defconstant +msg-newkeys+        21)
(defconstant +msg-ext-info+        7)

;;; KEX ECDH messages (RFC 5656 §7.1; used for curve25519-sha256 too)
(defconstant +msg-kex-ecdh-init+  30)
(defconstant +msg-kex-ecdh-reply+ 31)

;;; User authentication messages (RFC 4252 §6)
(defconstant +msg-userauth-request+ 50)
(defconstant +msg-userauth-failure+ 51)
(defconstant +msg-userauth-success+ 52)
(defconstant +msg-userauth-banner+  53)
(defconstant +msg-userauth-pk-ok+   60)
;; RFC 4256 method-specific messages.  Message number 60 overlaps with
;; SSH_MSG_USERAUTH_PK_OK (RFC 4252) depending on active auth method.
(defconstant +msg-userauth-info-request+  60)
(defconstant +msg-userauth-info-response+ 61)

;;; Connection protocol messages (RFC 4254 §9)
(defconstant +msg-global-request+            80)
(defconstant +msg-request-success+           81)
(defconstant +msg-request-failure+           82)
(defconstant +msg-channel-open+              90)
(defconstant +msg-channel-open-confirmation+ 91)
(defconstant +msg-channel-open-failure+      92)
(defconstant +msg-channel-window-adjust+     93)
(defconstant +msg-channel-data+              94)
(defconstant +msg-channel-extended-data+     95)
(defconstant +msg-channel-eof+               96)
(defconstant +msg-channel-close+             97)
(defconstant +msg-channel-request+           98)
(defconstant +msg-channel-success+           99)
(defconstant +msg-channel-failure+          100)

;;; Extended data types (RFC 4254 §5.2)
(defconstant +extended-data-stderr+ 1)

;;; Disconnect reason codes (RFC 4253 §11.1)
(defconstant +disconnect-host-not-allowed-to-connect+    1)
(defconstant +disconnect-protocol-error+                 2)
(defconstant +disconnect-key-exchange-failed+            3)
(defconstant +disconnect-mac-error+                      5)
(defconstant +disconnect-compression-error+              6)
(defconstant +disconnect-service-not-available+          7)
(defconstant +disconnect-protocol-version-not-supported+ 8)
(defconstant +disconnect-host-key-not-verifiable+        9)
(defconstant +disconnect-connection-lost+               10)
(defconstant +disconnect-by-application+               11)
(defconstant +disconnect-too-many-connections+         12)
(defconstant +disconnect-auth-cancelled-by-user+       13)
(defconstant +disconnect-no-more-auth-methods-available+ 14)
(defconstant +disconnect-illegal-user-name+            15)

;;; Channel open failure codes (RFC 4254 §5.1)
(defconstant +open-administratively-prohibited+ 1)
(defconstant +open-connect-failed+              2)
(defconstant +open-unknown-channel-type+        3)
(defconstant +open-resource-shortage+           4)

;;; Algorithm name strings (IANA SSH registry)
;;; defparameter is correct here: strings are not eql-comparable across
;;; reloads, so defconstant would signal a redefinition error on the second
;;; load.  The +name+ convention is sufficient to communicate immutability.
(defparameter +kex-curve25519-sha256+       "curve25519-sha256")
(defparameter +kex-curve25519-sha256-libssh+ "curve25519-sha256@libssh.org")
(defparameter +kex-dh-group14-sha256+       "diffie-hellman-group14-sha256")
(defparameter +host-key-ed25519+            "ssh-ed25519")
(defparameter +host-key-rsa-sha2-256+       "rsa-sha2-256")
(defparameter +host-key-rsa-sha2-512+       "rsa-sha2-512")
(defparameter +cipher-aes128-ctr+           "aes128-ctr")
(defparameter +cipher-aes256-ctr+           "aes256-ctr")
(defparameter +mac-hmac-sha2-256+           "hmac-sha2-256")
(defparameter +mac-hmac-sha2-512+           "hmac-sha2-512")
(defparameter +compression-none+            "none")
(defparameter +ext-info-c+                  "ext-info-c")
(defparameter +ext-info-s+                  "ext-info-s")

;;; Service names
(defparameter +service-userauth+   "ssh-userauth")
(defparameter +service-connection+ "ssh-connection")

;;; Authentication method names (RFC 4252)
(defparameter +auth-none+                 "none")
(defparameter +auth-password+             "password")
(defparameter +auth-publickey+            "publickey")
(defparameter +auth-keyboard-interactive+ "keyboard-interactive")

;;; Channel type names (RFC 4254)
(defparameter +channel-session+      "session")
(defparameter +channel-direct-tcpip+ "direct-tcpip")

;;; Session channel request type names (RFC 4254 §6)
(defparameter +request-pty+           "pty-req")
(defparameter +request-shell+         "shell")
(defparameter +request-exec+          "exec")
(defparameter +request-subsystem+     "subsystem")
(defparameter +request-env+           "env")
(defparameter +request-window-change+ "window-change")

;;; Client identification string (sent during version exchange)
(defparameter +client-version-string+ "SSH-2.0-cl-ssh_0.1")
