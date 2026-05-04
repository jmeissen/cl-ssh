;;;; SSH connection protocol — RFC 4254.
;;;;
;;;; Manages the channel multiplexer: opening channels, dispatching
;;;; incoming packets to the correct channel, and handling flow control
;;;; (window sizing).
;;;;
;;;; Each channel has:
;;;;   - A local channel number and a remote channel number (different)
;;;;   - A local receive window (how many bytes the remote may send us)
;;;;   - A remote send window (how many bytes we may send to the remote)
;;;;   - A max-packet-size (per-channel cap on individual data packets)
;;;;
;;;; This implementation is synchronous and single-threaded.  A blocking
;;;; CHANNEL-READ call drives the receive loop until data arrives.

(uiop:define-package ssh/connection
  (:use #:cl)
  (:import-from #:ssh/constants
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
                #:+extended-data-stderr+
                #:+open-administratively-prohibited+)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-boolean
                #:write-string* #:write-raw-bytes #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-uint32 #:read-string*
                #:read-boolean #:read-remaining-bytes #:read-raw-bytes)
  (:import-from #:ssh/transport
                #:transport #:transport-send #:transport-recv)
  (:export
   #:connection
   #:make-connection
   #:channel
   #:channel-local-id
   #:channel-remote-id
   #:channel-open-p
   #:channel-eof-p
   #:channel-closed-p
   #:channel-stdout-buffer
   #:channel-stderr-buffer
   #:channel-exit-status
   #:open-channel
   #:channel-send-data
   #:channel-send-eof
   #:channel-close
   #:channel-request
   #:channel-dispatch-until
   #:connection-error))

(in-package #:ssh/connection)

;;;; Condition

(define-condition connection-error (error)
  ((message :initarg :message :reader connection-error-message))
  (:report (lambda (c s)
             (format s "SSH connection error: ~A" (connection-error-message c)))))

;;;; Channel

(defconstant +initial-window-size+ #.(expt 2 21)   ; 2 MiB
  "Default local receive window size.")
(defconstant +max-packet-size+    #.(expt 2 15)    ; 32 KiB
  "Maximum SSH_MSG_CHANNEL_DATA payload per packet.")

(defstruct channel
  (local-id    0   :type (unsigned-byte 32))
  (remote-id   0   :type (unsigned-byte 32))
  ;; Flow control
  (local-window  +initial-window-size+ :type (unsigned-byte 32))
  (remote-window 0                     :type (unsigned-byte 32))
  (max-packet    +max-packet-size+      :type (unsigned-byte 32))
  ;; State flags
  (open-p    nil :type boolean)
  (eof-p     nil :type boolean)         ; remote sent EOF
  (close-p   nil :type boolean)         ; remote sent CLOSE
  (eof-sent  nil :type boolean)         ; we sent EOF
  ;; Buffered data (byte vectors accumulated before the reader consumes them)
  (stdout-buffer (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  (stderr-buffer (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  ;; Exit status (set when exit-status channel request received)
  (exit-status nil))

;;;; Connection

(defstruct (connection (:constructor %make-connection))
  transport
  (channels      (make-array 16 :adjustable t :fill-pointer 0))
  (next-local-id 0 :type (unsigned-byte 32)))

(defun make-connection (transport)
  "Return a new connection multiplexer over TRANSPORT."
  (%make-connection :transport transport))

;;;; Channel allocation

(defun %alloc-channel (conn)
  "Allocate a new channel struct, register it, and return it."
  (let* ((id  (connection-next-local-id conn))
         (ch  (make-channel :local-id id)))
    (setf (connection-next-local-id conn) (ldb (byte 32 0) (1+ id)))
    (vector-push-extend ch (connection-channels conn))
    ch))

(defun %find-channel (conn local-id)
  "Return the channel with LOCAL-ID or signal an error."
  (or (find local-id (connection-channels conn)
            :key #'channel-local-id :test #'=)
      (error 'connection-error
             :message (format nil "unknown local channel id ~D" local-id))))

;;;; Packet helpers

(defun conn-send (conn payload)
  (transport-send (connection-transport conn) payload))

(defun conn-recv (conn)
  (transport-recv (connection-transport conn)))

;;;; Window adjustment

(defun %maybe-adjust-window (conn ch)
  "Send SSH_MSG_CHANNEL_WINDOW_ADJUST if the local window is getting small."
  (when (< (channel-local-window ch) (ash +initial-window-size+ -1))
    (let ((increment (- +initial-window-size+ (channel-local-window ch)))
          (buf (make-write-buffer)))
      (write-byte*   buf +msg-channel-window-adjust+)
      (write-uint32  buf (channel-remote-id ch))
      (write-uint32  buf increment)
      (conn-send conn (buffer-to-octets buf))
      (incf (channel-local-window ch) increment))))

;;;; Opening a channel

(defun open-channel (conn channel-type &key (initial-window +initial-window-size+)
                                            (max-packet +max-packet-size+)
                                            extra-data)
  "Send SSH_MSG_CHANNEL_OPEN for CHANNEL-TYPE and wait for confirmation.
   EXTRA-DATA, if non-NIL, is a pre-encoded octet vector appended after
   the standard fields (used for direct-tcpip etc.).
   Returns the opened CHANNEL."
  (let* ((ch  (%alloc-channel conn))
         (buf (make-write-buffer)))
    (write-byte*   buf +msg-channel-open+)
    (write-string* buf channel-type)
    (write-uint32  buf (channel-local-id ch))
    (write-uint32  buf initial-window)
    (write-uint32  buf max-packet)
    (when extra-data
      (write-raw-bytes buf extra-data))
    (conn-send conn (buffer-to-octets buf))
    ;; Wait for CHANNEL_OPEN_CONFIRMATION or CHANNEL_OPEN_FAILURE
    (channel-dispatch-until conn
                            (lambda (pkt)
                              (let ((type (aref pkt 0)))
                                (or (= type +msg-channel-open-confirmation+)
                                    (= type +msg-channel-open-failure+)))))
    (unless (channel-open-p ch)
      (error 'connection-error
             :message (format nil "server refused to open ~A channel" channel-type)))
    ch))

;;;; Sending data

(defun channel-send-data (conn ch data &key (start 0) (end (length data)))
  "Send DATA[START:END] as SSH_MSG_CHANNEL_DATA, respecting the remote window
   and max-packet-size.  Blocks if the remote window is exhausted (busy wait
   — a real implementation would integrate with an event loop)."
  (loop while (< start end)
        do (let* ((avail  (min (- end start)
                               (channel-remote-window ch)
                               (channel-max-packet ch)))
                  (dummy (when (zerop avail)
                           ;; Remote window exhausted — receive more packets
                           (channel-dispatch-until conn (lambda (pkt)
                                                          (= (aref pkt 0) +msg-channel-window-adjust+)))))
                  (chunk-end (+ start avail))
                  (buf (make-write-buffer)))
             (declare (ignore dummy))
             (write-byte*   buf +msg-channel-data+)
             (write-uint32  buf (channel-remote-id ch))
             (write-uint32  buf avail)
             (write-raw-bytes buf data :start start :end chunk-end)
             (conn-send conn (buffer-to-octets buf))
             (decf (channel-remote-window ch) avail)
             (setf start chunk-end))))

(defun channel-send-eof (conn ch)
  "Send SSH_MSG_CHANNEL_EOF."
  (unless (channel-eof-sent ch)
    (let ((buf (make-write-buffer)))
      (write-byte*  buf +msg-channel-eof+)
      (write-uint32 buf (channel-remote-id ch))
      (conn-send conn (buffer-to-octets buf))
      (setf (channel-eof-sent ch) t))))

(defun channel-close (conn ch)
  "Send SSH_MSG_CHANNEL_CLOSE and wait for the server's CLOSE."
  (channel-send-eof conn ch)
  (let ((buf (make-write-buffer)))
    (write-byte*  buf +msg-channel-close+)
    (write-uint32 buf (channel-remote-id ch))
    (conn-send conn (buffer-to-octets buf)))
  ;; Drain until we get CHANNEL_CLOSE back
  (unless (channel-close-p ch)
    (channel-dispatch-until conn (lambda (pkt)
                                   (and (= (aref pkt 0) +msg-channel-close+)
                                        (let ((rbuf (make-read-buffer pkt :start 1)))
                                          (= (read-uint32 rbuf) (channel-local-id ch))))))))

;;;; Channel requests

(defun channel-request (conn ch request-type want-reply &optional extra-buf)
  "Send SSH_MSG_CHANNEL_REQUEST.  EXTRA-BUF is a write-buffer whose
   contents are appended after the standard fields.
   If WANT-REPLY, waits for CHANNEL_SUCCESS / CHANNEL_FAILURE and
   returns T or NIL respectively."
  (let ((buf (make-write-buffer)))
    (write-byte*   buf +msg-channel-request+)
    (write-uint32  buf (channel-remote-id ch))
    (write-string* buf request-type)
    (write-boolean buf want-reply)
    (when extra-buf
      (write-raw-bytes buf (buffer-to-octets extra-buf)))
    (conn-send conn (buffer-to-octets buf)))
  (when want-reply
    (let ((reply nil))
      (channel-dispatch-until conn
                              (lambda (pkt)
                                (let ((type (aref pkt 0)))
                                  (when (or (= type +msg-channel-success+)
                                            (= type +msg-channel-failure+))
                                    (setf reply (= type +msg-channel-success+))
                                    t))))
      reply)))

;;;; Dispatch loop

(defun %handle-packet (conn pkt)
  "Dispatch one incoming packet.  Returns T if handled, NIL if unknown."
  (let ((type (aref pkt 0)))
    (case type
      ;; ---- Global requests (we always refuse) ----
      (#.+msg-global-request+
       (let* ((buf       (make-read-buffer pkt :start 1))
              (name      (read-string* buf))
              (want-reply (read-boolean buf)))
         (declare (ignore name))
         (when want-reply
           (let ((rbuf (make-write-buffer)))
             (write-byte* rbuf +msg-request-failure+)
             (conn-send conn (buffer-to-octets rbuf)))))
       t)

      ;; ---- Channel open confirmation ----
      (#.+msg-channel-open-confirmation+
       (let* ((buf       (make-read-buffer pkt :start 1))
              (local-id  (read-uint32 buf))
              (remote-id (read-uint32 buf))
              (win       (read-uint32 buf))
              (maxpkt    (read-uint32 buf))
              (ch        (%find-channel conn local-id)))
         (setf (channel-remote-id     ch) remote-id
               (channel-remote-window ch) win
               (channel-max-packet    ch) maxpkt
               (channel-open-p        ch) t))
       t)

      ;; ---- Channel open failure ----
      (#.+msg-channel-open-failure+
       ;; Channel remains open-p = NIL; caller checks
       t)

      ;; ---- Window adjust ----
      (#.+msg-channel-window-adjust+
       (let* ((buf      (make-read-buffer pkt :start 1))
              (local-id (read-uint32 buf))
              (incr     (read-uint32 buf))
              (ch       (%find-channel conn local-id)))
         (incf (channel-remote-window ch) incr))
       t)

      ;; ---- Channel data ----
      (#.+msg-channel-data+
       (let* ((buf      (make-read-buffer pkt :start 1))
              (local-id (read-uint32 buf))
              (data     (read-string* buf))
              (ch       (%find-channel conn local-id)))
         (loop for b across data
               do (vector-push-extend b (channel-stdout-buffer ch)))
         (decf (channel-local-window ch) (length data))
         (%maybe-adjust-window conn ch))
       t)

      ;; ---- Extended data (stderr) ----
      (#.+msg-channel-extended-data+
       (let* ((buf       (make-read-buffer pkt :start 1))
              (local-id  (read-uint32 buf))
              (data-type (read-uint32 buf))
              (data      (read-string* buf))
              (ch        (%find-channel conn local-id)))
         (when (= data-type +extended-data-stderr+)
           (loop for b across data
                 do (vector-push-extend b (channel-stderr-buffer ch))))
         (decf (channel-local-window ch) (length data))
         (%maybe-adjust-window conn ch))
       t)

      ;; ---- Channel EOF ----
      (#.+msg-channel-eof+
       (let* ((buf      (make-read-buffer pkt :start 1))
              (local-id (read-uint32 buf))
              (ch       (%find-channel conn local-id)))
         (setf (channel-eof-p ch) t))
       t)

      ;; ---- Channel close ----
      (#.+msg-channel-close+
       (let* ((buf      (make-read-buffer pkt :start 1))
              (local-id (read-uint32 buf))
              (ch       (%find-channel conn local-id)))
         (setf (channel-close-p ch) t))
       t)

      ;; ---- Channel request (e.g. exit-status) ----
      (#.+msg-channel-request+
       (let* ((buf        (make-read-buffer pkt :start 1))
              (local-id   (read-uint32 buf))
              (req-type   (map 'string #'code-char (read-string* buf)))
              (want-reply (read-boolean buf))
              (ch         (%find-channel conn local-id)))
         (cond
           ((string= req-type "exit-status")
            (setf (channel-exit-status ch) (read-uint32 buf)))
           ((string= req-type "exit-signal")
            ;; Could record signal name; for now just note non-zero exit
            (setf (channel-exit-status ch) 128)))
         (when want-reply
           ;; Send success for unrecognised requests too (permissive)
           (let ((rbuf (make-write-buffer)))
             (write-byte*  rbuf +msg-channel-success+)
             (write-uint32 rbuf (channel-remote-id ch))
             (conn-send conn (buffer-to-octets rbuf)))))
       t)

      ;; ---- Channel success / failure (replies to our requests) ----
      (#.+msg-channel-success+ t)
      (#.+msg-channel-failure+  t)
      (#.+msg-request-success+  t)
      (#.+msg-request-failure+  t)

      (otherwise nil))))

(defun channel-dispatch-until (conn predicate)
  "Read and dispatch packets until PREDICATE returns true for a packet.
   The matching packet is handled normally and also returned."
  (loop
    (let ((pkt (conn-recv conn)))
      (%handle-packet conn pkt)
      (when (funcall predicate pkt)
        (return pkt)))))
