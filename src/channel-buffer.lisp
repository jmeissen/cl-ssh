(uiop:define-package #:ssh/channel-buffer
  (:use #:cl)
  (:export #:make-input-buffer #:input-buffer-count #:input-buffer-mode
           #:input-buffer-truncated-p #:buffer-accept #:buffer-take
           #:buffer-snapshot))
(in-package #:ssh/channel-buffer)

;; The channel state lock protects every operation on an input buffer.

(defclass input-buffer ()
  ((count :initform 0 :accessor input-buffer-count)
   (position :initform 0 :accessor input-buffer-position)
   (truncated-p :initform nil :accessor input-buffer-truncated-p)))

(defun %discard (buffer count)
  (decf (input-buffer-count buffer) count)
  (loop while (plusp count)
        for chunk = (car (input-buffer-head buffer))
        for available = (- (length chunk) (input-buffer-position buffer))
        for take = (min count available)
        do (incf (input-buffer-position buffer) take)
           (decf count take)
           (when (= take available)
             (pop (input-buffer-head buffer))
             (setf (input-buffer-position buffer) 0)
             (unless (input-buffer-head buffer)
               (setf (input-buffer-tail buffer) nil)))))

(defgeneric buffer-accept (buffer octets)
  (:documentation "Accept incoming channel bytes according to the buffer's retention policy.
BUFFER is protected by its owning channel's state lock.
OCTETS contains incoming binary data.
Returns the number of bytes immediately eligible for window credit."))

(defgeneric buffer-take (buffer destination start end)
  (:documentation "Consume available channel bytes into a sequence.
BUFFER is protected by its owning channel's state lock.
DESTINATION receives bytes between START and END.
Returns the number of bytes copied and the earned receive-window credit."))

(defgeneric buffer-snapshot (buffer)
  (:documentation "Copy retained channel bytes without consuming them.
BUFFER is protected by its owning channel's state lock.
Returns unread bytes, complete captured history, or the retained diagnostic tail."))

(defclass chunk-buffer (input-buffer)
  ((head :initform nil :accessor input-buffer-head)
   (tail :initform nil :accessor input-buffer-tail)))

(defclass stream-buffer (chunk-buffer) ())

(defclass tail-buffer (chunk-buffer)
  ((limit :initarg :limit :initform 65536 :reader input-buffer-limit)))

(defclass capture-buffer (input-buffer)
  ((history :initform (make-array 0 :element-type '(unsigned-byte 8)
                                   :adjustable t :fill-pointer 0)
            :accessor input-buffer-history)))

(defun make-input-buffer (&key (mode :stream) (limit 65536))
  "Create a channel input buffer with a fixed retention policy.
MODE selects :STREAM, :CAPTURE, or :TAIL.
LIMIT bounds the number of bytes retained by a :TAIL buffer.
Returns a new input buffer."
  (ecase mode
    (:stream (make-instance 'stream-buffer))
    (:capture (make-instance 'capture-buffer))
    (:tail (make-instance 'tail-buffer :limit limit))))

(defgeneric input-buffer-mode (buffer)
  (:documentation "Identify a buffer's retention policy.
BUFFER is a channel input buffer.
Returns :STREAM, :CAPTURE, or :TAIL."))

(defmethod input-buffer-mode ((buffer stream-buffer)) :stream)

(defmethod input-buffer-mode ((buffer capture-buffer)) :capture)

(defmethod input-buffer-mode ((buffer tail-buffer)) :tail)

(defmethod buffer-accept ((buffer chunk-buffer) octets)
  (unless (zerop (length octets))
    (let ((cell (list (copy-seq octets))))
      (if (input-buffer-tail buffer)
          (setf (cdr (input-buffer-tail buffer)) cell)
          (setf (input-buffer-head buffer) cell))
      (setf (input-buffer-tail buffer) cell))
    (incf (input-buffer-count buffer) (length octets)))
  (length octets))

(defmethod buffer-accept ((buffer stream-buffer) octets)
  (call-next-method)
  0)

(defmethod buffer-accept ((buffer tail-buffer) octets)
  (prog1 (call-next-method)
    (when (> (input-buffer-count buffer) (input-buffer-limit buffer))
      (setf (input-buffer-truncated-p buffer) t)
      (%discard buffer (- (input-buffer-count buffer) (input-buffer-limit buffer))))))

(defmethod buffer-accept ((buffer capture-buffer) octets)
  (let* ((count (length octets))
         (history (input-buffer-history buffer))
         (old (length history))
         (new (+ old count)))
    (when (> new (array-total-size history))
      (setf history (adjust-array history (max new (* 2 (array-total-size history))))
            (input-buffer-history buffer) history))
    (setf (fill-pointer history) new)
    (replace history octets :start1 old)
    (incf (input-buffer-count buffer) count)
    count))

(defmethod buffer-take ((buffer chunk-buffer) destination start end)
  (let ((count (min (- end start) (input-buffer-count buffer))))
    (loop with remaining = count
          while (plusp remaining)
          for chunk = (car (input-buffer-head buffer))
          for take = (min remaining (- (length chunk) (input-buffer-position buffer)))
          do (replace destination chunk :start1 start :end1 (+ start take)
                      :start2 (input-buffer-position buffer))
             (%discard buffer take)
             (incf start take)
             (decf remaining take))
    (values count 0)))

(defmethod buffer-take ((buffer stream-buffer) destination start end)
  (let ((count (call-next-method)))
    (values count count)))

(defmethod buffer-take ((buffer capture-buffer) destination start end)
  (let ((count (min (- end start) (input-buffer-count buffer))))
    (replace destination (input-buffer-history buffer)
             :start1 start :end1 (+ start count)
             :start2 (input-buffer-position buffer))
    (incf (input-buffer-position buffer) count)
    (decf (input-buffer-count buffer) count)
    (values count 0)))

(defmethod buffer-snapshot ((buffer capture-buffer))
  (copy-seq (input-buffer-history buffer)))

(defmethod buffer-snapshot ((buffer chunk-buffer))
  (let ((result (make-array (input-buffer-count buffer) :element-type '(unsigned-byte 8)))
        (offset 0))
    (loop for cell on (input-buffer-head buffer)
          for start = (input-buffer-position buffer) then 0
          for chunk = (car cell)
          do (replace result chunk :start1 offset :start2 start)
             (incf offset (- (length chunk) start)))
    result))
