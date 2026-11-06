;;;; Derived from 3bz; see ORIGIN.md for provenance and license.
(in-package #:ssh/compression/zlib/inflate)

(deftype octet () '(unsigned-byte 8))
(deftype octet-vector () '(simple-array octet (*)))

(defgeneric boxes (context))

;; Typed container for offsets and bounds of the current input source.
(defstruct (context-boxes (:conc-name cb-))
  (start 0 :type size-t)
  (end 0 :type size-t)
  (offset 0 :type size-t))

(defmacro context-common ((boxes) &body body)
  `(macrolet ((pos ()
                `(cb-offset ,',boxes))
              (end ()
                `(cb-end ,',boxes))
              (%octet (read-form
                       &optional (eob-form
                                  '(error "read past end of buffer")))
                `(progn
                   (when (>= (pos) (end))
                     ,eob-form)
                   (prog1
                       ,read-form
                     (incf (pos)))))
              (octets-left ()
                `(- (cb-end ,',boxes) (pos))))
     ,@body))

(defclass octet-vector-context ()
  ((octet-vector :reader octet-vector :initarg :octet-vector)
   (boxes :reader boxes :initarg :boxes)))

(defun make-octet-vector-context (vector &key (start 0) (offset start)
                                           (end (length vector)))
  (make-instance 'octet-vector-context
                 :octet-vector vector
                 :boxes (make-context-boxes
                         :start start :offset offset :end end)))

(defmacro with-vector-context ((context) &body body)
  (with-gensyms (context-value boxes vector)
      `(let* ((,context-value ,context)
              (,boxes (boxes ,context-value))
              (,vector (octet-vector ,context-value)))
         (declare (optimize speed)
                  (ignorable ,vector ,boxes)
                  (type context-boxes ,boxes))
         (check-type ,vector octet-vector)
         (locally (declare (type octet-vector ,vector))
           (context-common (,boxes)
             (macrolet (;; Read up to 8 octets in little-endian order and
                        ;; return the value and number of octets read.
                        (word64 ()
                          (with-gensyms (available result)
                            `(let ((,available (octets-left)))
                               (if (>= ,available 8)
                                   (let ((,result (ub64ref/le
                                                   ,',vector (pos))))
                                     (incf (pos) 8)
                                     (values ,result 8))
                                   (let ((,result 0))
                                     (loop
                                       for i fixnum below ,available
                                       do (setf ,result
                                                (ldb (byte 64 0)
                                                     (logior
                                                      ,result
                                                      (ash
                                                       (aref ,',vector
                                                             (+ (pos) i))
                                                       (* i 8))))))
                                     (incf (pos) ,available)
                                     (values ,result ,available))))))
                        (word32 (&optional (maximum-octets 4))
                          (with-gensyms (available result limit)
                            `(let* ((,limit (min 4 ,maximum-octets))
                                    (,available
                                      (min ,limit (octets-left))))
                               (declare (type (integer 0 4)
                                              ,limit ,available))
                               (if (= ,available 4)
                                   (let ((,result (ub32ref/le
                                                   ,',vector (pos))))
                                     (incf (pos) 4)
                                     (values ,result 4))
                                   (let ((,result 0))
                                     (loop
                                       for i of-type (unsigned-byte 2)
                                         below (min 4 ,available)
                                       do (setf ,result
                                                (ldb (byte 32 0)
                                                     (logior
                                                      ,result
                                                      (ash
                                                       (aref ,',vector
                                                             (+ (pos) i))
                                                       (* i 8))))))
                                     (incf (pos) ,available)
                                     (values ,result ,available)))))))
               ,@body))))))
