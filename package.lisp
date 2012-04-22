;;;; package.lisp

(defpackage #:crypt
  (:documentation "Common-Lisp implementation of unix crypt function")
  (:use #:cl)
  (:export #:crypt #:random-salt))

