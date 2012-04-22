;;;; crypt.asd

(asdf:defsystem #:crypt
  :serial t
  :description "Common-Lisp implementation of unix crypt function"
  :author "John A.R. Williams <J.A.R.Williams@jarw.org.uk>"
  :license "GPL"
  :components ((:file "package")
               (:file "crypt")))

