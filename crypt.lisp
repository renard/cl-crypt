;;; Common-Lisp implementation of unix crypt function
;;; This Lisp version
;;; Copyright (C) 2004-2005 John A.R. Williams <J.A.R.Williams@jarw.org.uk>
;;; Based upon C source code written by Eric Young, eay@psych.uq.oz.au
;;; Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
;;; All rights reserved.
;;; Copyright remains Eric Young's, and as such any Copyright notices in
;;; the code are not to be removed.
;;; If this package is used in a product, Eric Young should be given
;;; attribution as the author of the parts of the library used.
;;; This can be in the form of a textual message at program startup or
;;; in documentation (online or textual) provided with the package.
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;; 1. Redistributions of source code must retain the copyright
;;;    notice, this list of conditions and the following disclaimer.
;;; 2. Redistributions in binary form must reproduce the above copyright
;;;    notice, this list of conditions and the following disclaimer in the
;;;    documentation and/or other materials provided with the distribution.
;;; 3. All advertising materials mentioning features or use of this software
;;;    must display the following acknowledgement:
;;;    "This product includes cryptographic software written by
;;;     Eric Young (eay@cryptsoft.com)"
;;;    The word 'cryptographic' can be left out if the rouines from the library
;;;    being used are not cryptographic related :-).
;;; 4. If you include any Windows specific code (or a derivative thereof) from
;;;  the apps directory (application code) you must include an acknowledgement:
;;;  "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
;;;
;;; THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
;;; ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
;;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
;;; OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;;; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
;;; LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
;;; OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
;;; SUCH DAMAGE.
;;;
;;; The licence and distribution terms for any publically available version or
;;; derivative of this code cannot be changed.  i.e. this code cannot simply be
;;; copied and put under another distribution licence
;;; [including the GNU Public Licence.]
;;; $Id: crypt.lisp,v 1.3 2006/07/13 06:20:03 willijar Exp $

(in-package :crypt)

(defparameter +iterations+ 16)
(defparameter +con-salt+
  (make-array
   128 :element-type '(unsigned-byte 8)
   :initial-contents
   #(#X00 #X00 #X00 #X00 #X00 #X00 #X00 #X00
     #X00 #X00 #X00 #X00 #X00 #X00 #X00 #X00
     #X00 #X00 #X00 #X00 #X00 #X00 #X00 #X00
     #X00 #X00 #X00 #X00 #X00 #X00 #X00 #X00
     #X00 #X00 #X00 #X00 #X00 #X00 #X00 #X00
     #X00 #X00 #X00 #X00 #X00 #X00 #X00 #X01
     #X02 #X03 #X04 #X05 #X06 #X07 #X08 #X09
     #X0A #X0B #X05 #X06 #X07 #X08 #X09 #X0A
     #X0B #X0C #X0D #X0E #X0F #X10 #X11 #X12
     #X13 #X14 #X15 #X16 #X17 #X18 #X19 #X1A
     #X1B #X1C #X1D #X1E #X1F #X20 #X21 #X22
     #X23 #X24 #X25 #X20 #X21 #X22 #X23 #X24
     #X25 #X26 #X27 #X28 #X29 #X2A #X2B #X2C
     #X2D #X2E #X2F #X30 #X31 #X32 #X33 #X34
     #X35 #X36 #X37 #X38 #X39 #X3A #X3B #X3C
     #X3D #X3E #X3F #X00 #X00 #X00 #X00 #X00 )))

(defparameter +shifts2+
  #(nil nil t t t t t t nil t  t t t t t nil))

(defparameter +skb+
  (make-array
   '(8 64)
   :element-type '(unsigned-byte 32)
   :initial-contents
   #(
     #(		 ; for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
       #X00000000 #X00000010 #X20000000 #X20000010
       #X00010000 #X00010010 #X20010000 #X20010010
       #X00000800 #X00000810 #X20000800 #X20000810
       #X00010800 #X00010810 #X20010800 #X20010810
       #X00000020 #X00000030 #X20000020 #X20000030
       #X00010020 #X00010030 #X20010020 #X20010030
       #X00000820 #X00000830 #X20000820 #X20000830
       #X00010820 #X00010830 #X20010820 #X20010830
       #X00080000 #X00080010 #X20080000 #X20080010
       #X00090000 #X00090010 #X20090000 #X20090010
       #X00080800 #X00080810 #X20080800 #X20080810
       #X00090800 #X00090810 #X20090800 #X20090810
       #X00080020 #X00080030 #X20080020 #X20080030
       #X00090020 #X00090030 #X20090020 #X20090030
       #X00080820 #X00080830 #X20080820 #X20080830
       #X00090820 #X00090830 #X20090820 #X20090830)
     #(	     ; for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 */
       #X00000000 #X02000000 #X00002000 #X02002000
       #X00200000 #X02200000 #X00202000 #X02202000
       #X00000004 #X02000004 #X00002004 #X02002004
       #X00200004 #X02200004 #X00202004 #X02202004
       #X00000400 #X02000400 #X00002400 #X02002400
       #X00200400 #X02200400 #X00202400 #X02202400
       #X00000404 #X02000404 #X00002404 #X02002404
       #X00200404 #X02200404 #X00202404 #X02202404
       #X10000000 #X12000000 #X10002000 #X12002000
       #X10200000 #X12200000 #X10202000 #X12202000
       #X10000004 #X12000004 #X10002004 #X12002004
       #X10200004 #X12200004 #X10202004 #X12202004
       #X10000400 #X12000400 #X10002400 #X12002400
       #X10200400 #X12200400 #X10202400 #X12202400
       #X10000404 #X12000404 #X10002404 #X12002404
       #X10200404 #X12200404 #X10202404 #X12202404 )
     #(	   ; for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 */
       #X00000000 #X00000001 #X00040000 #X00040001
       #X01000000 #X01000001 #X01040000 #X01040001
       #X00000002 #X00000003 #X00040002 #X00040003
       #X01000002 #X01000003 #X01040002 #X01040003
       #X00000200 #X00000201 #X00040200 #X00040201
       #X01000200 #X01000201 #X01040200 #X01040201
       #X00000202 #X00000203 #X00040202 #X00040203
       #X01000202 #X01000203 #X01040202 #X01040203
       #X08000000 #X08000001 #X08040000 #X08040001
       #X09000000 #X09000001 #X09040000 #X09040001
       #X08000002 #X08000003 #X08040002 #X08040003
       #X09000002 #X09000003 #X09040002 #X09040003
       #X08000200 #X08000201 #X08040200 #X08040201
       #X09000200 #X09000201 #X09040200 #X09040201
       #X08000202 #X08000203 #X08040202 #X08040203
       #X09000202 #X09000203 #X09040202 #X09040203 )
     #(	   ; for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 */
       #X00000000 #X00100000 #X00000100 #X00100100
       #X00000008 #X00100008 #X00000108 #X00100108
       #X00001000 #X00101000 #X00001100 #X00101100
       #X00001008 #X00101008 #X00001108 #X00101108
       #X04000000 #X04100000 #X04000100 #X04100100
       #X04000008 #X04100008 #X04000108 #X04100108
       #X04001000 #X04101000 #X04001100 #X04101100
       #X04001008 #X04101008 #X04001108 #X04101108
       #X00020000 #X00120000 #X00020100 #X00120100
       #X00020008 #X00120008 #X00020108 #X00120108
       #X00021000 #X00121000 #X00021100 #X00121100
       #X00021008 #X00121008 #X00021108 #X00121108
       #X04020000 #X04120000 #X04020100 #X04120100
       #X04020008 #X04120008 #X04020108 #X04120108
       #X04021000 #X04121000 #X04021100 #X04121100
       #X04021008 #X04121008 #X04021108 #X04121108 )
     #(		 ; for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
       #X00000000 #X10000000 #X00010000 #X10010000
       #X00000004 #X10000004 #X00010004 #X10010004
       #X20000000 #X30000000 #X20010000 #X30010000
       #X20000004 #X30000004 #X20010004 #X30010004
       #X00100000 #X10100000 #X00110000 #X10110000
       #X00100004 #X10100004 #X00110004 #X10110004
       #X20100000 #X30100000 #X20110000 #X30110000
       #X20100004 #X30100004 #X20110004 #X30110004
       #X00001000 #X10001000 #X00011000 #X10011000
       #X00001004 #X10001004 #X00011004 #X10011004
       #X20001000 #X30001000 #X20011000 #X30011000
       #X20001004 #X30001004 #X20011004 #X30011004
       #X00101000 #X10101000 #X00111000 #X10111000
       #X00101004 #X10101004 #X00111004 #X10111004
       #X20101000 #X30101000 #X20111000 #X30111000
       #X20101004 #X30101004 #X20111004 #X30111004 )
     #(	     ; for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 */
       #X00000000 #X08000000 #X00000008 #X08000008
       #X00000400 #X08000400 #X00000408 #X08000408
       #X00020000 #X08020000 #X00020008 #X08020008
       #X00020400 #X08020400 #X00020408 #X08020408
       #X00000001 #X08000001 #X00000009 #X08000009
       #X00000401 #X08000401 #X00000409 #X08000409
       #X00020001 #X08020001 #X00020009 #X08020009
       #X00020401 #X08020401 #X00020409 #X08020409
       #X02000000 #X0A000000 #X02000008 #X0A000008
       #X02000400 #X0A000400 #X02000408 #X0A000408
       #X02020000 #X0A020000 #X02020008 #X0A020008
       #X02020400 #X0A020400 #X02020408 #X0A020408
       #X02000001 #X0A000001 #X02000009 #X0A000009
       #X02000401 #X0A000401 #X02000409 #X0A000409
       #X02020001 #X0A020001 #X02020009 #X0A020009
       #X02020401 #X0A020401 #X02020409 #X0A020409 )
     #(	   ; for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 */
       #X00000000 #X00000100 #X00080000 #X00080100
       #X01000000 #X01000100 #X01080000 #X01080100
       #X00000010 #X00000110 #X00080010 #X00080110
       #X01000010 #X01000110 #X01080010 #X01080110
       #X00200000 #X00200100 #X00280000 #X00280100
       #X01200000 #X01200100 #X01280000 #X01280100
       #X00200010 #X00200110 #X00280010 #X00280110
       #X01200010 #X01200110 #X01280010 #X01280110
       #X00000200 #X00000300 #X00080200 #X00080300
       #X01000200 #X01000300 #X01080200 #X01080300
       #X00000210 #X00000310 #X00080210 #X00080310
       #X01000210 #X01000310 #X01080210 #X01080310
       #X00200200 #X00200300 #X00280200 #X00280300
       #X01200200 #X01200300 #X01280200 #X01280300
       #X00200210 #X00200310 #X00280210 #X00280310
       #X01200210 #X01200310 #X01280210 #X01280310 )
     #(	   ; for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 */
       #X00000000 #X04000000 #X00040000 #X04040000
       #X00000002 #X04000002 #X00040002 #X04040002
       #X00002000 #X04002000 #X00042000 #X04042000
       #X00002002 #X04002002 #X00042002 #X04042002
       #X00000020 #X04000020 #X00040020 #X04040020
       #X00000022 #X04000022 #X00040022 #X04040022
       #X00002020 #X04002020 #X00042020 #X04042020
       #X00002022 #X04002022 #X00042022 #X04042022
       #X00000800 #X04000800 #X00040800 #X04040800
       #X00000802 #X04000802 #X00040802 #X04040802
       #X00002800 #X04002800 #X00042800 #X04042800
       #X00002802 #X04002802 #X00042802 #X04042802
       #X00000820 #X04000820 #X00040820 #X04040820
       #X00000822 #X04000822 #X00040822 #X04040822
       #X00002820 #X04002820 #X00042820 #X04042820
       #X00002822 #X04002822 #X00042822 #X04042822 ))))

(defparameter +sptrans+
  (make-array
   '(8 64)
   :element-type '(unsigned-byte 32)
   :initial-contents
   #(
     #(					; nibble 0 */
       #X00820200 #X00020000 #X80800000 #X80820200
       #X00800000 #X80020200 #X80020000 #X80800000
       #X80020200 #X00820200 #X00820000 #X80000200
       #X80800200 #X00800000 #X00000000 #X80020000
       #X00020000 #X80000000 #X00800200 #X00020200
       #X80820200 #X00820000 #X80000200 #X00800200
       #X80000000 #X00000200 #X00020200 #X80820000
       #X00000200 #X80800200 #X80820000 #X00000000
       #X00000000 #X80820200 #X00800200 #X80020000
       #X00820200 #X00020000 #X80000200 #X00800200
       #X80820000 #X00000200 #X00020200 #X80800000
       #X80020200 #X80000000 #X80800000 #X00820000
       #X80820200 #X00020200 #X00820000 #X80800200
       #X00800000 #X80000200 #X80020000 #X00000000
       #X00020000 #X00800000 #X80800200 #X00820200
       #X80000000 #X80820000 #X00000200 #X80020200)
     #(					; /* nibble 1 */
       #X10042004 #X00000000 #X00042000 #X10040000
       #X10000004 #X00002004 #X10002000 #X00042000
       #X00002000 #X10040004 #X00000004 #X10002000
       #X00040004 #X10042000 #X10040000 #X00000004
       #X00040000 #X10002004 #X10040004 #X00002000
       #X00042004 #X10000000 #X00000000 #X00040004
       #X10002004 #X00042004 #X10042000 #X10000004
       #X10000000 #X00040000 #X00002004 #X10042004
       #X00040004 #X10042000 #X10002000 #X00042004
       #X10042004 #X00040004 #X10000004 #X00000000
       #X10000000 #X00002004 #X00040000 #X10040004
       #X00002000 #X10000000 #X00042004 #X10002004
       #X10042000 #X00002000 #X00000000 #X10000004
       #X00000004 #X10042004 #X00042000 #X10040000
       #X10040004 #X00040000 #X00002004 #X10002000
       #X10002004 #X00000004 #X10040000 #X00042000)
     #(					; /* nibble 2 */
       #X41000000 #X01010040 #X00000040 #X41000040
       #X40010000 #X01000000 #X41000040 #X00010040
       #X01000040 #X00010000 #X01010000 #X40000000
       #X41010040 #X40000040 #X40000000 #X41010000
       #X00000000 #X40010000 #X01010040 #X00000040
       #X40000040 #X41010040 #X00010000 #X41000000
       #X41010000 #X01000040 #X40010040 #X01010000
       #X00010040 #X00000000 #X01000000 #X40010040
       #X01010040 #X00000040 #X40000000 #X00010000
       #X40000040 #X40010000 #X01010000 #X41000040
       #X00000000 #X01010040 #X00010040 #X41010000
       #X40010000 #X01000000 #X41010040 #X40000000
       #X40010040 #X41000000 #X01000000 #X41010040
       #X00010000 #X01000040 #X41000040 #X00010040
       #X01000040 #X00000000 #X41010000 #X40000040
       #X41000000 #X40010040 #X00000040 #X01010000)
     #(					; /* nibble 3 */
       #X00100402 #X04000400 #X00000002 #X04100402
       #X00000000 #X04100000 #X04000402 #X00100002
       #X04100400 #X04000002 #X04000000 #X00000402
       #X04000002 #X00100402 #X00100000 #X04000000
       #X04100002 #X00100400 #X00000400 #X00000002
       #X00100400 #X04000402 #X04100000 #X00000400
       #X00000402 #X00000000 #X00100002 #X04100400
       #X04000400 #X04100002 #X04100402 #X00100000
       #X04100002 #X00000402 #X00100000 #X04000002
       #X00100400 #X04000400 #X00000002 #X04100000
       #X04000402 #X00000000 #X00000400 #X00100002
       #X00000000 #X04100002 #X04100400 #X00000400
       #X04000000 #X04100402 #X00100402 #X00100000
       #X04100402 #X00000002 #X04000400 #X00100402
       #X00100002 #X00100400 #X04100000 #X04000402
       #X00000402 #X04000000 #X04000002 #X04100400)
     #(					; /* nibble 4 */
       #X02000000 #X00004000 #X00000100 #X02004108
       #X02004008 #X02000100 #X00004108 #X02004000
       #X00004000 #X00000008 #X02000008 #X00004100
       #X02000108 #X02004008 #X02004100 #X00000000
       #X00004100 #X02000000 #X00004008 #X00000108
       #X02000100 #X00004108 #X00000000 #X02000008
       #X00000008 #X02000108 #X02004108 #X00004008
       #X02004000 #X00000100 #X00000108 #X02004100
       #X02004100 #X02000108 #X00004008 #X02004000
       #X00004000 #X00000008 #X02000008 #X02000100
       #X02000000 #X00004100 #X02004108 #X00000000
       #X00004108 #X02000000 #X00000100 #X00004008
       #X02000108 #X00000100 #X00000000 #X02004108
       #X02004008 #X02004100 #X00000108 #X00004000
       #X00004100 #X02004008 #X02000100 #X00000108
       #X00000008 #X00004108 #X02004000 #X02000008)
     #(					; nibble 5 */
       #X20000010 #X00080010 #X00000000 #X20080800
       #X00080010 #X00000800 #X20000810 #X00080000
       #X00000810 #X20080810 #X00080800 #X20000000
       #X20000800 #X20000010 #X20080000 #X00080810
       #X00080000 #X20000810 #X20080010 #X00000000
       #X00000800 #X00000010 #X20080800 #X20080010
       #X20080810 #X20080000 #X20000000 #X00000810
       #X00000010 #X00080800 #X00080810 #X20000800
       #X00000810 #X20000000 #X20000800 #X00080810
       #X20080800 #X00080010 #X00000000 #X20000800
       #X20000000 #X00000800 #X20080010 #X00080000
       #X00080010 #X20080810 #X00080800 #X00000010
       #X20080810 #X00080800 #X00080000 #X20000810
       #X20000010 #X20080000 #X00080810 #X00000000
       #X00000800 #X20000010 #X20000810 #X20080800
       #X20080000 #X00000810 #X00000010 #X20080010)
     #(					;/* nibble 6 */
       #X00001000 #X00000080 #X00400080 #X00400001
       #X00401081 #X00001001 #X00001080 #X00000000
       #X00400000 #X00400081 #X00000081 #X00401000
       #X00000001 #X00401080 #X00401000 #X00000081
       #X00400081 #X00001000 #X00001001 #X00401081
       #X00000000 #X00400080 #X00400001 #X00001080
       #X00401001 #X00001081 #X00401080 #X00000001
       #X00001081 #X00401001 #X00000080 #X00400000
       #X00001081 #X00401000 #X00401001 #X00000081
       #X00001000 #X00000080 #X00400000 #X00401001
       #X00400081 #X00001081 #X00001080 #X00000000
       #X00000080 #X00400001 #X00000001 #X00400080
       #X00000000 #X00400081 #X00400080 #X00001080
       #X00000081 #X00001000 #X00401081 #X00400000
       #X00401080 #X00000001 #X00001001 #X00401081
       #X00400001 #X00401080 #X00401000 #X00001001)
     #(					; /* nibble 7 */
       #X08200020 #X08208000 #X00008020 #X00000000
       #X08008000 #X00200020 #X08200000 #X08208020
       #X00000020 #X08000000 #X00208000 #X00008020
       #X00208020 #X08008020 #X08000020 #X08200000
       #X00008000 #X00208020 #X00200020 #X08008000
       #X08208020 #X08000020 #X00000000 #X00208000
       #X08000000 #X00200000 #X08008020 #X08200020
       #X00200000 #X00008000 #X08208000 #X00000020
       #X00200000 #X00008000 #X08000020 #X08208020
       #X00008020 #X08000000 #X00000000 #X00208000
       #X08200020 #X08008020 #X08008000 #X00200020
       #X08208000 #X00000020 #X00200020 #X08008000
       #X08208020 #X00200000 #X08200000 #X08000020
       #X00208000 #X00008020 #X08008020 #X08200000
       #X00000020 #X08208000 #X00208020 #X00000000
       #X08000000 #X08200020 #X00008000 #X00208020))))

(defparameter +cov-2char+
  (make-array
   64 :element-type '(unsigned-byte 32)
   :initial-contents
   #(#X2E #X2F #X30 #X31 #X32 #X33 #X34 #X35
     #X36 #X37 #X38 #X39 #X41 #X42 #X43 #X44
     #X45 #X46 #X47 #X48 #X49 #X4A #X4B #X4C
     #X4D #X4E #X4F #X50 #X51 #X52 #X53 #X54
     #X55 #X56 #X57 #X58 #X59 #X5A #X61 #X62
     #X63 #X64 #X65 #X66 #X67 #X68 #X69 #X6A
     #X6B #X6C #X6D #X6E #X6F #X70 #X71 #X72
     #X73 #X74 #X75 #X76 #X77 #X78 #X79 #X7A)))

(declaim (inline lshift rshift))
(defun lshift(value n)
  (declare (type (unsigned-byte 32) value)
	   (type (integer 0 31) n)
	   (optimize speed  #+cmu(extensions:inhibit-warnings 3)))
  (the (unsigned-byte 32) (dpb value (byte (- 32 n) n) 0)))

(defun rshift(value n)
  (declare (type (unsigned-byte 32) value)
	   (type (integer 0 31) n)
	   (optimize speed #+cmu(extensions:inhibit-warnings 3)))
  (the (unsigned-byte 32) (ldb (byte (- 32 n) n) value)))


(defun 4-octets-to-word(bytes &optional (offset 0))
  (let ((value (aref bytes offset)))
    (declare (type (unsigned-byte 32) value)
	     (type (unsigned-byte 28) offset)
	     (type (simple-array (unsigned-byte 8) *) bytes)
	     (optimize speed #+cmu(extensions:inhibit-warnings 3)))
    (setf value (dpb (aref bytes (incf offset)) (byte 8 8) value))
    (setf value
	  (dpb (aref bytes (incf offset)) (byte 8 16) value))
    (the (unsigned-byte 32)
      (dpb (aref bytes (incf offset)) (byte 8 24) value))))

(defun word-to-4-octets(value bytes &optional (offset 0))
  (declare (type (unsigned-byte 32) value)
	   (type (unsigned-byte 28) offset)
	   (type (simple-array (unsigned-byte 8) *) bytes)
	   (optimize speed #+cmu(extensions:inhibit-warnings 3)))
  (setf (aref bytes offset) (ldb (byte 8 0) value))
  (setf (aref bytes (incf offset)) (ldb (byte 8 8) value))
  (setf (aref bytes (incf offset)) (ldb (byte 8 16) value))
  (setf (aref bytes (incf offset)) (ldb (byte 8 24) value))
  bytes)

(defun perm-op(a b n m)
  (declare (type (unsigned-byte 32) a b m)
	   (type (unsigned-byte 8) n)
	   (optimize speed #+cmu(extensions:inhibit-warnings 3)))
  (let ((temp (logand (logxor (rshift a n) b) m)))
    (declare (type (unsigned-byte 32) temp))
    (values (the (unsigned-byte 32) (logxor a (lshift temp n)))
	    (the (unsigned-byte 32) (logxor b temp)))))

(defun hperm-op(a n m)
  (declare (type (unsigned-byte 32) a m)
	   (type (integer -2 -2) n)
	   (optimize speed #+cmu(extensions:inhibit-warnings 3)))
  (let* ((shift (- 16 n))
	 (temp (logand (logxor (lshift a shift) a) m)))
    (declare (type (unsigned-byte 32) temp))
    (the (unsigned-byte 32) (logxor a temp (rshift temp shift)))))

(defun bits(value)
  (let ((bits))
    (dotimes(i 32)
      (push (logand value 1) bits)
      (setq value (rshift value 1)))
    (reverse bits)))

(defun des-set-key(key)
  (declare (type (simple-array (unsigned-byte 8) (8)) key))
  (let ((schedule (make-array 32 :element-type '(unsigned-byte 32)))
	(c (4-octets-to-word key 0))
	(d (4-octets-to-word key 4)))
    (declare (type (unsigned-byte 32) c d))
    (multiple-value-setq (d c) (perm-op d c 4 #X0f0f0f0f))
    (setq c (hperm-op c -2  #Xcccc0000)
	  d (hperm-op d -2  #Xcccc0000))

    (multiple-value-setq (d c) (perm-op d c 1 #X55555555))
    (multiple-value-setq (c d) (perm-op c d 8 #X00ff00ff))
    (multiple-value-setq (d c) (perm-op d c 1 #X55555555))
    (setq d (logior (lshift (logand d #X000000ff) 16)
		    (logand d  #X0000ff00)
		    (rshift (logand d #X00ff0000) 16)
		    (rshift (logand c #Xf0000000) 4))
	  c (logand c #X0fffffff))

    (dotimes(i +iterations+)
      (if (aref +shifts2+ i)
	  (setq c (logior (rshift c 2) (lshift c 26))
		d (logior (rshift d 2) (lshift d 26)))
	  (setq c (logior (rshift c 1) (lshift c 27))
		d (logior (rshift d 1) (lshift d 27))))
      (setq c (logand c #X0fffffff)
	    d (logand d #X0fffffff))
      (let ((%s
	     (logior
	      (aref +skb+ 0 (logand c #X3f))
	      (aref +skb+ 1 (logior (logand (rshift c 6) #X03)
				    (logand (rshift c 7) #X3C)))
	      (aref +skb+ 2 (logior (logand (rshift c 13) #X0F)
				    (logand (rshift c 14) #X30)))
	      (aref +skb+ 3 (logior (logand (rshift c 20) #X01)
				    (logand (rshift c 21) #X06)
				    (logand (rshift c 22) #X38)))))
	    (%t
	     (logior
	      (aref +skb+ 4 (logand d #X3f))
	      (aref +skb+ 5 (logior (logand (rshift d 7) #X03)
				    (logand (rshift d 8) #X3C)))
	      (aref +skb+ 6 (logand (rshift d 15) #X3F))
	      (aref +skb+ 7 (logior (logand (rshift d 21) #X0F)
				    (logand (rshift d 22) #X30))))))
	(let ((j (* 2 i)))
	  (setf (aref schedule j)
		(logand (logior (lshift %t 16) (logand %s #X0000ffff))
			#Xffffffff))
	  (setq %s (logior (rshift %s 16) (logand %t #Xffff0000)))
	  (setf (aref schedule (1+ j))
		(logand (logior (lshift %s 4) (rshift %s 28)) #Xffffffff)))))
    schedule))

(defun d-encrypt(l r idx e0 e1 s)
  (declare (type (unsigned-byte 32) l r e0 e1)
	   (type (integer 0 31)  idx)
	   (type (simple-array (unsigned-byte 32) (32)) s)
	   (optimize speed #+cmu(extensions:inhibit-warnings 3)))
  (let* ((%t (logxor r (rshift r 16)))
	 (%u (logand %t e0))
	 (%v (logand %t e1)))
    (declare (type (unsigned-byte 32) %t %u %v))
    (setq %u (logxor %u (lshift %u 16) r (aref s idx))
	  %t (logxor %v (lshift %v 16) r (aref s (1+ idx))))
    (setq %t (logior (rshift %t 4) (lshift %t 28)))
    (logxor
     l
     (logior
      (aref +sptrans+ 1 (logand %t #X3f))
      (aref +sptrans+ 3 (logand (rshift %t 8) #X3f))
      (aref +sptrans+ 5 (logand (rshift %t 16) #X3f))
      (aref +sptrans+ 7 (logand (rshift %t 24) #X3f))
      (aref +sptrans+ 0 (logand %u #X3f))
      (aref +sptrans+ 2 (logand (rshift %u 8) #X3f))
      (aref +sptrans+ 4 (logand (rshift %u 16) #X3f))
      (aref +sptrans+ 6 (logand (rshift %u 24) #X3f))))))

(defun body(schedule e0 e1)
  (declare (type (simple-array (unsigned-byte 32) (32)) schedule)
	   (type (unsigned-byte 32) e0 e1)
	   (optimize speed #+cmu(extensions:inhibit-warnings 3)))
  (let ((left 0)
	(right 0))
    (dotimes(j 25)
      (do((i 0 (incf i 4)))
	 ((>= i (* 2 +iterations+)))
	(setq left (d-encrypt left right i e0 e1 schedule))
	(setq right (d-encrypt right left (+ 2 i) e0 e1 schedule)))
      (let ((%t left))
	(setq left right
	      right %t)))
    (let ((%t right))
      (setq right (logior (rshift left 1) (lshift left 31))
	    left  (logior (rshift %t 1) (lshift %t 31))))
    (setq left (logand left #Xffffffff)
	  right (logand right #Xffffffff))
    (multiple-value-setq(right left) (perm-op right left 1 #X55555555))
    (multiple-value-setq(left right) (perm-op left right 8 #X00ff00ff))
    (multiple-value-setq(right left) (perm-op right left 2 #X33333333))
    (multiple-value-setq(left right) (perm-op left right 16 #X0000ffff))
    (multiple-value-setq(right left) (perm-op right left 4 #X0f0f0f0f))
    (values left right)))

(defun crypt(PWD &optional (salt "AA"))
  "Password encrypion function.
PWD is the user's typed password.
SALT is a two character string chosen from the set [a-zA-Z0-9./] used to
perturb the algorithm in one of 4096 different ways.
Returns the 13 character encrypted password."
  (declare (type string salt pwd))
  (assert (= 2 (length salt)))
  (let ((buffer (make-string 13)))
    (setf (subseq buffer 0 2) salt)
    (let ((e0 (aref +con-salt+ (char-code (aref salt 0))))
          (e1 (lshift (aref +con-salt+ (char-code (aref salt 1))) 4))
          (key (make-array  8 :element-type '(unsigned-byte 8)
                            :initial-element 0)))
      (declare (type (unsigned-byte 32) e0 e1))
      (dotimes(i (min (length key) (length pwd)))
        (setf (aref key i) (lshift (char-code (char pwd i)) 1)))
      (multiple-value-bind(left right) (body (des-set-key key) e0 e1)
        (let ((b (make-array  9 :element-type '(unsigned-byte 8))))
          (word-to-4-octets left b 0)
          (word-to-4-octets right b 4)
          (setf (aref b 8) 0)
          (let ((y 0)
                (u #X80))
            (do((i 2 (1+ i)))
               ((<= 13 i))
              (let ((c 0))
                (do((j 0 (1+ j)))
                   ((<= 6 j))
                  (setq c (lshift c 1))
                  (when (/= (logand (aref b y) u) 0)
                    (setq c (logior c 1)))
                  (setq u (rshift u 1))
                  (when (= 0 u)
                    (incf y)
                    (setq u #X80))
                  (setf (aref buffer i)
                        (code-char (aref +cov-2char+ c))))))))))
    buffer))

(defun random-salt(&optional (length 2))
  "Generate random salt string of given length (default 2)"
  (let((salt-chars
        "abcdefghijklmnopqestuvwxyzABCDEFGHIJKLMNOPQESTUVWXYZ0123456789./")
       (salt (make-string length))
       (*random-state* (make-random-state t)))
    (dotimes(idx (length salt))
      (setf (char salt idx) (char salt-chars (random (length salt-chars)))))
    salt))
