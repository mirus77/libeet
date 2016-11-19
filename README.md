# libEET
---
libEET library provides C wrapper compiled into one DLL file based on libxml2, xmlsec, openssl  for creating registered sale data messages. http://www.etrzby.cz 

libEET is based on well known XMLSec (http://http://www.aleksey.com/xmlsec/), LibXML (http://xmlsoft.org), LibXSLT (http://xmlsoft.org/XSLT) and OpenSSL (http://www.openssl.org) libraries.

This code is released under the MIT Licence see the Copyright file.

Miroslav Kundela <mail@mirus.cz>

Installation
---

Compile OpenSSL, LibXML, LibXSLT, XMLSec.

```
run win32/_buildtools.bat
cmd inside:/> buildall.bat
```