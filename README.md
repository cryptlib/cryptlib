# cryptlib Security Toolkit

cryptlib is a security toolkit focused on long-term stability and realiability
that implements a wide range of protocols including S/MIME and PGP/OpenPGP
secure messaging, SSL/TLS and SSH secure sessions, a full range of CA services
such as CMP, SCEP, RTCS, OCSP, SCVP and TSP, and secure authentication
protocols like EAP-TLS, EAP-TTLS, and PEAP.

## Overview

cryptlib's primary goal is stability and reliability, consisting of a highly
mature code base with a 30-year history and an API that's been stable for the
last 20 years - you should be able to take 20-year-old code, recompile it
against the current code base, and it'll still work (you'll just get the
latest algorithms and crypto mechanisms).  This emphasis on long-term
stability means that what you deploy today will still be fine in 10-20 years -
there's no need to roll out patches every two weeks to deal with bugs and
security vulnerabilities.

cryptlib provides a strong emphasis on safe, reliable operation.  Main memory
sections are statically allocated (only variable-sized items like certificates
use dynamic allocation, and even this is done in a FIFO manner where storage
can be drawn from a static memory block if required), allowing the memory
footprint to be determined in advance.  All cryptovariables and algorithms
have extensive protection through self-testing, pairwise consistency checks on
crypto operations, and checksumming of cryptovariables to prevent
modifications, either indirectly (faults) or deliberately (glitch attacks).
All parameters are range-checked and bounds-checked, all loops and array
accesses are statically-bounded, pointers and critical variables are protected
against data corruption and faults, and critical code sections involving
crypto operations have control flow integrity protections to prevent glitches.

cryptlib's development has been driven by user feedback over its 30-year
lifetime, evolving to maximise ease-of-use and minimise the need to plough
through the manual or online forums for every task, augmented by a
comprehensive 400-page manual with extensive ready-to-use code samples for
most tasks.  Requests or bug reports result in a fix and test suite and/or
documentation update to resolve the issue for the future.

The code base is highly tuneable and configurable to allow use in constrained
environments, minimising code size and memory footprints.  The emphasis is on
providing a high-level API that makes it easy to get things right, providing
fully functional interfaces rather than stub APIs that need to be crafted into
a working system.  cryptlib's cross-platform nature means that you can develop
in your preferred environment (Windows, Unix, Mac OS) and then deploy the same
code to the target embedded or RTOS environment, bypassing the need to do
extensive development directly on the embedded hardware.

Alongside the security services, cryptlib provides a sophisticated key storage
interface that allows the use of a wide range of key database types ranging
from PKCS #11 devices, PKCS #15 key files, and PGP/OpenPGP key rings through
to commercial-grade RDBMS' and LDAP directories, as well as interfacing to
cryptographic hardware like PKCS #11 tokens and crypto accelerators, TPMs, and
fully custom crypto hardware via plugin modules.

cryptlib is written in C, with language bindings for C / C++, C# / .NET,
Delphi, Java, Python, and Visual Basic (VB).

## Suppported Platforms

Although cryptlib runs on the usual suspects (every Unix variant including
AIX, Digital Unix, DGUX, FreeBSD/NetBSD/OpenBSD, HP-UX, IRIX, Linux, MP-RAS,
OSF/1, QNX, Solaris, Ultrix, and UTS4), Windows, Mac OS, and lesser-known
systems like IBM MVS, Tandem, and VM/CMS, it's also targeted at embedded,
RTOS, and even bare-metal use, including AMX, ARINC653, ChorusOS, CMSIS, CMX,
eCos, embOS, FreeRTOS/OpenRTOS, uITRON, MGOS, MQX, Nucleus, OSEK, PalmOS,
Quadros, RiotOS, RTEMS, SMX, Telit, ThreadX, TI kernel, T-Kernel, uC/OS II,
VDK, VxWorks, XMK, and Zephyr OS.

## Installation and Usage

cryptlib is provided in source code form and optionally as precompiled DLLs
for Windows.  To build it from source, you can load the project file into
Visual Studio to build for Windows, or for non-Windows environments either
`make` or `make shared` depending on whether you want the static or shared
library.  When you're done, `make install` will set things up for use
systemwide if you're not just using it locally.  More details are given in the
[manual](https://github.com/cryptlib/cryptlib/blob/main/manual.pdf).

cryptlib has a comprehensive [user
manual](https://github.com/cryptlib/cryptlib/blob/main/manual.pdf) containing
many code samples that you can copy directly into your application, so the
following is just a brief overview of how to use it.  To create an S/MIME
signed message:

  ```
  CRYPT_ENVELOPE cryptEnvelope;
  int bytesCopied;

  /* Create the S/MIME envelope */
  cryptCreateEnvelope( &cryptEnvelope, CRYPT_FORMAT_SMIME );

  /* Add the signing key */
  cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE, sigKeyContext );

  /* Push in the data and pop out the signed data */
  cryptPushData( cryptEnvelope, data, dataLength, &bytesCopied );
  cryptFlushData( cryptEnvelope );
  cryptPopData( cryptEnvelope, processedData, processedDataBufsize, &bytesCopied );

  cryptDestroyEnvelope( cryptEnvelope );
  ```

To encrypt instead of signing, change the second function call to:

  ```
  /* Add the certificate of the message recipient */
  cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY, certificate );
  ```

That's all that's necessary (you can copy this code directly into your
application to S/MIME-enable it).  To do the same for PGP/OpenPGP, just change
the CRYPT_FORMAT_SMIME specifier to CRYPT_FORMAT_PGP.

To create an SSL/TLS session:

  ```
  CRYPT_SESSION cryptSession;

  /* Create the TLS session */
  cryptCreateSession( &cryptSession, cryptUser, CRYPT_SESSION_TLS );

  /* Add the server name and activate the session */
  cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_SERVER_NAME, serverName, serverNameLength );
  cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, 1 );
  ```

The corresponding SSL/TLS server is:

  ```
  CRYPT_SESSION cryptSession;

  /* Create the TLS server session */
  cryptCreateSession( &cryptSession, cryptUser, CRYPT_SESSION_TLS_SERVER );

  /* Add the server key/certificate and activate the session */
  cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY, privateKey );
  cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, 1 );
  ```

That's all that's necessary (you can copy this code directly into your
application to TLS-enable it).  As with the S/MIME to PGP switch, to change
this from SSL/TLS to SSH, just change the CRYPT_SESSION_TLS specifier to
CRYPT_SESSION_SSH.

## Contributing

All contributions are welcome, however because we carefully vet any code that
goes into cryptlib to maintain the stability and reliability guarantees (see
the principles in the [overview](#overview) we'll probably rewrite it, add
unit tests and documentation, and so on rather than taking it as is.

To request new features or ask a question, please use the [Discussion
forum](https://github.com/cryptlib/cryptlib/discussions).  For bug reports,
see the [Issues section](https://github.com/cryptlib/cryptlib/issues).  To
privately report an issue such as a vulnerability, see the [Security
section](https://github.com/cryptlib/cryptlib/security).

cryptlib contains contributions from various open-source developers, see the
acknowledgements section of the
[manual](https://github.com/cryptlib/cryptlib/blob/main/manual.pdf) for
details.

## License

cryptlib is dual-licensed:

* Under the historic
[Sleepycat License](https://opensource.org/license/sleepycat-php).  This is an
[Open Source Initiative](https://opensource.org)-approved license that allows
use under standard GPL copyleft terms.

* Optionally [closed-source use](https://www.cryptlib.com) for anyone
requiring commercial support.

cryptlib supports the
[OpenSSL Mission and Values](https://openssl-mission.org/).
