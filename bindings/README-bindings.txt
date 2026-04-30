#----------------------------#
README-bindings
Ralf Senderek, April 2026
#----------------------------#

cryptlib is written in C, but it can also be used with a number of programming languages,
such as PYTHON3, PERL and JAVA.

This README explains what you need to do in order to be able to use the cryptlib shared 
library in your own project, written in one of the programming languages mentioned above.

#----------------------------#
 The cryptlib shared library:
#----------------------------#

Once you have downloaded the cryptlib source code "cryptlib-3.4.9.1.zip" 
into your current directory, you can build the shared library with the command:

    make clean; make shared

In case you have CLANG installed, the library is compiled with clang automatically.
Otherwise gcc is used to build the library. 

The result is a file "libcl.so.3.4.9.1" which should be copied into the proper
directory:

    cp libcl.so.3.4.9.1 /usr/lib64
    cd /usr/lib64
    ln -s libcl.so.3.4.9.1 libcl.so.3.4
    ln -s libcl.so.3.4.9.1 libcl.so

The symbolic links in the /usr/lib64 directory are necessary to make the new library
available under the SONAME 3.4 as libcl.so.

The following explanations are based on a RPM Linux like Fedora or Centos.
In DEB Linux like Ubuntu the target directories may be different. 

You will find a bash script ./tools/mkhdr.sh in the tools subdirectory which produces
several files which are the foundation for binding the shared library to the three
programming languages below.

     ./tools/mkhdr.sh

Now you'll find the following files in the "./bindings" subdirectory:     
Please stay in the "bindings" subdirectory, unless stated.

     cd ./bindings
     /bin/ls

     drwxr-xr-x 2 ralph ralph    200 18. Apr 19:06 cryptlib
     -rw-r--r-- 1 ralph ralph  95770 18. Apr 19:06 cryptlib.bas
     -rw-r--r-- 1 ralph ralph 144191 18. Apr 19:06 cryptlib.cs
     -rw-r--r-- 1 ralph ralph  48082 18. Apr 19:06 cryptlib.jar
     -rw-r--r-- 1 ralph ralph  98397 18. Apr 19:06 cryptlib.pas
     -rw-r--r-- 1 ralph ralph 105214 15. Apr 03:21 cryptlib-perl.h
     -rw-r--r-- 1 ralph ralph 102593 18. Apr 19:06 cryptlib.rs
     -rw-r--r-- 1 ralph ralph  37087 15. Apr 18:09 function-comments.py3
     -rw-r--r-- 1 ralph ralph 110144 15. Apr 18:07 javadoc.h
     -rw-r--r-- 1 ralph ralph 140158 18. Apr 19:06 java_jni.c
     -rw-r--r-- 1 ralph ralph   3095  7. Feb 17:22 Makefile.PL
     -rw-r--r-- 1 ralph ralph  96403 18. Apr 19:06 PerlCryptLib.ph
     -rw-r--r-- 1 ralph ralph  13853 15. Apr 05:58 PerlCryptLib.pm
     -rw-r--r-- 1 ralph ralph  16327 14. Apr 05:19 PerlCryptLib.xs
     -rw-r--r-- 1 ralph ralph 193172 18. Apr 19:06 python.c
     -rw-r--r-- 1 ralph ralph   1647 18. Apr 19:05 README-bindings
     -rw-r--r-- 1 ralph ralph    478 18. Apr 19:06 setup.py


#----------------------------#
         PYTHON 3
#----------------------------#

In order to make cryptlib available in python programs, you will import everything
from the cryptlib_py module which can be built with the setup.py script:

     /usr/bin/python3 setup.py build

     running build
     running build_ext
     building 'cryptlib_py' extension
     creating build
     creating build/temp.linux-x86_64-cpython-313
     gcc -fno-strict-overflow -Wsign-compare -DDYNAMIC_ANNOTATIONS_ENABLED=1 -DNDEBUG -fexceptions -fcf-protection -fexceptions -fcf-protection -fexceptions -fcf-protection -O3 -fPIC -I/usr/include/python3.13 -c python.c -o build/temp.linux-x86_64-cpython-313/python.o
     creating build/lib.linux-x86_64-cpython-313
gcc -shared build/temp.linux-x86_64-cpython-313/python.o -L.. -L/usr/lib64 -lcl -o build/lib.linux-x86_64-cpython-313/cryptlib_py.cpython-313-x86_64-linux-gnu.so


Finally the shared library for python3 should be copied into a directory where python can import it. 
Please use the Python site-package directory for your python installation.

     cp build/lib.linux-x86_64-cpython-313/cryptlib_py.cpython-313-x86_64-linux-gnu.so /usr/lib/python3.13/site-packages/cryptlib_py.so


#----------------------------#
         PERL
#----------------------------#

Building the shared library for the PERL binding requires two additional files, that you can 
find on my web server.

     wget https://senderek.ie/fedora/cryptlib-perlfiles.tar.gz .
     /usr/bin/tar xpzf cryptlib-perlfiles.tar.gz
     ls -l

     -rw-r--r-- ralph/ralph   15381 2009-03-03 08:35 ppport.h
     -rw-r--r-- ralph/ralph      46 2009-03-03 08:35 typemap

     /usr/bin/cp ../tools/GenPerl.pl .
     export PERL_CRYPT_LIB_HEADER=cryptlib-perl.h
     /usr/bin/perl Makefile.PL INSTALLDIRS=vendor
     make

          [...]
          gcc  -lpthread -shared -Wl,-z,relro -Wl,--as-needed -Wl,-z,pack-relative-relocs -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -Wl,--build-id=sha1  -L/usr/local/lib -fstack-protector-strong  PerlCryptLib.o  -o blib/arch/auto/PerlCryptLib/PerlCryptLib.so  \
          -lresolv -lpthread -lcl -lperl   \
  
          chmod 755 blib/arch/auto/PerlCryptLib/PerlCryptLib.so
          [...]


     ls -l blib/arch/auto/PerlCryptLib/PerlCryptLib.so
     -rwxr-xr-x 1 ralph ralph 303968 18. Apr 19:50 blib/arch/auto/PerlCryptLib/PerlCryptLib.so

Now the shared library (and three other files) need to be placed into their proper directories:

     /usr/bin/mkdir -p /usr/lib64/perl5/vendor_perl/auto/PerlCryptLib
     /usr/bin/cp blib/arch/auto/PerlCryptLib/PerlCryptLib.so /usr/lib64/perl5/vendor_perl/auto/PerlCryptLib
     /usr/bin/cp blib/lib/auto/PerlCryptLib/autosplit.ix /usr/lib64/perl5/vendor_perl/auto/PerlCryptLib
     /usr/bin/cp blib/lib/PerlCryptLib.* /usr/lib64/perl5/vendor_perl

And the manual page goes into :

     /usr/bin/cp blib/man3/PerlCryptLib.3pm /usr/share/man/man3


#----------------------------#
         JAVA
#----------------------------#

The use of JAVA is disabled by default. If you wish to use cryptlib with JAVA, you need
to re-build the cryptlib shared library with USE_JAVA enabled. 
It's best to enable the use of JAVA JNI in the config file misc/config.h by uncommenting
line 299 or you can use the sed command to do that automatically :

     299 #define USE_JAVA 

     # enable JAVA in config
     sed -i 's/\/\* #define USE_JAVA \*\// #define USE_JAVA /' misc/config.h

Now you have to re-build the shared library and replace the file in /usr/lib64

And of course, you need to re-do the command ./tools/mkhdr.sh, which builds the
file "cryptlib.jar" that contains all the JAVA classes.
Copy the file "cryptlib.jar" wherever you expect your JAVA classes to reside.

     /usr/bin/cp cryptlib.jar /usr/lib/java


#----------------------------#
         JAVADOC
#----------------------------#

To support the development of JAVA projects that use cryptlib, you can build a
comprehensive HTML documentation with the following commands:
(You are still in the bindings directory)

     # build javadoc with separate header file
     mkdir javadoc
     chmod +x ../tools/cryptlibConverter.py3
     cp function-comments.py3 javadoc
     ../tools/cryptlibConverter.py3 javadoc.h javadoc java
     cd javadoc
     # to ensure english terminology in HTML files
     export LC_ALL=en_EN.utf8
     javadoc cryptlib -encoding utf-8

Now you can copy the files in "javadoc" to your web server or a local directory.     

#----------------------------#
         The MANUAL
#----------------------------#

For all questions regarding the use of cryptlib's functionality please refer to 
the manual.pdf in the source code, or use the up-to-date manual that you can find
on Peter Gutmann's GITHUB repository:

     https://github.com/cryptlib/cryptlib


#----------------------------#
         TEST PROGRAMS 
#----------------------------#

Feel free to check out the test programs that I publish on my web site:

    https://senderek.ie/fedora/cryptlib-tests.tar.gz
    https://senderek.ie/fedora/cryptlib-tools.tar.gz

(c) Version 1.0 April 2026
