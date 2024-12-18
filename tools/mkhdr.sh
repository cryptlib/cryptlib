<<<<<<< HEAD
#!/bin/bash
# Create the headers/interface files for non-C languages from the cryptlib
# C header file.

# Create the Delphi and VB headers.

perl tools/GenPas.pl
perl tools/GenVB.pl
mv -f cryptlib.?as bindings

# Create the Perl headers

perl tools/GenPerl.pl
mv -f PerlCryptLib.ph bindings

# Create the Java, Python, and .NET interface.  We use python3 if available,
# otherwise fall back to python2.

if [ -x /usr/bin/python3 ];then
     python3 tools/cryptlibConverter.py3 cryptlib.h bindings java
     python3 tools/cryptlibConverter.py3 cryptlib.h bindings python
     python3 tools/cryptlibConverter.py3 cryptlib.h bindings net
else
     python2 tools/cryptlibConverter.py cryptlib.h bindings java
     python2 tools/cryptlibConverter.py cryptlib.h bindings python
     python2 tools/cryptlibConverter.py cryptlib.h bindings net
fi

# Bundle everything up for download.  We have to send the pushd output to
# /dev/null since bash performs an implicit 'dirs' if the pushd/popd
# succeeds.

rm -f bindings.zip
pushd bindings > /dev/null
zip -qo9 ../bindings cryptlib.bas cryptlib.cs cryptlib.jar cryptlib.pas java_jni.c PerlCryptLib.* Makefile.PL python.c setup.py
popd > /dev/null

# Tell the user what we've done

echo "Updated language bindings have been moved to file 'bindings.zip'."
echo
=======
#!/bin/bash
# Create the headers/interface files for non-C languages from the cryptlib
# C header file.

# Create the Delphi and VB headers.

perl tools/GenPas.pl
perl tools/GenVB.pl
mv -f cryptlib.?as bindings

# Create the Perl headers

perl tools/GenPerl.pl
mv -f PerlCryptLib.ph bindings

# Create the Java, Python, and .NET interface.  We use python3 if available,
# otherwise fall back to python2.

if [ -x /usr/bin/python3 ];then
     python3 tools/cryptlibConverter.py3 cryptlib.h bindings java
     python3 tools/cryptlibConverter.py3 cryptlib.h bindings python
     python3 tools/cryptlibConverter.py3 cryptlib.h bindings net
else
     python2 tools/cryptlibConverter.py cryptlib.h bindings java
     python2 tools/cryptlibConverter.py cryptlib.h bindings python
     python2 tools/cryptlibConverter.py cryptlib.h bindings net
fi

# Bundle everything up for download.  We have to send the pushd output to
# /dev/null since bash performs an implicit 'dirs' if the pushd/popd
# succeeds.

rm -f bindings.zip
pushd bindings > /dev/null
zip -qo9 ../bindings cryptlib.bas cryptlib.cs cryptlib.jar cryptlib.pas java_jni.c PerlCryptLib.* Makefile.PL python.c setup.py
popd > /dev/null

# Tell the user what we've done

echo "Updated language bindings have been moved to file 'bindings.zip'."
echo
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
