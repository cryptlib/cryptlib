#!/bin/bash
#
# Create the headers/interface files for non-C languages from the cryptlib
# C header file.

OUTPATH="./bindings"
OUTFILE="$HOME/bindings.zip"
PYTHON=python3

# Check whether we need to fall back to an older version of Python

if [ ! -x /usr/bin/python3 ] ; then
	PYTHON=python2 ;
fi

# Create the Delphi and VB headers.

perl tools/GenPas.pl
perl tools/GenVB.pl
mv -f cryptlib.?as $OUTPATH

# Create the Perl headers

perl tools/GenPerl.pl
mv -f PerlCryptLib.ph $OUTPATH

# Create the Java, Python, and .NET interfaces.

for language in java python net ; do
	$PYTHON ./tools/cryptlibConverter.py3 cryptlib.h $OUTPATH $language ;
done

# Create the Rust interface.

bindgen cryptlib.h -o $OUTPATH/cryptlib.rs

# Bundle everything up for download.  We have to send the pushd output to
# /dev/null since bash performs an implicit 'dirs' if the pushd/popd
# succeeds.

rm -f bindings.zip
pushd $OUTPATH > /dev/null
zip -qo9 "$OUTFILE" cryptlib.bas cryptlib.cs cryptlib.jar cryptlib.pas cryptlib.rs java_jni.c PerlCryptLib.* Makefile.PL python.c setup.py
popd > /dev/null

# Tell the user what we've done

echo "Updated language bindings have been moved to $OUTFILE."
echo ""
