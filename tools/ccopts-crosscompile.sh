#!/bin/sh
# Obtain appropriate gcc options for building cryptlib during a cross-compile.
# This is a stripped-down version of tools/ccopts.sh which only performs
# those checks that are safe in a cross-compile build, which in general means
# checking for gcc bugs, see tools/ccopts.sh for an explanation of what the
# following does.
#
# Usage: ccopts-crosscompile.sh compiler

CCARGS=""
GCC_VER=0

# Make sure that we've been given sufficient arguments.

if [ $# -ne 1 ] ; then
	echo "Usage: $0 compiler" >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

CC=$1
shift

# Make sure that the compiler we've been given actually exists/is accessible.
# This is a useful check for the cross-compile case because we're not using
# the default system compiler but something that may not be there, or may
# require the setting of custom paths to be visible/accessible.

if ! [ -x "$(command -v $CC)" ] ; then
	echo "$0: Compiler $CC isn't present or accessible" >&2 ;
	exit 1 ;
fi

# Get the randomness seed.  Since we're running in a hosted environment, we
# use the local OS name, not the one of the target system we're building
# for.

OSNAME="$(uname)"
CCARGS="$(./tools/getseed.sh $OSNAME)"

# If we're not using gcc, we're done.  See the long comment in ccopts.sh for
# the check that we're using here.

if [ "$($CC -v 2>&1 | grep -c "gcc")" = 0 ] ; then
	echo "$CCARGS" ;
	exit 0 ;
fi

# Get any gcc arguments we may need, again see ccopts.sh for the details of
# this.

GCC_VER=`$CC -dumpversion | tr -d  '.' | cut -c 1-2`
if [ "$GCC_VER" -lt 10 ] ; then
	GCC_VER="${GCC_VER}0" ;
fi
if [ $GCC_VER -ge 40 ] ; then
	if [ `$CC -Wno-pointer-sign -S -o /dev/null -xc /dev/null > /dev/null 2>&1` ] ; then
		CCARGS="$CCARGS -Wno-pointer-sign" ;
	fi ;
fi

echo $CCARGS
