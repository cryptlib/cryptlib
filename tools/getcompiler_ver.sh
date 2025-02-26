#!/bin/sh
# Get the clang/gcc compiler version, assumes the caller has already checked
# that $compiler is either gcc or clang.
#
# Usage: getcompiler_ver.sh compiler

ISCLANG_WRAPPER=0

# Make sure that we've been given sufficient arguments.

if [ $# -lt 1 ] ; then
	echo "Usage: $0 compiler" >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

CC=$1
shift

# Check whether we're running clang via a wrapper.

if [ "$(echo $CC | grep -ci "afl-clang")" -gt 0 ] ; then
	ISCLANG_WRAPPER=1 ;
fi ;

# Find out which version of clang or gcc we're using.  The check for the gcc
# version is complicated by the fact that a (rare) few localised gcc's don't
# use a consistent version number string.  Almost all versions print "gcc
# version", but the French localisation has "version gcc" (we can't use just
# "gcc" by itself since this appears elsewhere in the gcc -v output, as well
# as the clang output).
#
# To make things even more confusing, Apple's hacked-up gcc branch (before
# they switched to clang) printed something like
# "PowerPC-Apple-Is-Great-I-Love-Darwin-4567-Hup234-gcc-x.y.z", so any
# simple attempt at extracting what looks like a version number will fail.
# The only way to get around this is to look for the first set of numeric
# values that follow the string "gcc" and use that as the version number.
#
# In order to avoid this mess we use the "-dumpversion" option, which has
# worked since at least 2.7.2 although it wasn't actually documented until
# the first 3.x releases, and works in all versions of clang.  Since clang
# may be called via a wrapper, we have to explicitly call it in this case
# since the wrapper won't give us the clang version.
#
# However, dumpversion has its own problems in that it lists major-version
# releases as a single-digit number, '6' rather than '6.0', and the major
# version itself may have one or two digits, so if we find a single-digit
# version we add a trailing zero to the string (first case), otherwise we
# use the first two or three digits depending on what the string starts
# with.
#
# However with a major-version release >= 10 we get the same problem as with
# single-digit major-versons so we also add a trailing zero to two-digit
# versions, which will be removed by the 3-digit cut if the version is xyz
# already but not if it's xy0-added (second case).

if [ $ISCLANG_WRAPPER -gt 0 ] ; then
	COMPILER_VER="$(clang -dumpversion)" ;
else
	COMPILER_VER="$($CC -dumpversion)" ;
fi ;
case $COMPILER_VER in

	[0-9])
		COMPILER_VER="${COMPILER_VER}0" ;;

	[0-9][0-9]*)
		COMPILER_VER="$(echo ${COMPILER_VER}0 | tr -d  '.' | cut -c 1-3)" ;;

	*)
		COMPILER_VER="$(echo $COMPILER_VER | tr -d  '.' | cut -c 1-2)" ;;
esac

echo $COMPILER_VER
