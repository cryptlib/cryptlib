#!/bin/sh
# Get a (non-cryptographic) random seed for compilation.
#
# Usage: getseed.sh osname

OSNAME=""

# Make sure that we've been given sufficient arguments.

if [ $# -lt 1 ] ; then
	echo "Usage: $0 osname" >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

OSNAME=$1
shift

# Get a 64-bit seed value, from /dev/random if possible or from other
# random-ish sources if not.

if [ -r /dev/urandom ] ; then
	# Get the seed as a 64-bit hex string
	if [ "$OSNAME" = "SunOS" ] ; then
		# shellcheck disable=SC2006 # Antediluvian Sun tools.
		SEEDVALUE=`od -An -N8 -tx1 < /dev/urandom | tr -d ' \t\n'` ;
	else
		SEEDVALUE="$(od -An -N8 -tx1 < /dev/urandom | tr -d ' \t\n')" ;
	fi ;
else
	# Without md5sum to process the output we can't continue.  Note that we
	# try and run md5sum directly via 'command' rather than using 'which',
	# which is broken on many systems, see Answer #1 for
	# https://stackoverflow.com/questions/592620/how-can-i-check-if-a-program-exists-from-a-bash-script
	if command -v md5sum > /dev/null 2>&1 ; then
		exit 0 ;
	fi ;

	# There's no /dev/random, fall back to a random-ish alternative.
	if [ "$(which last)" ] ; then
		SOURCE="last -50" ;
	else
		SOURCE="uptime" ;
	fi ;
	if [ "$OSNAME" = "SunOS" ] ; then
		# shellcheck disable=SC2006 # Antediluvian Sun tools.
		SEEDVALUE=`$SOURCE | md5sum | cut -c1-16` ;
	else
		SEEDVALUE="$($SOURCE | md5sum | cut -c1-16)" ;
	fi ;
fi

# Print the 64-bit value as a hex string.  We run the values together to make
# a single string rather than trying to get "0xAA, 0xBB, 0xCC .." through the
# multiple levels of escaped quoting needed for the shell scripts that we're
# called from.

printf -- "-DFIXED_SEED=" ;
if [ "$OSNAME" = "SunOS" ] ; then
	for i in 1 3 5 7 9 11 13 ; do
		# shellcheck disable=SC2006,SC2003 # Antediluvian Sun tools.
		j=`expr $i + 1` ;
		# shellcheck disable=SC2006 # Antediluvian Sun tools.
		printf "0x%s," `echo $SEEDVALUE | cut -c $i-$j` ;
	done ;
	# shellcheck disable=SC2006 # Antediluvian Sun tools.
	printf "0x%s" `echo $SEEDVALUE | cut -c 15-16` ;
else
	for i in 1 3 5 7 9 11 13 ; do
		j="$(expr $i + 1)" ;
		printf "0x%s," "$(echo $SEEDVALUE | cut -c $i-$j)" ;
	done ;
	printf "0x%s" "$(echo $SEEDVALUE | cut -c 15-16)" ;
fi
