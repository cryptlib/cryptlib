#!/bin/sh
# Obtain appropriate cc options for building cryptlib.
#
# Usage: ccopts.sh [shared] [analyse|special|generic] compiler osname

CCARGS=""
OSNAME=""
ARCH=""
HOSTNAME=""
NODENAME=""
ANALYSE=0
COMPILER_VER=0
ISCLANG=0
ISCLANG_ANALYSER=0
ISDEVELOPMENT=0
ISGCC=0
ISSPECIAL=0
GENERICBUILD=0
SHARED=0
SPECIAL_SNOWFLAKE=0

# Make sure that we've been given sufficient arguments.

if [ "$1" = "shared" ] ; then
	SHARED=1 ;
	shift ;
fi
if [ "$1" = "analyse" ] ; then
	ANALYSE=1 ;
	shift ;
elif [ "$1" = "special" ] ; then
	ISSPECIAL=1 ;
	shift ;
elif [ "$1" = "generic" ] ; then
	GENERICBUILD=1 ;
	shift ;
fi
if [ $# -lt 2 ] ; then
	echo "Usage: $0 [shared] [analyse|special|generic] compiler osname" >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

CC=$1
OSNAME=$2
shift
shift

# Determine the CPU endianness by building and executing the endianness-
# detection program.  Since analysis/fuzzing builds will be using special-
# case tools that may not even be actual compilers, we hardcode in use of
# cc for this case.
#
# Note that we have to use -s for detecting its presence rather than the
# more obvious -e since this doesn't exist under the Slowaris sh.

if [ ! -s ./tools/endian ] ; then
	if [ "$OSNAME" = "NONSTOP_KERNEL" ] ; then
		c89 ./tools/endian.c -o ./tools/endian > /dev/null ;
	elif [ $ISSPECIAL -gt 0 ] ; then
		cc ./tools/endian.c -o ./tools/endian > /dev/null ;
	else
		$CC ./tools/endian.c -o ./tools/endian > /dev/null ;
	fi ;
	strip tools/endian ;
	if [ ! -s ./tools/endian ] ; then
		echo "Couldn't build endianness-checking program ./tools/endian" >&2 ;
		exit 1 ;
	fi ;
fi

if [ "$OSNAME" = "SunOS" ] ; then
	# shellcheck disable=SC2006 # Antediluvian Sun tools.
	CCARGS="`./tools/endian` `./tools/getseed.sh $OSNAME`" ;
else
	CCARGS="$(./tools/endian) $(./tools/getseed.sh $OSNAME)" ;
fi

# Try and determine the CPU type.  This is made more complex by a pile of
# *BSE's which, along with antideluvian tools like an as that doesn't
# recognise 486 opcodes, report the CPU type as i386.  Even sysctl reports
# the CPU as being i386, so if we find this we assume it's some *BSE which
# is actually running on a P4 or Athlon or something similar (unfortunately
# there's no real way to detect this, but it's 99.9% likely that it's not
# actually still running on an 80386).

if [ "$OSNAME" = "SunOS" ] ; then
	# shellcheck disable=SC2006 # Antediluvian Sun tools.
	ARCH=`uname -m` ;
else
	ARCH="$(uname -m)" ;
fi
if [ "$ARCH" = "i386" ] && [ "$(uname | grep -c BSD)" -gt 0 ] ; then
	echo "Warning: uname/sysctl reports that this machine is using an 80386 CPU (!!)," >&2 ;
	echo "         continuing under the assumption that it's at least a Pentium." >&2 ;
	echo >&2 ;
	ARCH="i586" ;
fi

# Check whether we're building on one of the development systems, which
# allows enabling various unsafe test-only options.  To avoid problems with
# false positives leading to nonstandard-configuration versions being built
# on non-development systems, we check for the existence of a sentinel file
# ~/.ISDEVELOPMENT before performing any further checks.  This probably
# makes the additional checks redundant, but it doesn't hurt to have extra
# safety margins.
#
# We also have to be a bit careful with the Gnu compile farm because it
# usually doesn't use FQDNs for the machines, so we check as much as we can
# and (for the Gnu compile farm) only allow machines on a whitelist to narrow
# down false positives.

getFQDNName()
	{
	# Check whether the hostname command is available.  It usually is, but
	# if it isn't then we fall back to the machine name via uname -n, which
	# in theory is the same as what we'd get from hostname but in practice
	# isn't really.
	if ! command -v hostname >/dev/null 2>&1 ; then
		HOSTNAME="$(uname -n)" ;
		return ;
	fi

	# Try and get the FQDN of the host.  This doesn't always work, in which
	# case we fall back to the bare host name.  Also in some cases
	# 'hostname -f' will return "localhost" while the bare 'hostname' will
	# return the (unqualified) hostname, so we check for this case as well.
	if command -v hostname -f >/dev/null 2>&1 ; then
		HOSTNAME="$(hostname -f)" ;
		if [ $HOSTNAME = "localhost" ] ; then
			HOSTNAME="$(hostname)" ;
		fi ;
	else
		HOSTNAME="$(hostname)" ;
	fi
	}

getNodeName()
	{
	# Another instance of nonstandard Unix standards, uname -n may or may
	# not return just the node name, an FQDN, or something that isn't
	# anything like the machine name.  For example cfarm22 identifies itself
	# as "erpro8-fsf1", cfarm110 as "gcc1-power7", cfarm111 as "power-aix".
	# To deal with this we have to delete everything returned by uname past
	# the first dot.
	NODENAME="$(uname -n | cut -f1 -d'.')" ;
	}

checkForDevSystem()
	{
	TIMEZONE=$1

	# Get name information
	getFQDNName
	getNodeName

	# Sun's antediluvian tools don't recognise "$(...)" so we explicitly
	# check for the two Sun development systems using backticks and early-
	# exit at this point.
	if [ "$OSNAME" = "SunOS" ] ; then
		# shellcheck disable=SC2006 # Antediluvian Sun tools.
		if [ "`uname -n`" = "gcc-solaris10" ] || [ "`uname -n`" = "gcc-solaris11" ] ; then
			ISDEVELOPMENT=1 ;
		fi ;
		return ;
	fi

	# Check for development systems by FQDN
	if [ "$(echo $HOSTNAME | grep -c "sitsshprd0[1-3]\.its\.auckland\.ac\.nz")" -gt 0 ] ; then
		ISDEVELOPMENT=1 ;
		return ;
	fi
	if [ "$(echo $HOSTNAME | grep -c "[a-z]*\.cypherpunks\.to")" -gt 0 ] ; then
		ISDEVELOPMENT=1 ;
		return ;
	fi

	# Check for development systems by whitelisted name.  The behaviour of
	# uname varies from system to system, some return just the node name,
	# some return an FQDN, and some return something that isn't anything like
	# the machine name:
	#	cfarm110 = "gcc1-power7"
	#	cfarm111 = "power-aix"
	#	cfarm112 = "gcc2-power8"
	#	cfarm210 = "gcc-solaris10"
	#	cfarm211 = "gcc-solaris11"
	#	cfarm400 = "gcc400"
	# so we have to delete everything past the first dot and explicitly
	# check for weird names.
	case $NODENAME in
		'gcc1-power7'|'power-aix'|'gcc2-power8'|'gcc-solaris10'|'gcc-solaris11'|'gcc400')
			ISDEVELOPMENT=1 ;
			return ;;
	esac ;
	if [ "$(uname -n | grep -c "cfarm[0-9][0-9]")" -gt 0 ] ; then
		case $NODENAME in
			'cfarm23'|'cfarm27'|'cfarm70'|'cfarm92')
				ISDEVELOPMENT=1 ;
				return ;;
			'cfarm104'|'cfarm110'|'cfarm111'|'cfarm112'|'cfarm119'|'cfarm185')
				ISDEVELOPMENT=1 ;
				return ;;
			'cfarm203'|'cfarm210'|'cfarm211'|'cfarm220'|'cfarm230'|'cfarm231'|'cfarm240')
				ISDEVELOPMENT=1 ;
				return ;;
			'cfarm400')
				# As of late 2024, cfarm400 is still called gcc400 so it's
				# identified via the custom $NODENAME check earlier.
				ISDEVELOPMENT=1 ;
				return ;;
		esac ;
	fi

	# Anything local is either FreeBSD or Linux and in NZ, so don't continue
	# for anything else.
	if [ $OSNAME != "FreeBSD" ] && [ $OSNAME != "Linux" ] ; then
		return ;
	fi
	if [ $TIMEZONE != "NZDT" ] && [ $TIMEZONE != "NZST" ] ; then
		return ;
	fi

	# Check for local development systems based on their network address and
	# name.  This is vulnerable to FPs but should be reasonably safe:
	# Devices in the 192.168.1.x range with gateway 192.168.1.1 with
	# specific device names.
	if [ $OSNAME = "FreeBSD" ] ; then
		if [ "$(ifconfig awg0 | grep -c "inet 192.168.1.")" -le 0 ] ; then
			return ;
		fi ;
		if [ "$(route get default | grep -c "gateway: 192.168.1.1")" -le 0 ] ; then
			return ;
		fi ;
		if [ $HOSTNAME = "pine64" ] ; then
			ISDEVELOPMENT=1 ;
		fi ;
		return ;
	fi
	if [ ! "$(ip addr show eth0 2>/dev/null)" ] ; then
		return ;
	fi
	if [ "$(ip addr show eth0 | grep -c "inet 192.168.1.")" -le 0 ] ; then
		return ;
	fi
	if [ "$(ip route show default | grep -cF "via 192.168.1.1")" -le 0 ] ; then
		return ;
	fi
	if [ $HOSTNAME = "ci20.lan" ] || [ $HOSTNAME = "odroid" ] || \
	   [ $HOSTNAME = "odroid-n2" ] || [ $HOSTNAME = "starfive" ] ; then
		ISDEVELOPMENT=1 ;
	fi
	}

if [ -f ~/.ISDEVELOPMENT ] ; then
	checkForDevSystem "$(date +%Z)" ;
fi

# Check whether we're running clang in a code-analysis mode.  Since some of
# these require a build configuration specific to a development machine, we
# only allow them to be enabled on a development system.
#
# Use of clang is a bit complicated because there's clang the compiler and
# clang the static analyser, to deal with this we detect both the compiler
# (via the "clang" string (general) or the "LLVM" string (Apple) in the
# verbose info) and the analyser (via the "ccc-analyzer" string in the
# verbose info).
#
# gcc eventually also added a Johnny-come-lately code analysis mode via
# -fanalyzer but all it produces is enormously long false positives where
# the analyser traces through 50-step code flows to eventually announce a
# null pointer dereference unrelated to the code flow it's just described
# and which isn't actually a null pointer dereference, see the code comment
# in the gcc options section for how we deal with this.
#
# In addition the STACK analyser uses an ancient version of clang on a
# static path which is accessed via a wrapper that looks like an equally
# ancient vesion of gcc, so we detect it with a check for the static path
# as part of $CC.
#
# The AFL wrapper also hides the use of clang but since we're compiling with
# afl-clang-xxx, typically afl-clang-lto, we can use the compiler wrapper
# name to detect it.  We also remember that it's a wrapper for later tests
# that require getting information from clang.
#
# To make things more entertaining, the Aches xlc displays a manpage in
# response to 'cc -v' (!!) and the manpage mentions a gcc-compatibility
# feature so the compiler is misidentified as gcc, so we have to explicitly
# check for xlc and exclude that from the gcc check.  clang also sometimes
# displays gcc-related information in its output so we have to exclude that
# too.

if [ "$($CC -v 2>&1 | grep -ci "clang")" -gt 0 ] || \
   [ "$(echo $CC | grep -ci "afl-clang")" -gt 0 ] || \
   [ "$(echo $CC | grep -ci "stack-master")" -gt 0 ] ; then
	ISCLANG=1 ;
fi
if [ "$($CC -v 2>&1 | grep -c "ccc-analyzer")" -gt 0 ] ; then
	ISCLANG_ANALYSER=1 ;
fi
if [ $ISCLANG -le 0 ] && [ $CC != "xlc" ] && [ "$($CC -v 2>&1 | grep -c "gcc")" -gt 0 ] ; then
	ISGCC=1 ;
fi
if [ $ISCLANG_ANALYSER -gt 0 ] ; then
	ANALYSE=1 ;
	if [ -z "$CCC_CC" ] ; then
		echo "$0: Environment variable CCC_CC must be set to 'clang' for the analysis build." >&2 ;
		exit 1 ;
	fi ;
	if [ $ISDEVELOPMENT -le 0 ] ; then
		echo "$0: clang analyser must be run on a system designated as a development environment by changing the ISDEVELOPMENT in this script." >&2 ;
		exit 1 ;
	fi ;
fi

# Find out which version of clang or gcc we're using.

if [ $ISCLANG -gt 0 ] || [ $ISGCC -gt 0 ] ; then
	COMPILER_VER="$(./tools/getcompiler_ver.sh $CC)" ;
fi

# Determine whether various optional system features are installed and
# enable their use if they're present.  Since these additional libs are
# dynamically loaded, we only check for them on systems with dynamic
# loading support.  We could also check for the presence of
# /usr/include/dlfcn.h, but this can lead to false positives on systems
# that have dummy a dlfcn.h for compatibility reasons.
#
# When indicating the presence of a subsystem, we set the HAS_xxx flag to
# indicate its presence rather than unconditionally setting the USE_xxx
# flag.  This allows the facility to be disabled in config.h if required.
# An exception to this is if we're building on a development system in
# which case we always enable it unconditionally.
#
# To allow these optional subsystems to be explicitly disabled, we also
# check for the presence of the DISABLE_AUTODETECT flag and skip the
# checking if this is set.

DEVCRYPTOPATHS="/usr/include/crypto/cryptodev.h /usr/local/include/crypto/cryptodev.h"
NCIPHERPATHS="/opt/nfast/toolkits/pkcs11/libcknfast.so /usr/lib/libcknfast.so"
ODBCPATHS="/usr/include/sql.h /usr/local/include/sql.h /usr/include/hpodbc/sql.h"
PKCS11PATHS="/usr/include/pkcs11.h /usr/include/security/pkcs11.h /usr/include/opensc/pkcs11.h /usr/local/include/pkcs11.h"
TPMPATHS="/usr/include/tss2/tss2_fapi.h"
TPMRNGPATHS="/usr/include/tss/tspi.h /usr/local/include/tss/tspi.h"

HASDYNLOAD=0
case $OSNAME in
	'Darwin'|'Linux'|'FreeBSD'|'OpenBSD'|'NetBSD')
		HASDYNLOAD=1 ;;

	'SunOS')
		# shellcheck disable=SC2006,SC2046 # Antediluvian Sun tools.
		if [ `./tools/osversion.sh SunOS` -gt 4 ] ; then
			HASDYNLOAD=1 ;
		fi ;;

	'HP-UX')
		if [ "$(./tools/osversion.sh HP-UX)" -gt 10 ] ; then
			HASDYNLOAD=1 ;
		fi ;;
esac
if [ -z "$DISABLE_AUTODETECT" ] && [ $HASDYNLOAD -gt 0 ] ; then
	# ODBC support
	for includepath in $ODBCPATHS ; do
		if [ -f $includepath ] ; then
			echo "ODBC interface detected, enabling ODBC support." >&2 ;
			CCARGS="$CCARGS -DHAS_ODBC" ;
			if [ "$(dirname $includepath)" != "/usr/include" ] ; then
				CCARGS="$CCARGS -I$(dirname $includepath)" ;
			fi ;
			break ;
		fi ;
	done

	# LDAP support
	if [ -f /usr/include/ldap.h ] ; then
		echo "LDAP interface detected, enabling LDAP support" >&2 ;
		CCARGS="$CCARGS -DHAS_LDAP" ;
		if [ $ISDEVELOPMENT -gt 0 ] ; then
			CCARGS="$CCARGS -DUSE_LDAP" ;
		fi ;
	fi

	# PKCS #11 support
	for includepath in $PKCS11PATHS ; do
		if [ -f $includepath ] ; then
			echo "PKCS #11 interface detected, enabling PKCS #11 support." >&2 ;
			CCARGS="$CCARGS -DHAS_PKCS11" ;
			if [ "$OSNAME" = "SunOS" ] ; then
				# shellcheck disable=SC2006 # Antediluvian Sun tools.
				if [ "`dirname $includepath`" != "/usr/include" ] ; then
					# shellcheck disable=SC2006 # Antediluvian Sun tools.
					CCARGS="$CCARGS -I`dirname $includepath`" ;
				fi ;
			else
				if [ "$(dirname $includepath)" != "/usr/include" ] ; then
					CCARGS="$CCARGS -I$(dirname $includepath)" ;
				fi ;
			fi ;
			break ;
		fi ;
	done
	for includepath in $NCIPHERPATHS ; do
		if [ -f $includepath ] ; then
			echo "  (Enabling use of additional nCipher PKCS #11 extensions)." >&2 ;
			CCARGS="$CCARGS -DNCIPHER_PKCS11" ;
			break ;
		fi ;
	done

	# TPM support.  The use of the doubled-up dirname is required because
	# the TPM header is in a subdirectory tss2/tss2_fapi.h so we have to
	# remove first the tss2_fapi.h and then the tss2 from the path.
	for includepath in $TPMPATHS ; do
		if [ -f $includepath ] ; then
			echo "TPM interface detected, enabling TPM support." >&2 ;
			CCARGS="$CCARGS -DHAS_TPM" ;
			if [ "$(dirname $includepath)" != "/usr/include/tss2" ] ; then
				CCARGS="$CCARGS -I$(dirname $(dirname $includepath))" ;
			fi ;
			break ;
		fi ;
	done

	# TPM RNG support.  The use of the doubled-up dirname is required because
	# the TPM header is in a subdirectory tss/tspi.h so we have to remove
	# first the tspi.h and then the tss from the path.
	for includepath in $TPMRNGPATHS ; do
		if [ -f $includepath ] ; then
			echo "TPM RNG interface detected, enabling TPM RNG support." >&2 ;
			CCARGS="$CCARGS -DHAS_TPM_RNG" ;
			if [ "$(dirname $includepath)" != "/usr/include/tss" ] ; then
				CCARGS="$CCARGS -I$(dirname $(dirname $includepath))" ;
			fi ;
			break ;
		fi ;
	done

	# /dev/crypto support.  The use of the doubled-up dirname is required
	# because the /dev/crypto header is in a subdirectory crypto/cryptodev.h
	# so we have to remove first the cryptodev.h and then the crypto from
	# the path.
	#
	# This is actually a pain to do because although both Linux and the
	# *BSDs can have a /dev/crypto they have almost
	# nothing in common except the name.  For now we only enable the
	# interface under Linux, see the comment in misc/os_spec.c for the
	# details.
	for includepath in $DEVCRYPTOPATHS ; do
		if [ -f $includepath ] ; then
			echo "/dev/crypto API support detected, enabling crypto hardware support." >&2 ;
			if [ "$OSNAME" = "Linux" ] || [ "$OSNAME" = "FreeBSD" ] ; then
				CCARGS="$CCARGS -DHAS_DEVCRYPTO" ;
			fi ;
			if [ "$(dirname $includepath)" != "/usr/include/crypto" ] ; then
				CCARGS="$CCARGS -I$(dirname $(dirname $includepath))" ;
			fi ;
			break ;
		fi ;
	done
fi
#if [ -f /usr/include/zlib.h ] ; then
#	echo "  (Enabling use of system zlib)." >&2 ;
#	CCARGS="$CCARGS -DHAS_ZLIB" ;
#fi

# If we're building a development or analysis build, enable various unsafe
# options that are normally disabled by default.  Enabling USE_ANALYSER
# enables everything possible via misc/config.h, the development version
# only enables a few additional algorithms and options.

if [ $ANALYSE -gt 0 ] ; then
	echo "  (Enabling all source code options for analysis build)." >&2 ;
	CCARGS="$CCARGS -DUSE_ANALYSER" ;
elif [ $ISSPECIAL -gt 0 ] ; then
	echo "  (Enabling all source code options for instrumented build)." >&2 ;
	echo "  (Disabling compile warnings for instrumented build)." >&2 ;
	CCARGS="$CCARGS -DUSE_ANALYSER" ;
elif [ $ISDEVELOPMENT -gt 0 ] ; then
	echo "  (Enabling additional source code options for development version)." >&2 ;
	CCARGS="$CCARGS -DUSE_CERT_DNSTRING -DUSE_DNSSRV" ;
fi

# Some distros - and it's always Linux distros - want to set their own
# special-snowflake build options based on the fact that since the entire
# world uses their particular distro and nothing else exists, everyone has
# to do things their way.  Since cryptlib both has to run under anything
# under the sun including some quite odd environments and also goes to
# considerable lengths to take advantage of specific hardware capabilities
# and features, what this special-snowflake requirement does is disable a
# bunch of performance, security, and functionality features.  To deal with
# this, we detect the special-snowflake distros here and provide the option
# of bailing out without setting any options other than the basic CPU
# architecture, endianness, and so on.

if [ -f /etc/fedora-release ] ; then
	# shellcheck disable=SC2034 # Currently unused.
	SPECIAL_SNOWFLAKE=1 ;
fi

# Enable additional options for clang.  Primarily this means enabling stack
# protection and extra checking for buffer overflows and similar.  Note that
# fsanitize=safe-stack has problems of its own and is handled separately
# further down.  -fsanitize=cfi is even more problematic, requiring LTO which
# in turn requires a specific linker and plugins and that everything be set
# up exactly right for things to work, so it'll have to be handled explicitly
# by the user.
#
# If this is a non-development build (which includes special builds, which
# enable all options as for standard development builds) then we need to
# disable the two on-by-default false-positive warnings because we exit
# before we get to the mass handling of clang warnings further down.
#
# In addition to the warnings, we disable clang's emulation of gcc
# braindamage around two's-complement maths and null pointer checks, see the
# comment for gcc further down.  In the clang case -fwrapv is the same as
# -fno-strict-overflow unlike gcc where the two have different levels of
# braindamage so we can take care of things with that.

hasStackClashProtection()
	{
	TMPFILE=$(mktemp)
	RETURN_STATUS=255

	# Check whether clang supports -fstack-clash-protection.  In theory
	# any version past 7.0 should support it, however support for some
	# architectures isn't available yet so even if the compiler recognises
	# the flag that doesn't mean it actually supports it, producing
	# warnings about 'argument unused during compilation' for each file.
	echo "int main(void) {return 0;}" >> $TMPFILE.c
	if [ "$(clang $TMPFILE.c -o $TMPFILE -fstack-clash-protection 2>&1 | grep -c "argument unused")" -gt 0 ] ; then
		RETURN_STATUS=0 ;
	fi
	rm $TMPFILE.c
	if [ -f $TMPFILE ] ; then
		# May already have been deleted by the linker
		rm $TMPFILE ;
	fi

	return $RETURN_STATUS ;
	}

if [ $ISCLANG -gt 0 ] ; then
	if [ "$COMPILER_VER" -ge 70 ] ; then
		CCARGS="$CCARGS -fstack-protector-strong -D_FORTIFY_SOURCE=2" ;
		if hasStackClashProtection ; then
			CCARGS="$CCARGS -fstack-clash-protection" ;
		fi
	elif [ "$COMPILER_VER" -ge 50 ] ; then
		CCARGS="$CCARGS -fstack-protector-strong -D_FORTIFY_SOURCE=2" ;
	elif [ "$COMPILER_VER" -ge 43 ] ; then
		# Various web pages claim that this was added in 3.7 but it's not
		# present in 4.2 and the manual only documents command-line options
		# starting at 5.0, so we guess 4.3 for support.
		CCARGS="$CCARGS -fstack-protector -D_FORTIFY_SOURCE=2" ;
	elif [ "$COMPILER_VER" -ge 37 ] ; then
		CCARGS="$CCARGS -D_FORTIFY_SOURCE=2" ;
	fi
	if [ $ISDEVELOPMENT -le 0 ] || [ $ISSPECIAL -gt 0 ] ; then
		CCARGS="$CCARGS -Wno-pointer-sign -Wno-switch" ;
	fi
	CCARGS="$CCARGS -fwrapv" ;
	if [ $COMPILER_VER -ge 45 ] ; then
		CCARGS="$CCARGS -fno-delete-null-pointer-checks" ;
	fi
fi

# If we're using a newer version of clang, turn on stack buffer overflow
# protection unless it's a special-case build.  Given cryptlib's built-in
# protection mechanisms this shouldn't be necessary, but it can't hurt to
# enable it anyway.
#
# Note that this is a weird flag in that it was supposedly added to clang
# in 3.9 but not really supported until about 4.3, and then in clang
# something, maybe 4.7 or so, was also added as a link flag.  To deal with
# this we only enable it for clang >= 4.7, and also enable it in
# tools/getlibs.sh if it's been enabled here (that is, getlibs checks for
# it being enabled here and if so enables it too).
#
# An additional problem is that alongside the tool support it also requires
# libclang_rt support which typically isn't installed on anything other than
# development systems, so alongside the compiler check we also check for the
# presence of the necessary runtime library.

checkSafeStack()
	{
	TMPFILE="$(mktemp)"
	CLANG_RESULT=""
	RESULT=0

	# Check whether the required libraries for safe-stack use are present.
	# This is necessary because even if the compiler support is there it
	# requires additional libclang_rt libraries that typically aren't
	# installed.  Since these can be stashed almost anywhere even when they
	# are present, we use a dummy link to try and detect their presence.
	echo "int main(void) {return 0;}" >> $TMPFILE.c
	CLANG_RESULT="$(clang $TMPFILE.c -o $TMPFILE -fsanitize=safe-stack 2>&1)"
	if [ "$(echo $CLANG_RESULT | grep -c "unsupported option" )" -gt 0 ] ; then
		# Some architectures don't support -fsanitize=safe-stack, for example
		# the versions of clang shipped with OS X or OpenBSD even as late as
		# clang 12.
		RESULT=0 ;
	elif [ "$(echo $CLANG_RESULT | grep -c "No such file")" -gt 0 ] ; then
		# -fsanitize=safe-stack but no libraries.
		RESULT=1 ;
	else
		# -fsanitize=safe-stack and libraries present.
		RESULT=2 ;
	fi
	rm $TMPFILE.c
	if [ -f $TMPFILE ] ; then
		# May already have been deleted by the linker
		rm $TMPFILE ;
	fi

	return $RESULT ;
	}

if [ $ISCLANG -gt 0 ] && [ $ISSPECIAL -eq 0 ] ; then
	if [ $COMPILER_VER -ge 47 ] ; then
		SAFESTACK_SUPPORT=checkSafeStack ;
		case $SAFESTACK_SUPPORT in
			0)	;;
			1)	echo "  " >&2 ;
				echo "  (This system supports clang stack sanitization via -fsanitize=safe-stack" >&2 ;
				echo "   in $0, however the necessary libclang_rt isn't installed." >&2 ;
				echo "   If you can install the required library then consider enabling" >&2 ;
				echo "   -fsanitize=safe-stack in $0)." >&2 ;
				echo "  " >&2 ;;
			2)	CCARGS="$CCARGS -fsanitize=safe-stack" ;;
		esac ;
	fi ;
fi

# If we're using clang or gcc and RELRO support is present, enable it.  This
# is a bit of an odd one, the various descriptions and docs imply it really
# only works on Linux x86-64 (at least in part because of it being tied to
# the ELF format), but it seems to work even on lesser-supported platforms
# like 32-bit ARM, so we try and detect it and enable it if present.  Check
# for its presence in the compiled binary with
# 'readelf -l ./testlib | grep RELRO'.
#
# As an additional factor, for versions of gcc starting at 14 we enable
# -fhardened which auto-enables RELRO if available, but there again
# -fhardened is only supported on x86-64 Linux.
#
# The reason why the section below is commented out is because these are
# linker flags and we're compiling with -c, so the linker is never invoked.
# Instead, we enable the flags in tools/buildsharedlib.sh, the code below is
# left in place in case some future versions require compile options as
# well.
#
#if [ $ISCLANG -gt 0 ] && [ $COMPILER_VER -ge 70 ] ; then
#	if [ "$(clang -Wl,-help | grep -c "relro")" -gt 0 ] ; then
#		CCARGS="$CCARGS -Wl,-z,relro,-z,now" ;
#	fi ;
#fi
#if [ $ISGCC -gt 0 ] && [ $COMPILER_VER -ge 90 ] ; then
#	if [ "$(gcc -Wl,-help | grep -c "relro")" -gt 0 ] ; then
#		CCARGS="$CCARGS -Wl,-z,relro,-z,now" ;
#	fi ;
#fi

# The Sun compiler has its own set of problems, the biggest of which is
# determining where it is and what it is (see comments elsewhere), but
# another one is that some of the warning options changed across compiler
# versions or possibly target types (there's no obvious pattern), so we have
# to detect use of this compiler and then feed it the options to see which
# one is accepted.  In addition we can't use "$(...)" because of the usual
# Sun antediluvian tools problem.

# shellcheck disable=SC2006,SC2046 # Antediluvian Sun tools.
if [ "$OSNAME" = "SunOS" ] && [ `$CC 2>&1 | grep -c "cc -flags"` -gt 0 ] ; then
	CCARGS="$CCARGS -errtags=yes" ;
	touch suncctest.c ;
	# shellcheck disable=SC2006,SC2046 # Antediluvian Sun tools.
	if [ `$CC -erroff=E_ARG_INCOMPATIBLE_WITH_ARG suncctest.c 2>&1 | grep -c "bad message"` -gt 0 ] ; then
		CCARGS="$CCARGS -erroff=E_ARG_INCOMPATIBLE_WITH_ARG_L" ;
	else
		CCARGS="$CCARGS -erroff=E_ARG_INCOMPATIBLE_WITH_ARG" ;
	fi ;
	rm suncctest.c ;
fi

# If we're building a shared lib, set up the necessary additional cc args.
# The IRIX cc and Cygwin/MinGW gcc (and for Cygwin specifically Cygwin-
# native, not a cross-development toolchain hosted under Cygwin) don't
# recognise -fPIC, but generate PIC by default anyway.  The PHUX compiler
# requires +z for PIC, and Solaris cc requires -KPIC for PIC.  OS X
# generates PIC by default, but doesn't mind having -fPIC specified anyway.
# In addition it requires -fno-common for DYLIB use.
#
# For the PIC options, the only difference between -fpic and -fPIC is that
# the latter generates large-displacement jumps while the former doesn't,
# bailing out with an error if a large-displacement jump would be required.
# As a side-effect, -fPIC code is slightly less efficient because of the use
# of large-displacement jumps, so if you're tuning the code for size/speed
# you can try -fpic to see if you get any improvement.

if [ $SHARED -gt 0 ] ; then
	case $OSNAME in
		'Darwin')
			CCARGS="$CCARGS -fPIC -fno-common -mmacosx-version-min=%%MIN_MAC_OSX_VERSION%%" ;;

		'CYGWIN_NT-5.0'|'CYGWIN_NT-5.1'|'CYGWIN_NT-6.1')
			;;

		'HP-UX')
			CCARGS="$CCARGS +z" ;;

		'IRIX'|'IRIX64')
			;;

		'MINGW_NT-5.0'|'MINGW_NT-5.1'|'MINGW_NT-6.1')
			;;

		'SunOS')
			# shellcheck disable=SC2006,SC2046 # Antediluvian Sun tools.
			if [ `$CC -v 2>&1 | grep -c "gcc"` = 0 ] ; then
				CCARGS="$CCARGS -KPIC" ;
			else
				CCARGS="$CCARGS -fPIC" ;
			fi ;;

		*)
			CCARGS="$CCARGS -fPIC" ;;
	esac ;
fi

# Conversely, if we're building a static lib and the system requires it, set
# up static lib-specific options.

if [ $SHARED -eq 0 ] ; then
	case $OSNAME in
		'BeOS')
			CCARGS="$CCARGS -D_STATIC_LINKING" ;;
	esac ;
fi

# Enable ASLR.  We only do this for static libs, for shared libs it's
# already been handled via -fPIC above.
#
# Note that we don't add '-Wl,-pie' at this point since we're compiling with
# -c so linker flags will be ignored.  However even then the static lib is
# assembled with ar without any linker involvement, so only the final binary
# that it's linked with can specify -pie.

if [ $SHARED -eq 0 ] ; then
	if [ $ISCLANG -gt 0 ] && [ "$COMPILER_VER" -ge 30 ] ; then
		CCARGS="$CCARGS -fpie" ;
		echo "Enabling ASLR support, consider linking the final binary with -pie." >&2 ;
	fi ;
	if [ $ISGCC -gt 0 ] && [ "$COMPILER_VER" -ge 42 ] ; then
		CCARGS="$CCARGS -fpie" ;
		echo "Enabling ASLR support, consider linking the final binary with -pie." >&2 ;
	fi ;
fi

# If the system supports recursive and/or robust mutexes, indicate that
# they're available.  We don't use recursive mutexes by default because they
# tend to be somewhat hit-and-miss but we at least indicate their presence
# via a define.

if [ -f /usr/include/pthread.h ] ; then
	if [ "$(grep -c PTHREAD_MUTEX_RECURSIVE /usr/include/pthread.h)" -gt 0 ] ; then
		CCARGS="$CCARGS -DHAS_RECURSIVE_MUTEX" ;
	fi ;
	if [ "$(grep -c PTHREAD_MUTEX_ROBUST /usr/include/pthread.h)" -gt 0 ] ; then
		CCARGS="$CCARGS -DHAS_ROBUST_MUTEX" ;
	fi ;
fi

# If this is a special build e.g. for fuzzing, don't enable the mass of
# compiler warnings that we'd get from a normal development build

if [ $ISCLANG -gt 0 ] && [ $ISSPECIAL -gt 0 ] ; then
	echo "$CCARGS" ;
	exit 0 ;
fi

# If we're building with clang on a development system or with the clang
# static analyser, set options specific to that.  It's unclear which options
# are enabled by -Wall and -Wextra so we first enable both sets and then
# disable the false-positive-inducing ones, and finally explicitly enable
# warnings where it's not documented whether they're set by -Wall/-Wextra
# or not.  The -Wall/-Wextra false-positives that we need to disable are:
#
#	-Wno-misleading-indentation: Misleading indentation in if/else/for/while.
#		This is based on 'goto fail' but since it's guessing-based it leads
#		to too many false positives from 'if( cond ) expr1; expr2;' where
#		expr2 produces a warning about 'statement is not part of the
#		previous if'.
#
#	-Wno-missing-field-initializers: Missing initialisers in structs.  This
#		also warns about things like the fairly common 'struct foo = { 0 }',
#		which makes it too noisy for detecting problems.
#
#	-Wno-sign-compare: Compare int to unsigned int and similar.
#
#	-Wno-pointer-sign: Signed vs. unsigned values in pointers.
#
#	-Wno-switch:
#	-Wno-switch-enum: Unused enum values in a switch statement.  Since all
#		cryptlib attributes are declared from a single pool of enums but
#		only the values for a particular object class are used in the
#		object-specific code, this leads to huge numbers of warnings about
#		unhandled enum values in case statements.
#
# The additional diagnostics that we explicitly enable, see
# https://clang.llvm.org/docs/DiagnosticsReference.html, because it's not
# certain whether they're set by -Wall/-Wextra, are:
#
#	-Warray-bounds-pointer-arithmetic: Pointer increment/decrenent moves
#		past array bounds.
#
#	-Wbad-function-cast: Cast from function of type A to type B.
#
#	-Wbitwise-conditional-parentheses: Precedence issues with |, &, and ?.
#
#	-Wbitwise-op-parentheses: (Something about nesting?).
#
#	-Wbool-operation: Mixing of bitwise and logical ops, || vs |.  This was
#		introduced in clang 10 and marked as enabled by default in clang
#		10-13 but is no longer marked as such in clang 14-15 so we enable it
#		explicitly.
#
#	-Wchar-subscripts: Array subscript is of type 'char'.
#
#	-Wcomma: Potential misuse of comma operator.
#
#	-Wconditional-uninitialized: Condition leaves variable uninitialised.
#
#	-Wdeclaration-after-statement: Declaration follows code, for older
#		compilers.
#
#	-Wduplicate-enum: (Something about assigning enums to things?).
#
#	-Wempty-init-stmt: Empty initialization statement of if/switch has no
#		effect.
#
#	-Wextra-semi: Spurious semicolon.
#
#	-Wformat-type-confusion: Format specifier is type X but argument is
#		type Y.
#
#	-Widiomatic-parentheses: Using the result of an assignment as a
#		condition without parentheses.
#
#	-Winfinite-recursion: All paths through this function call itself.
#
#	-Wkeyword-macro: Keyword hidden by macro definition.
#
#	-Wlogical-op-parentheses: Ambiguous '&&' / '||' use.
#
#	-Wmisleading-indentation: Misleading indentition for if/else/etc.
#
#	-Wmissing-braces: Ambiguous initialisation of nested objects due to
#		missing braces.
#
#	-Wmissing-prototypes: No prototype for function.
#
#	-Wnull-pointer-subtraction: Subtraction involving a null pointer,
#		enabled by default with -Wextra.
#
#	-Wrange-loop-analysis: (Something about loop variables), enabled by
#		-Wall as of 10.0.
#
#	-Wself-assign: Assigning variable to itself.
#
#	-Wself-move: Moving variable to itself.
#
#	-Wshift-sign-overflow: Shift sets the sign bit.
#
#	-Wsizeof-array-div
#	-Wsizeof-pointer-div: Incorrect use of sizeof( array ) / sizeof( type )
#
#	-Wsometimes-uninitialized: Variable uninitialised on condition X.
#
#	-Wtautological-compare: Tautological comparisons, also enables
#		-Wtautological-bitwise-compare, -Wtautological-constant-compare,
#		-Wtautological-overlap-compare, -Wtautological-pointer-compare and
#		-Wtautological-undefined-compare.
#
#	-Wthread-safety: Various non-thread-safe behaviours.
#
#	-Wundef: Macro not defined.
#
#	-Wunreachable-code-loop-increment: Loop will only be executed once.
#
#	-Wunused-but-set-parameter
#	-Wunused-but-set-variable: Parameter or a variable is set but not used.
#
#	-Wunused-const-variable, -Wunused-variable: Unused variable.
#
#	-Wunused-label: Unused label.
#
#	-Wunused-local-typedef: Unused typedef.
#
#	-Wused-but-marked-unused: Marked as unused but actually used.  This
#		leads to false positives when a parameter is unused but is also
#		checked in a REQUIRES() to ensure that it's set to NULL or zero,
#		or where UNUSED_ARG() is used for compilers that can't deal with
#		STDC_UNUSED, however it's sufficiently useful in catching incorrect
#		use of STDC_UNUSED that it's left enabled despite the noise.
#
#	-Wzero-as-null-pointer-constant: Zero used in place of NULL.
#
# The following look useful but have too many problems with false
# positives:
#
# 	-Wdate-time: Expansion of date/time macro is not reproducible.  This runs
#		into problems with the use of CURRENT_TIME_VALUE, which extracts
#		the current time from __TIME__.  Technically this is a problem
#		because we could have slightly different CURRENT_TIME_VALUEs if we
#		rebuild a single module at a later date, but it's only done to a
#		one-month resolution and in any case just sets the floor limit for
#		what's considered a valid date.
#
#	-Wdisabled-macro-expansion: Expansion of recursive macro, this produces
#		false positives with system headers that rely on the compiler
#		stopping expension of recursive macros.
#
#	-Wextra-semi-stmt: Warns about semicolons on function-like macros.
#
#	-Wshorten-64-to-32: Warn about long -> int conversion, this has the
#		potential to catch issues but at the moment leads to all false
#		positives around things like the sizeofXXX() functions or stell(),
#		as well as anything involving size_t (e.g. strlen()), which return a
#		long in general but are often used in cases where the range is an
#		int (or more generally a short).
#
#	-Wunused-macros: Macro defined but not used.  This typically occurs
#		when macros are used to define constants (e.g. cipher block sizes),
#		not all of which are used in the code.

if [ $ISCLANG_ANALYSER -gt 0 ] || \
   ( [ $ISCLANG -gt 0 ] && [ $ISDEVELOPMENT -gt 0 ] ) ; then
	echo "  (Enabling additional clang compiler options for development version)." >&2 ;
	CCARGS="$CCARGS -Wall -Wextra" ;
	CCARGS="$CCARGS -Wno-missing-field-initializers -Wno-pointer-sign \
					-Wno-sign-compare -Wno-switch" ;
	CCARGS="$CCARGS -Warray-bounds-pointer-arithmetic -Wbad-function-cast \
					-Wbitwise-op-parentheses -Wchar-subscripts \
					-Wconditional-uninitialized -Wdeclaration-after-statement \
					-Wduplicate-enum -Wextra-semi -Widiomatic-parentheses \
					-Wlogical-op-parentheses -Wmissing-braces \
					-Wmissing-prototypes -Wself-assign -Wshift-sign-overflow \
					-Wsometimes-uninitialized -Wthread-safety -Wundef \
					-Wunused-const-variable -Wunused-variable -Wunused-label \
					-Wused-but-marked-unused" ;
	if [ $COMPILER_VER -ge 43 ] ; then
		CCARGS="$CCARGS -Winfinite-recursion \
						-Wunreachable-code-loop-increment" ;
	fi
	if [ $COMPILER_VER -ge 45 ] ; then
		CCARGS="$CCARGS -Wcomma -Wformat-type-confusion -Wempty-init-stmt \
						-Wkeyword-macro -Wno-misleading-indentation \
						-Wrange-loop-analysis -Wself-move -Wunused-local-typedef \
						-Wzero-as-null-pointer-constant" ;
	fi
	if [ $COMPILER_VER -ge 60 ] ; then
		CCARGS="$CCARGS -Wtautological-compare" ;
	fi
	if [ $COMPILER_VER -ge 80 ] ; then
		# Versions beyond this, released 2019, are new enough that we draw
		# special attention to their presence.
		echo "  (Enabling additional compiler options for clang 8.x)." >&2 ;
#		CCARGS="$CCARGS -Wextra-semi-stmt" ;	-- See comment about FPs
	fi
	if [ $COMPILER_VER -ge 100 ] ; then
		echo "  (Enabling additional compiler options for clang 10.x)." >&2 ;
		CCARGS="$CCARGS -Wbitwise-conditional-parentheses \
						-Wmisleading-indentation -Wsizeof-array-div \
						-Wsizeof-pointer-div" ;
	fi
	if [ $COMPILER_VER -ge 130 ] ; then
		echo "  (Enabling additional compiler options for clang 13.x)." >&2 ;
		CCARGS="$CCARGS -Wunused-but-set-parameter -Wunused-but-set-variable" ;
	fi
	if [ $COMPILER_VER -ge 140 ] ; then
		echo "  (Enabling additional compiler options for clang 14.x)." >&2 ;
		CCARGS="$CCARGS -Wbool-operation" ;
	fi
fi

# If we're not using gcc, we're done.  This isn't as simple as a straight
# name comparison of cc vs. gcc, sometimes gcc is installed as cc so we
# have to check whether the compiler is really gcc even if it's referred to
# as cc.  In addition we have to be careful about which strings we check for
# because i18n of the gcc -v output makes many strings highly mutable.  The
# safest value to check for is "gcc", hopefully this won't yield any false
# positives (apart from Aches, see below).
#
# To make things more entertaining, the Aches xlc displays a manpage in
# response to 'cc -v' (!!) and the manpage mentions a gcc-compatibility
# feature so the compiler is misidentified as gcc.  In addition because
# of clang's compatibility-with-gcc system clang can be misidentified as
# gcc (or at least clang can appear as both clang and gcc, depending on
# whether the check is for clang or gcc).
#
# To work around this we perform a special-case false-positive check for
# Aches and clang and only then check for gcc.
#
# For xlc, the options are:
#
#	langlvl=extended0x: Enables the static_assert keyword, this is present
#			but disabled by default (!!) unless enabled on the compile line.
#
#	maxmem: Give the optimizer more headroom, it's not really needed but
#			avoids millions of informational messages telling you to
#			increase it from the default 2048.
#
#	nolist: Turns off generation of listing files, this is supposed to be
#			off by default but xlc isn't aware of this.  Note though that
#			even when qnolist is specified, some versions still generate
#			.lst files for each source file, containing a two-line entry
#			that's identical across each file.
#
#	roconst: Puts const data into read-only memory (this may happen anyway
#			 on some versions of the compiler).

if [ "$OSNAME" = "AIX" ] ; then
	if [ $CC = "xlc" ] ; then
		echo "$CCARGS -qlanglvl=extended0x -qmaxmem=-1 -qnolist -qroconst" ;
		exit 0 ;
	fi ;
	if [ "$(which cc 2>&1 | grep -c "gcc")" = 0 ] ; then
		echo "$CCARGS" ;
		exit 0 ;
	fi ;
fi
if [ $ISCLANG -gt 0 ] ; then
	echo "$CCARGS" ;
	exit 0 ;
fi
if [ $ISGCC -eq 0 ] ; then
	echo "$CCARGS" ;
	exit 0 ;
fi

# gcc changed its CPU architecture-specific tuning option from -mcpu to
# -march in about 2003, so when using gcc to build for x86 systems (where
# we specify the architecture as P5 rather than the default 386) we have
# to use an intermediate build rule that changes the compiler arguments
# based on compiler version info.  The reason for the change was to
# distinguish -march (choice of instruction set used) from -mtune
# (scheduling of instructions), so for example -march=pentium
# -mtune=pentium4 would generate instructions from the pentium instruction
# set but scheduled for the P4 CPU.  Usually -march=X also imples -mtune=X,
# but newer versions of gcc allow an mtune=generic to tune for the most
# widely-used current CPUs.  In particular, specifying -march=<oldest CPU
# type to support> requires -mtune=generic otherwise it'll also -mtune for
# the oldest CPU type rather than any current one.  To see what the current
# setting is, use:
#
#	gcc -Q --help=target
#
# For x86-64 it's -march=x86-64 -mtune=generic, the default config for gcc
# on x86, which means that pretty much every instruction-set extension
# beyond basic x64 is disabled.  Even a slightly more optimistic -march=core2
# makes no difference, with the results identical to -march=x86-64.
#
# (The changeover is in fact somewhat messier than that, newer 2.9.x versions
# (as well as 3.x onwards) recognised -march (depending on the CPU they
# targeted and patch level) and all versions still recognise -mcpu, however
# as of about 3.4.x the compiler complains about deprecated options whenever
# it sees -mcpu used, which is why we use -march for 3.x and newer).
#
# As of version 4.2.0, gcc finally supports an option "optimise for the
# machine I'm building on", eliminating the need to perform complex
# guesswork for the CPU type, so if we're using any recent version we use
# this by default.  If not, we fall back to guessing, but since it's not
# really possible to determine the exact CPU type the only options that we
# have (aside from the broken *BSE's reporting of "80386" mentioned above)
# are "586" (generic pre-MMX(!!) Pentium), "686" (generic Pentium Pro), and
# "x86-64" (generic x86-64).  The lowest common denominator is the generic
# "pentium", which just means "something better than the default 80386",
# 'x86-64' means the > 20-year-old version of the architecture and 'core2'
# is identical to 'x86-64', see the comment earlier.  gcc on x86-64 defaults
# to -march=x86-64 anyway so specifying this is the same as omitting -march
# entirely.
#
# Unfortunately handling of "-march=native" is pretty comprehensively broken
# for the gcc 4.2 versions because of the hit-and-miss way that the
# information is passed by the compiler driver to the compiler back-end.
# Sometimes it works, sometimes it produces a "bad value (native) for
# -march= switch; bad value (native) for -mtune= switch" error, and
# sometimes it just bails out and falls back to "-march=generic" which
# often produces very poor code.  As a result it's not safe to enable the
# use of this option for anything before about gcc 4.5.
#
# However using -march=native mode puts gcc into y'all-watch-this mode where
# it uses every single possible obscure instruction in the current system's
# ISA, including (for example) a single use of an instruction throughout the
# entire codebase that ensures it crashes with an illegal instruction error
# on anything that isn't the exact same CPU.  Apart from obvious problems
# like building a binary on system A and trying to run it on system B, it
# leads to very nonobvious failures like building with tools like distcc,
# which builds for the native architecture of whatever remote system a
# particular module happens to be compiled on, and which may change across
# different build runs.
#
# Using -march=x86-64-vX seems to be the only way out of this mess, although
# it's a bit confusing because it depends on the compiler version, for
# example gcc 4.5 generates identical code for -64-v2, -64-v3, and -64-v4 so
# presumably it allows -64-v > 2 for future compatibility and 4.5 didn't
# know about -64-v3 or -64-v4 yet.  -64-v2 is the minimum required to enable
# 2008-vintage AES instructions but -64-v3 works for CPUs back to about 2012
# so we use that instead of -64-v2.  Note that we can't just use -maes because
# AES also requires a range of SSEx instructions (see crypt/aes_ni.c) which
# means we'd need to specify a whole string of specific options on the command
# line.  crypt/aes_ni.c gets around this by using GCC pragmas to enable the
# specific options needed before including x86intrin.h, but for that to work
# the command-line has to specify an overall architecture level high enough
# to support all of the pragmas used there, which is what -64-v2 and above do.
#
# However this then runs into another problem where -march=x86-64-vX isn't
# recognised until gcc 11, the only possible option being to specify a very
# specific architecture which produces the same results that we'd get from
# -march=native.  As a result we have to use the pretty bad -march=x86-64
# for most gcc versions, which doesn't even get us native AES support.

if [ "$ARCH" = "i586" ] || [ "$ARCH" = "i686" ] || [ "$ARCH" = "x86_64" ] ; then
	if [ "$COMPILER_VER" -ge 110 ] ; then
		if [ $GENERICBUILD -gt 0 ] ; then
			echo "  (Enabling lowest-common-denominator build options for cross-platform library)." >&2 ;
		else
			CCARGS="$CCARGS -march=x86-64-v3" ;
		fi
	elif [ "$COMPILER_VER" -ge 45 ] ; then
		if [ $GENERICBUILD -gt 0 ] ; then
			echo "  (Enabling lowest-common-denominator build options for cross-platform library)." >&2 ;
		else
			CCARGS="$CCARGS -march=x86-64" ;
		fi
	elif [ "$COMPILER_VER" -ge 30 ] ; then
		case $ARCH in
			'x86_64')
				CCARGS="$CCARGS -march=opteron -fPIC" ;;

			'i686')
				CCARGS="$CCARGS -march=pentiumpro" ;;

			*)
				CCARGS="$CCARGS -march=pentium" ;;
		esac ;
	else
		CCARGS="$CCARGS -mcpu=pentium" ;
	fi ;
fi

# gcc 4.x for 64-bit architectures has an optimiser bug that removes an
# empty-list check in cryptlib's list-management code (this has been
# verified for at least 4.0.x and 4.1.x for x86-64 and ppc64).  When running
# the self-test, this is first detectable in cert/dn.c in the function
# deleteComponent(), where the missing check for an empty list causes a
# segfault when the code tries to access a nonexistent list element.
# There's not much that we can do about this except warn the user.
#
# (Update: Rearranging some lines in the source causes the compiler to emit
#  correct code, so hopefully this shouldn't be necessary any longer).
#
# In theory we should also use '-s' for read to turn off echoing of
# keystrokes, however not all shells (e.g. Debian's stupid dash, which is
# symlinked to /bin/sh in some distros) support this.
#
#if [ "$COMPILER_VER" -ge 40 -a '(' "$ARCH" = "x86_64" -o "$ARCH" = "ppc64" ')' ] ; then
#	echo >&2 ;
#	echo "Warning: The version of gcc that this system uses has an optimiser bug in" >&2 ;
#	echo "         its 64-bit code generation.  If the cryptlib self-test segfaults" >&2 ;
#	echo "         during the certificate self-test, rebuild the code with -O2" >&2 ;
#	echo "         instead of the current -O3." >&2 ;
#	read -n1 -p "Hit a key..." ;
#	echo >&2 ;
#fi

# gcc 4.x changed the way that it performs optimisation so that -O3 often
# results in the creation of far larger binaries than -O2, with ensuing poor
# cache localisation properties.  In addition it enhances the triggering of
# gcc optimiser bugs, something that seems to be particularly bad in 4.x.
# While cryptlib contains numerous code-generation bug workarounds for gcc 4.x
# (and 3.x, and 2.x), the potential performance problems with -O3 means that
# it's better to just turn it off.
#
# (Update: Having optimisation set via this script rather than in the
#  makefile purely for gcc is awkward because if we're building under the
#  same OS but using clang then the optimisation level is never set.  Since
#  newer versions of gcc might be less buggy than the awful 4.x series we
#  go back to specifying the optimisation level in the makefile).
#
#if [ "$OSNAME" = "Linux" ] || [ "$OSNAME" = "FreeBSD" ] || \
#   [ "$OSNAME" = "NetBSD" ] || [ "$OSNAME" = "OpenBSD" ] || \
#   [ "$OSNAME" = "Darwin" ] ; then
#	if [ "$COMPILER_VER" -ge 40 ] ; then
#		CCARGS="$CCARGS -O2" ;
#	else
#		CCARGS="$CCARGS -O3" ;
#	fi ;
#fi

# Check for gcc 4.x with its stupid default setting of -Wpointer-sign,
# which leads to endless warnings about signed vs.unsigned char problems -
# you can't even call strlen() without getting warnings.
#
# Older versions of Solaris' sh can't handle the test below as a single line
# so we have to break it apart into two lines.  In addition without the
# backquotes the script will silently exit at this point (!!) so we quote the
# argument to 'test'.
#
# Unfortunately enabling C99 with gcc (see below) also enables the C99
# aliasing rules, or at least endless whiny warnings about potential
# problems with C99 aliasing rules, reported as type punning by gcc 4.x.
# Because of the way the cryptlib kernel works there's no way to work around
# this (well, except for horrible kludges with unions) because it uses a
# generic message-payload type that's always passed as a void *.  There's no
# easy way to fix this, we could in theory perform a massive janitorial run-
# through applying intermediate void casts between source and target (e.g.
# '( struct foo * ) ( void * ) whatever') but this just masks the problem,
# makes the code look ugly, and could quite well hide other problems because
# of the make-it-go-away void cast.  Telling the compiler to shut up is far
# cleaner, since it doesn't seem to have any effect on the code generated
# anyway.

if [ "$COMPILER_VER" -ge 40 ] ; then
	if [ "$($CC -Wno-pointer-sign -S -o /dev/null -xc /dev/null 2>&1 | grep -c "unrecog")" -eq 0 ] ; then
		CCARGS="$CCARGS -Wno-pointer-sign" ;
	fi ;
	CCARGS="$CCARGS -Wno-strict-aliasing" ;
fi

# The gcc developers are of the opinion that once the compiler encounters
# anything that can be classed as undefined behaviour (UB, e.g. an integer
# addition) then the compiler is allowed to do anything it wants.  While
# they very generously refrain from reformatting your hard drive, what they
# do do is remove code that does things like check for integer overflow or
# null pointers that may exist beyond the point where the UB can occur.
# Compilers like MSVC assume that they're running on a two's-complement
# machine and act accordingly, while gcc knows that it's also running on a
# two's-complement machine but nevertheless can't exlude the theoretical
# possibility that it's running on a one's-complement CDC 6600 from 1965 and
# therefore can't assume two's-complement behaviour.
#
# gcc then allows you to extend the braindamage by specifying -ftrapv, which
# generates a trap if overflow is encountered.  This means that gcc's
# default behaviour is to be braindamaged, and if -ftrapv is specified, to
# be braindamaged and then cause your app to crash.
#
# To get around this, we specify -fwrapv (yes, you really can assume that
# you're on a two's-complement machine, which has been the case for
# everything from the last half-century or so) and -fno-delete-null-pointer-
# checks (behaviour that's so totally stupid that it's incredible that you
# actually need to specify an option to fix it).
#
# There are actually two variants of the overflow-braindamage-limiting
# mechanism, -fwrapv and -fno-strict-overflow, which do more or less the
# same thing but in subtly different ways that no-one is quite clear on.
# One explanation is that -fwrapv tells the compiler that integer overflow
# wraps while -fno-strict-overflow tells the compiler that integer overflow
# can happen, but not what happens (in other words it tells it not to remove
# code based on this).  Since we know that we're running on a two's-
# complement machine even if the gcc developers don't, we use -fwrapv to
# reflect this.
#
# Specifying -fwrapv possibly disables diagnostics from -Wstrict-overflow
# (see the comment further down for the warnings) so we only enable it for
# non-development builds.

if [ "$COMPILER_VER" -ge 40 ] && [ "$ISDEVELOPMENT" -le 0 ] ; then
	CCARGS="$CCARGS -fwrapv -fno-delete-null-pointer-checks" ;
fi

# The AES code uses 64-bit data types, which older vesions of gcc don't
# support (at least via limits.h) unless they're operating in C99 mode.  So
# in order to have the AES auto-config work we have to explicitly run gcc
# in C99 (or newer) mode, which isn't the default for the gcc 3.x and some
# 4.6 versions.  Since the code also uses gcc extensions we have to specify
# the mode as gcc + C99, not just C99.

if [ "$COMPILER_VER" -ge 30 ] && [ "$COMPILER_VER" -le 46 ] ; then
	CCARGS="$CCARGS -std=gnu99" ;
fi

# Use of static_assert() requires that gnu11 mode be enabled, this isn't
# recognised by gcc 4.6, is recognised but not the default for gcc 4.7-4.9
# (the alleged default is gnu90 but it actually seems to be gnu99), and is
# the default for gcc 5.0 and above */

if [ "$COMPILER_VER" -ge 47 ] && [ "$COMPILER_VER" -le 49 ] ; then
	CCARGS="$CCARGS -std=gnu11" ;
fi

# Enable stack protection and extra checking for buffer overflows if it's
# available.  This was introduced (in a slightly hit-and-miss fashion) in
# later versions of gcc 4.1.x, to be on the safe side we only enable it
# for gcc 4.2 and newer.  gcc 4.9 introduced a slightly more comprehensive
# version so we use that if it's available.  Some people like to add
# '--param=ssp-buffer-size=4' (the default size is 8), but this isn't
# necessary for cryptlib since it doesn't allocate any 4-byte buffers.
#
# gcc 12 added a FORTIFY_SOURCE=3 but this changes compile-time checks into
# runtime ones whose performance overhead has had little evaluation beyond
# "there is some", and since cryptlib bounds-checks each memcpy()/memmove()/
# whatever with better knowledge than the compiler's guesswork we leave it
# out for now.
#
# gcc 14 added an umbrella -fhardened that enables all of the options that
# we enable item by item based on compiler versions and detection, but this
# is currently only supported under Linux.

if [ "$COMPILER_VER" -ge 140 ] && [ $OSNAME = "Linux" ] ; then
	CCARGS="$CCARGS -fhardened" ;
elif [ "$COMPILER_VER" -ge 90 ] ; then
	CCARGS="$CCARGS -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2" ;
elif [ "$COMPILER_VER" -ge 49 ] ; then
	CCARGS="$CCARGS -fstack-protector-strong -D_FORTIFY_SOURCE=2" ;
elif [ "$COMPILER_VER" -ge 42 ] ; then
	if [ "$($CC -fstack-protector -S -o /dev/null -xc /dev/null 2>&1 | grep -c "unrecog")" -eq 0 ] ; then
		CCARGS="$CCARGS -fstack-protector" ;
	fi ;
	CCARGS="$CCARGS -D_FORTIFY_SOURCE=2" ;
fi

# Newer versions of gcc support marking the stack as nonexecutable (e.g.
# using the x86-64 NX bit), so if it's available we enable it.  This is
# easier than the alternative of adding a:
#
# #if defined( __linux__ ) && defined( __ELF__ )
#   .section .note.GNU-stack, "", %progbits
# #endif
#
# to .S files since (a) we don't control most of the .S files and (b)
# some of the code is inline asm in C functions.
#
# Unfortunately this isn't possible to check for easily, at best we can
# do something like:
#
# if (echo|as --noexecstack -o /dev/null > /dev/null 2>&1); then
#	CCARGS="$CCARGS -Wa,--noexecstack" ;
# fi
#
# (which is necessary because no two assemblers have a consistent command-
# line interface so that we can't even reliably get version information as
# we can for gcc) but even this is problematic because even if the assembler
# claims to support it actual handling is still rather hit-and-miss.

# Enable additional compiler diagnostics if we're building on specific
# development boxes.  We only enable it on these specific systems to avoid
# having users complain about getting warnings when they build it.
#
# The gcc warnings are:
#
# -Waddress: Suspicious use of memory addresses, e.g. 'x == "abc"'
#		(-Wall).
#
# -Waggregate-return: Function returns structs.  This isn't used any more
#		as of 3.4.4 due to the use of safe pointers, which are scalar
#		values.
#
# -Walloc-zero: Call to malloc( 0 ).
#
# -Walloc-size-larger-than=value: Call to malloc() exceeds 'value',
#		potentially caused by arithmetic overflow (-Wall =
#		-Walloc-size-larger-than=PTRDIFF_MAX).
#
# -Walloca: Use of alloc().
#
# -Warray-bounds: Out-of-bounds array accesses, requires the use of
#		-ftree-vrp (which is enabled for -O2 and above) (-Wall).
#
# -Wcast-align: Pointer is cast such that the required alignment of the
#		target is increased, for example if a "char *" is cast to an
#		"int *".
#
# -Wchar-subscripts: Array has a char subscript (-Wall).
#
# -Wdangling-else: Dangling else.
#
# -Wdeclaration-after-statement: Variable declaration found after a
#		statement in a function (for older compilers).
#
# -Wduplicate-decl-specifier: Duplicate 'const', 'volatile' etc in a
#		declaration (-Wall).
#
# -Wduplicated-branches: if/else has identical branches (no idea how this
#		differs from -Wduplicated-cond).
#
# -Wduplicated-cond: Duplicate conditions in an if/else chain.
#
# -Wendif-labels: endif is followed by text.
#
# -Wempty-body: Empty body occurs in an if/else or do/while.
#
# -Wextra: Extra warnings on top of -Wall
#
# -Wformat: Check calls to "printf" etc to make sure that the args supplied
#		have types appropriate to the format string (-Wall).
#
# -Wformat-nonliteral: Check whether a format string is not a string literal,
#		i.e. argPtr vs "%s".
#
# -Wformat-overflow: Check for problems with overflows in arguments to
#		sprintf().
#
# -Wformat-security: Check for potential security problems in format strings.
#
# -Wformat-truncation: Chek for problems with truncation in arguments to
#		sprintf() (-Wall).
#
# -Wimplicit-int: Typeless variable declaration (-Wall).
#
# -Wimplicit-fallthrough=5: Falling through a case statement in a switch
#		without it being annotated as a fallthrough via an attribute (-Wextra,
#		but default is level 3, not level 5).
#
# -Winit-self: Value is initialised to itself, e.g. 'int i=i'.
#
# -Wjump-misses-init: goto or switch misses initialisation of a variable.
#
# -Wlogical-op: Suspicious use of logical operators in expressions, e.g.
#		'|' vs '||'.
#
# -Wlogical-not-parentheses: "logical not" used on the left hand side
#		operand of a comparison.
#
# -Wmemset-elt-size: Size argument for memset() of array doesn't include
#		sizeof() the elements (-Wall).
#
# -Wmemset-transposed-args: memset( ..., n, 0 ) where memset( ..., 0, n )
#		was probably meant (-Wall).
#
# -Wmisleading-indentation: goto fail (-Wall).
#
# -Wmissing-braces: Array initialiser isn't fully bracketed, e.g.
#		int a[2][2] = { 0, 1, 2, 3 } (-Wall).
#
# -Wmissing-parameter-type: Function has a K&R-style declaration,
#		int foo() { ... } (-Wextra).
#
# -Wmultistatement-macros: Macro expands to multiple statements, causing
#		problems if not enclosed in braces (-Wall).
#
# -Wnonnull: Passing a null for function args tagged as being __nonnull
#		(-Wall).
#
# -Wnonnull-compare: Checking an argument marked __nonnull for NULL
#		(-Wall).
#
# -Wnull-dereference: Guess at potential derefencing of null pointers, only
#		enabled if -fdelete-null-pointer-checks is active, which it is if
#		optimisation is enabled (note however that we disable this in order
#		to limit the braindamage that it causes, see the comment earlier).
#		This option appears to be a grudging admission of the braindamage of
#		existing nonnull behaviour.
#
# -Wparentheses: Missing parantheses so that the resulting expression is
#		ambiguous (or at least nonobvious) (-Wall).
#
# -Wpointer-arith: Expression depends on the sizeof a function type or of
#		void.
#
# -Wredundant-decls: Variable declared more than once in the same scope.
#
# -Wreturn-type: Incorrect return type for function, e.g. return( 1 ) for
#		void function (-Wall).
#
# -Wsequence-point: Sequence point violation, e.g. a = a++ (-Wall).
#
# -Wshadow: Local variable shadows another local variable, parameter or
#		global variable (that is, a local of the same name as an existing
#		variable is declared in a nested scope).  Note that this leads to
#		some false positives as gcc treats forward declarations of functions
#		within earlier functions that have the same parameters as the
#		function they're declared within as shadowing.  This can be usually
#		detected in the output by noting that a pile of supposedly shadow
#		declarations occur within a few lines of one another.
#
# -Wshift-count-negative: Problems with shift counts (default).
# -Wshift-count-overflow:
#
# -Wshift-negative-value: Left-shifting a negative value.
#
# -Wshift-overflow: Shift overflows.
#
# -Wsizeof-array-argument: sizeof operator is applied to a parameter that
#		has been declared as an array in a function definition.
#
# -Wsizeof-pointer-div: Sizeof maths, e.g. sizeof( ptr ) / sizeof(ptr[ 0 ])
#		when ptr isn't an array (-Wall).
#
# -Wsizeof-pointer-memaccess: Suspicious use of sizeof with some string and
#		memory functions, e.g. memcpy( &foo, ptr, sizeof( &foo ) ) (-Wall)
#
# -Wstrict-overflow: Potential integer overflow, this has an integer argument
#		ranging from 1 to 5, 1 is the default for -Wall.  When specified this
#		must follow -Wall since this will reset it to 1 if it's set to a
#		higher level.  This check is probably negated by the options to limit
#		gcc's braindamaged handling of (potential) overflow, see the comments
#		earlier on for more on this, however this is only applied to non-
#		development builds so we should still get the warnings.
#
#		However, this warning is handled in the traditional gcc braindamage
#		way where what's implemented is easy for the gcc developers to do
#		rather than useful for the user.  In particular any warning level
#		above 2 produces vast numbers of pointless warnings, mostly due to
#		optimiser-internal code rearrangement, and even level 2 produces
#		nothing but pointless warnings (for things not warned at in level 1),
#		for example that reducing "!( 0-expression )" to "1" assumes that
#		there's no overflow present.  This makes it completely useless for
#		detecting anything at all, so we set the level to 1 which is what
#		-Wall would be giving us anyway.
#
# -Wstrict-prototypes: Function is declared or defined K&R-style.
#
# -Wstringop-overflow: String/mem function may overflow the destination
#		buffer (-W..=2, default).
#
# -Wstringop-truncation: String ops may truncate the operation, e.g.
#		'strncat( buf, ".txt", 3 );' will only copy 3 of the 4 string chars
#		(-Wall).
#
# -Wswitch-bool: Switch statement has an index of boolean type.
#
# -Wswitch-unreachable: Switch statement has unreachable code, e.g. code
#		before the first "case:" (default).
#
# -Wtautological-compare: Self-comparison, e.g. if( i == i ) (-Wall).
#
# -Wtrampolines: Trampolines are being generated, which requires an
#		executable stack.  This is only done for nested functions:
#
#		foo( int x )
#			{
#			bar( int y )
#				{ };
#			}
#
#		which are a gcc-ism and not used anywhere, but we enable it anyway
#		just in case.
#
# -Wtype-limits: Comparison is always true due to the limited range of a
#		data type, e.g. unsigned >= 0.
#
# -Wundef: Undefined identifier is used in #if.
#
# -Wunused-const-variable: Unused const variables.
#
# -Wunused-function: Static function isn't used (-Wall).
#
# -Wunused-label: Label isn't used (-Wall).
#
# -Wunused-variable: Local variable isn't used (-Wall).
#
# -Wunused-but-set-variable: Variable is assigned to but not used (-Wall).
#
# -Wunused-local-typedefs: Unused typedef (-Wall).
#
# -Wunused-value: Statement produces a result that isn't used, e.g. 'x[i]'
#		as a standalone statement (-Wall).
#
# -Wundef: Undefined identifier is used in a #if.
#
# -Wunsafe-loop-optimizations: Compiler can't reason about loop bounds.
#
# -Wvla: Variable-length array used.
#
# -Wwrite-strings: Attempt to assign/use a constant string value with a
#		non-const pointer.
#
# -Wxor-used-as-pow: Using e.g. 2 ^ 16 in an expression (-Wall).
#
# -Wzero-as-null-pointer-constant: Explicit 0 or '\0' is used instead of
#		NULL.  Unfortunately this is currently valid (gcc 4.7) only for C++
#		so we can't use it.
#
# Note that some of these require the use of at least -O2 in order to be
# detected because they require the use of various levels of data flow
# analysis by the compiler.
#
# Finally, there are warnings that, as implemented by gcc, are more or less
# useless due to excessive false positives, for example warning on nearly
# every single stdlib function call.  See for example "Twice the Bits, Twice
# the Trouble", Wressnegger et al, CCS'16, for more on this, which found
# 45,000 false positives covering up the few actual issues.  Because they're
# essentially useless due to the level of noise, we disable them (if they're
# enabled through -Wall) or don't use them if they're optional.  VC++
# provides a usable level of warnings about these issues so we rely on that:
#
# -Wconversion: Potentially problematic conversion, e.g. 'unsigned foo = -1'.
#		This also warns for things like conversion from int to long unsigned
#		int/size_t, leading to avalanches of pointless warnings.  For
#		example pretty much every stdlib function that takes a length
#		parameter anywhere produces a warning when a generic int variable is
#		converted to a size_t.
#
# -Wno-ignored-qualifiers: Use of const with by-value return, for example
#		in 'const DATAPTR dataptrAttributeMoveCursor( ... )'.  This was
#		required starting with 3.4.4's use of safe pointers, see also the
#		comment for -Waggregate-return.
#
# -Wno-missing-field-initializers: Missing initialisers in structs.  This
#		also warns about things like the fairly common 'struct foo = { 0 }',
#		which makes it too noisy for detecting problems (-Wextra).
#
# -Wno-nonnull-compare: An extension of the nonnull braindamage in which,
#		alongside removing NULL checks, they're all warned about as well.
#
# -Wno-sign-compare: Compare between signed and unsigned values.  This leads
#		to endless warnings about comparing a signed to an unsigned value,
#		particularly problematic when comparing an integer to a
#		CRYPT_xxx_yyy enum because enums are treated as unsigned so every
#		comparison leads to a warning (-Wall, -Wextra).
#
# -Wno-switch: Unused enum values in a switch statement.  Since all cryptlib
#		attributes are declared from a single pool of enums but only the
#		values for a particular object class are used in the object-specific
#		code, this leads to huge numbers of warnings about unhandled enum
#		values in case statements (-Wall).
#
# -Wuninitialized: Used-before-initialised.  The detection of this isn't
#		very good, variables initialised conditionally always produce
#		warnings.
#
# -Wunreachable-code: The use of -O2/-O3 interacts badly with this due to
#		statements rearranged by the optimiser being declared unreachable.
#		Because of this the capability was removed in January 2010
#		(http://gcc.gnu.org/ml/gcc-patches/2009-11/msg00179.html), so while
#		the compiler still accepts the option it silently ignores it (par
#		for the course for gcc).
#
# Finally there's also -Wextra, which warns about even more potential
# problems, at the cost of more false positives.
#
# In addition to the standard warnings we also enable the use of gcc
# attributes warn_unused_result and nonnull, which are too broken (and in
# the case of nonnull far too dangerous) to use in production code (see the
# long comment in misc/analyse.h for details), and to catch the compiler
# brokenness we undefine NDEBUG to enable the use of assertion checks that
# will catch the problem.
#
# Starting at gcc 10, gcc added a basic static-analysis capability via
# -fanalyzer, however this is just a huge mass of false positives (in five
# years' use it's never produced a true positive) and nothing like clang's
# static analyser.  Since it's pure noise we only enable it on the latest
# version of gcc on any system we use, and only for one particular system
# to avoid drowning in avalanches of false-positive warnings.
#
# Alongside the warnings, we also enable various sanitisers if they're
# available.  We can't use -fsanitize=thread because it's incompatible
# with -fsanitize=address, not because of the compiler but because they
# require different memory layouts in the runtime libraries.  In addition
# the sanitizers require specific library support and since the clang/
# fuzzing build incorporates them anyway it's easier not to bother:
#
#	if [ "$COMPILER_VER" -ge 48 ] ; then
#		CCARGS="$CCARGS -fsanitize=address -lasan" ;
#	fi ;
#	if [ "$COMPILER_VER" -ge 49 ] ; then
#		CCARGS="$CCARGS -fsanitize=undefined -lubsan" ;
#	fi ;
#
# We also enable -finstrument-functions and -fexceptions if possible in
# order to be able to print stack trace information when debugging.  We
# can't enable it on x86-64 where SSE intrinsics are used for AES support
# because then gcc in its infinite buggyness decides to instrument SSE
# intrinsics, which aren't functions, and compilation fails with a string of
# undefined-reference errors.

if [ $ANALYSE -gt 0 ] ; then
	CCARGS="$CCARGS -DUSE_GCC_ATTRIBUTES" ;
	if [ "$COMPILER_VER" -ge 100 ] ; then
		CCARGS="$CCARGS -fanalyzer" ;
	else
		echo "gcc version is too old to support code analysis." >&2 ;
	fi ;
elif [ $ISDEVELOPMENT -gt 0 ] ; then
	echo "  (Enabling unsafe gcc compiler options for development version)." >&2 ;
	CCARGS="$CCARGS -Wall -Wcast-align -Wdeclaration-after-statement \
					-Wempty-body -Wextra -Wformat-nonliteral \
					-Wformat-security -Winit-self -Wlogical-op \
					-Wparentheses -Wpointer-arith -Wredundant-decls \
					-Wshadow -Wstrict-overflow=1 -Wstrict-prototypes \
					-Wtype-limits -Wundef -Wvla" ;
	CCARGS="$CCARGS -Wno-ignored-qualifiers -Wno-missing-field-initializers \
					-Wno-switch -Wno-sign-compare" ;
	CCARGS="$CCARGS -DUSE_GCC_ATTRIBUTES -UNDEBUG" ;
	if [ "$COMPILER_VER" -ge 45 ] ; then
		CCARGS="$CCARGS -Wlogical-op -Wjump-misses-init" ;
	fi ;
	if [ "$COMPILER_VER" -ge 47 ] ; then
		CCARGS="$CCARGS -Wtrampolines -Wunused-local-typedefs" ;
	fi ;
	if [ "$COMPILER_VER" -ge 50 ] ; then
		CCARGS="$CCARGS -Wlogical-not-parentheses -Wsizeof-array-argument \
						-Wswitch-bool -Wmissing-parameter-type" ;
	fi ;
	if [ "$COMPILER_VER" -ge 60 ] ; then
		CCARGS="$CCARGS -Wshift-negative-value -Wshift-overflow \
						-Wnull-dereference -Wduplicated-cond \
						-Wno-nonnull-compare -Wundef" ;
	fi ;
	if [ "$COMPILER_VER" -ge 70 ] ; then
		# Versions beyond this, released 2017, are new enough that we draw
		# special attention to their presence.
		echo "  (Enabling additional compiler options for gcc 7.x)." >&2 ;
		CCARGS="$CCARGS -Walloca -Wduplicated-branches -Wmemset-elt-size \
						-Wduplicate-decl-specifier -Wdangling-else \
						-Walloc-size-larger-than=1000000 -Walloc-zero \
						-Wformat-overflow -Wformat-truncation \
						-Wimplicit-fallthrough=5 -Wunused-const-variable=1 \
						-Wunsafe-loop-optimizations" ;
	fi ;
	if [ "$COMPILER_VER" -ge 80 ] ; then
		echo "  (Enabling additional compiler options for gcc 8.x)." >&2 ;
		CCARGS="$CCARGS -Wmultistatement-macros" ;
	fi ;
	if [ "$COMPILER_VER" -ge 130 ] ; then
		# See the note above on why we enable the analyser only on the latest
		# version of gcc that we recognise rather than for gcc 10 where it
		# first appeared.
		echo "  (Enabling additional compiler options for gcc 13.x)." >&2 ;
		CCARGS="$CCARGS -fanalyzer" ;
	fi ;
	if [ "$ARCH" != "x86_64" ] ; then
		CCARGS="$CCARGS -finstrument-functions -fexceptions" ;
	fi ;
fi

# Finally, report what we've found

echo "$CCARGS"
