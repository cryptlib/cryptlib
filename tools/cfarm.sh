#!/bin/sh
# Deploy and run the cryptlib test suite on selected cfarm hosts.
# Arguments:
#
#	-h host = Use non-cfarm host name.
#	-r restart-point-host = Restart the run from $restart-point-host,
#							used when a run stops due to an error.
#	-u user = Use non-default user name.
#
# Without args it'll run on the cfarm hosts, with -h and -u it can be
# run on other systems for testing.
#
# The SSH_ARGS are required to deal with the fact that some build farm
# servers are running very old versions of SSH that don't do SHA2
# signatures, and to deal with SSH server keys changing.

HOSTS="23 27 70 92 93 104 110 111 112 185 203 210 211 215 216 220 230 231 240 400"
HOSTPREFIX="cfarm"
HOSTSUFFIX="cfarm.net"
USER="peter"
SSH_PRIVKEYPATH="$HOME/.ssh/cpunx.pri"
SSH_ARGS="-o PubkeyAcceptedAlgorithms=+ssh-rsa -o KexAlgorithms=+diffie-hellman-group-exchange-sha1 -o HostKeyAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no"
SSH_PORTARG_SCP=
SSH_PORTARG_SSH=
DATA="beta.zip"
DEFAULT_NCORES="-j4"
NCORES=$DEFAULT_NCORES
DO_RESTART=0
RESTART_POINT=""
CFARM_HOST=1

# Process any optional flags.

while getopts "h:r:u:" options ; do
	case "${options}" in
		h) HOSTS=${OPTARG} ;
		   CFARM_HOST=0 ;;
		r) DO_RESTART=1 ;
		   RESTART_POINT=${OPTARG} ;;
		u) USER=${OPTARG} ;;
		*) echo "Invalid option -${OPTARG}" >&2 ;
		   exit 1 ;;
	esac
done
shift $(( OPTIND - 1 ))

# Upload and build the code on each host.  We use a here document for this
# rather than pulling it in from another file with 'ssh [...] < commands.sh'
# to keep everything in one place.  The script is fairly conservative in
# order to minimise interference with other users, for example it limits
# itself to -j4 rather than `getconf _NPROCESSORS_ONLN` and hogging all the
# cores.

for host in $HOSTS ; do
	# Check for whether we're restarting at a given point.
	if [ $DO_RESTART -gt 0 ] ; then
		if [ "$RESTART_POINT" != "$host" ] ; then
			continue ;
		fi ;
		DO_RESTART=0 ;
		echo "Restarting from cfarm$host" ;
	fi

	# Build the full hostname for cfarm hosts.
	if [ $CFARM_HOST -eq 1 ] ; then
		HOSTNAME=$HOSTPREFIX$host.$HOSTSUFFIX ;
	else
		HOSTNAME=$host ;
	fi

	# A few hosts only allow for -j2 rather than the default -j4.  In theory
	# we could do a per-host lookup for number of cores vs. host but that's
	# tricky to do in sh/bash/whatever and not really worth the hassle.
	#
	# Similarly, a few hosts need nonstandard port configs.
	case $host in
		'23'|'70')
			NCORES="-j2" ;;

		'211')
			# Solaris tools don't support -j.
			NCORES= ;;

		'400')
			SSH_PORTARG_SCP="-P 25465" ;
			SSH_PORTARG_SSH="-p 25465" ;;
	esac

	# Print information on the host that we're about to build on.
	case $host in
		'23') echo "cfarm23: MIPS64 big-endian Linux gcc." ;;
		'27') echo "cfarm27: Intel x86 little-endian Linux clang." ;;
		'70') echo "cfarm70: Xeon x86-64 little-endian Linux clang." ;;
		'92') echo "cfarm92: RiscV64 (SiFive) little-endian Linux clang." ;;
		'93') echo "cfarm93: RiscV64 (VisionFive) little-endian Linux clang." ;;
		'104') echo "cfarm104: Apple M1 little-endian OS X clang.  Hangs on SSH connect test." ;;
		'110') echo "cfarm110: PPC64 big-endian Linux clang." ;;
		'111') echo "cfarm111: PPC64 big-endian AIX xlc.  Hangs on SSH connect test." ;;
		'112') echo "cfarm112: PPC64 little-endian Linux gcc.  Broken clang install." ;;
		'185') echo "cfarm185: Arm64 little-endian Linux clang.  Hangs on SSH connect test." ;;
		'203') echo "cfarm203: PPC64 big-endian Linux clang." ;;
		'210') echo "cfarm210: Sparc64 big-endian Solaris 10 SunPro.  OpenCSW." ;;
		'211') echo "cfarm211: Sparc64 big-endian Solaris 11 SunPro.  OpenCSW." ;;
		'215') echo "cfarm215: Intel x86-64 little-endian Solaris 11." ;;
		'216') echo "cfarm216: Sparc64 big-endian Solaris 11." ;;
		'220') echo "cfarm220: Xeon x86-64 little-endian OpenBSD clang." ;;
		'230') echo "cfarm230: MIPS64 big-endian Linux clang." ;;
		'231') echo "cfarm231: MIPS64 big-endian OpenBSD clang" ;;
		'240') echo "cfarm240: ARM Morello CheriBSD/FreeBSD, 64-bit word, 128-bit pointers." ;;
		'400') echo "cfarm400: Loongson64 little-endian Linux clang." ;;
	esac

	# Copy the code across and build it.  Note that $PORTARG has to be
	# unquoted otherwise ssh will see a blank string arg and think it's a
	# file argument, and $SSH_ARGS and $NCORES similarly for distinct
	# strings.  In addition EOL has to be unquoted because we need $NCORES
	# to be expanded on the client side, not the server side.
	#
	# The Sun hosts are OpenCSW machines which are actually Solaris zones on
	# a single server so need paths to tools explicitly set depending on the
	# zone.
	echo "Deploying to $HOSTNAME"
	scp -B $SSH_ARGS -i "$SSH_PRIVKEYPATH" $SSH_PORTARG_SCP $DATA $USER@$HOSTNAME: || exit
	ssh $SSH_ARGS -i "$SSH_PRIVKEYPATH" $SSH_PORTARG_SSH $USER@$HOSTNAME <<EOL
		set -e ;
		if [ -d ./CLIB ] ; then
			if [ -n \$(ls ./CLIB) ] ; then
				rm -r ./CLIB/* ;
			fi ;
		else
			mkdir ./CLIB ;
		fi ;
		cd ./CLIB ;
		unzip -a ../beta.zip ;
		rm ../beta.zip ;
		touch ../.ISDEVELOPMENT ;
		if [ \$(uname -n | cut -f1 -d'.') = "gcc-solaris10" ] ; then
			PATH=/opt/solarisstudio12.3/bin::/usr/ccs/bin:\$PATH ; export PATH ;
		fi ;
		if [ \$(uname -n | cut -f1 -d'.') = "gcc-solaris11" ] ; then
			PATH=/opt/developerstudio12.6/bin::/usr/ccs/bin:\$PATH ; export PATH ;
		fi ;
		make touch ;
		make $NCORES ;
		make testlib ;
		./testlib ;
EOL

	# Exit if there was a problem.
	status=$?
	if [ $status -ne 0 ] ; 	then
		printf "\n**** Error building on %s: %d ****\n" "$HOSTNAME" "$status" >&2 ;
		case $host in
			'23')
				echo "(If the problem was an internal error in clang, restart with '-r 70')" >&2 ;;

			'104'|'111'|'185')
				# This doesn't actually get displayed because we have to ^C to
				# get out.
				echo "(If the problem was a hang on the SSH test, restart with '-r 111/112/203')" >&2 ;;

			'112')
				echo "(If the problem was due to a broken clang install, restart with '-r 185')" >&2 ;;
		esac ;
		exit 1 ;
	fi

	# Reset any variables to their defaults
	NCORES=$DEFAULT_NCORES
done
