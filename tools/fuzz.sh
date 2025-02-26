#!/bin/bash
# Fuzz cryptlib (via the spcially-built testlib).

INPUT_DIR_PARENT="afl-in"
OUTPUT_DIR_PARENT="afl-out"
PROGNAME_SRC="./testlib"
PROGNAME="./fuzz-clib"
FUZZER="../AFL/afl-fuzz"
FUZZTYPES="base64 certificate certchain certreq cms pgp pkcs12 pkcs15 \
		   tls-client tls-server ssh-client ssh-server ocsp-client ocsp-server tsp-client tsp-server \
		   cmp-client cmp-server rtcs-client rtcs-server scvp-client scvp-server \
		   pgppub pgpsec bignum url http-req http-resp websockets eap"
FUZZTYPE=""
DIRNAME=""
INPUT_DIR=""
OUTPUT_DIR=""
NO_CPUS=$(getconf _NPROCESSORS_ONLN)
DEBUG=0
VERBOSE=0

# Without ASAN the fuzzing uses -m 200 to give 200MB of memory which for
# some reason is needed by AFL, with ASAN it needs to be -m none to set no
# limit

MEMORY_LIMIT=none

# Process any optional flags before the args.

while getopts "dv" options ; do
	case "${options}" in
		d) DEBUG=1 ;;

		v) VERBOSE=1 ;;
	esac
done
shift $(( OPTIND - 1 ))

# Make sure that we've been given sufficient arguments.  We have to hardcode
# in the program name because none of the usual methods like $0 or
# $(basename $0) seem to work here.

show_help()
	{
	cat << "EOF" >&2
Usage: fuzz [-cd] options.  Valid options are
    -d                      - Output debug information.
    -v                      - Verbose stats.

    clean                   - Clean up working files.
    resume <type>           - Resume from previous run.
    stats                   - Show fuzzing stats.
    package                 - Package results in ~/afl.zip.

    base64                  - Fuzz base64 decoding.
    certificate/certchain   - Fuzz certificate/cert.chain.
    certreq                 - Fuzz cert.request.
    cms/pgp                 - Fuzz CMS/PGP message.
    pkcs12/pkcs15           - Fuzz PKCS #12/#15 keyset.
    pgppub/pgpsec           - Fuzz PGP pub/priv.keyset.
    tls-client/tls-server   - Fuzz TLS client/server.
    ssh-client/ssh-server   - Fuzz SSH client/server.
    cmp-client/cmp-server   - Fuzz CMP client/server.
    tsp-client/tsp-server   - Fuzz TSP client/server.
    ocsp-client/ocsp-server - Fuzz OCSP client/server.
    rtcs-client/rtcs-server - Fuzz RTCS client/server.
    scvp-client/scvp-server - Fuzz SCVP client/server.
    (SCEP is fuzzed via CMS envelopes).
    bignum                  - Fuzz bignum ops.
    url                     - Fuzz URL parsing.
    http-req/http-resp      - Fuzz HTTP request/response.
    websockets              - Fuzz WebSockets.
    eap                     - Fuzz EAP.
EOF
	}

if [ $OPTIND -eq 1 ] && [ -z "$1" ] ; then
	show_help ;
	exit 1
fi

# Get the protocol being fuzzed and the paths derived from it.

FUZZTYPE=$1
DIRNAME=${FUZZTYPE}
INPUT_DIR=${INPUT_DIR_PARENT}/${DIRNAME}
OUTPUT_DIR=${OUTPUT_DIR_PARENT}/${DIRNAME}

# Make sure that we don't try and fuzz non-fuzzable protocols.

if [ "$1" = "scep-client" ] || [ "$1" = "scep-server" ] ; then
	echo "$0: SCEP uses CMS messages which are fuzzed via envelopes." >&2 ;
	exit 1
fi

# Display debugging info if required.

debug_display()
	{
	if [ $DEBUG -eq 0 ] ; then
		return 0 ;
	fi
	echo "$1" ;
	}

# If we're doing a cleanup, delete input and output files and exit.

if [ "$1" = "clean" ] ; then
	echo "Cleaning up..."
	shift
	if [ -z "$1" ] ; then
		echo "$0: Missing option to clean up." >&2
		exit 1
	fi
	debug_display "Cleaning ${INPUT_DIR_PARENT}/$1 and /${OUTPUT_DIR_PARENT}/$1" ;
	rm -r "./${INPUT_DIR_PARENT}/$1"
	rm -r "./${OUTPUT_DIR_PARENT}/$1"
	exit 0
fi

# If we're showing stats, extract the information from the appropriate
# fuzzer_stats file and exit.  For crashes and hangs we use the substrings
# rather than the full form since these have changed over time.
#
# There's also a field last_find which returns the last time at which
# something was found, but it's given as a seconds timestamp which isn't
# useful.

show_stats_verbose()
	{
	NAME=$1
	DIR=$2

	echo "Stats for $NAME..."
	grep cycles_done "${DIR}/fuzzer_stats" ;
	grep cycles_wo_finds "${DIR}/fuzzer_stats" ;
	grep execs_done "${DIR}/fuzzer_stats"
	grep execs_per_sec "${DIR}/fuzzer_stats"
	grep crashes "${DIR}/fuzzer_stats"
	grep hangs "${DIR}/fuzzer_stats"
	echo
	}

show_stats()
	{
	DIR=./${OUTPUT_DIR_PARENT}/$1/default

	if [ ! -d "${DIR}" ] ; then
		return 0 ;
	fi
	if [ $VERBOSE -eq 1 ] ; then
		show_stats_verbose $1 $DIR ;
		return ;
	fi

	EXECS=$(grep execs_done "${DIR}/fuzzer_stats" | tr -cd 0-9)
	CYCLES=$(grep cycles_done "${DIR}/fuzzer_stats" | tr -cd 0-9)
	CYCLES_WO=$(grep cycles_wo_finds "${DIR}/fuzzer_stats" | tr -cd 0-9)
	CRASHES=$(grep crashes "${DIR}/fuzzer_stats" | tr -cd 0-9)

	printf "%-12s %'11d execs, %3d cycle" $1 $EXECS $CYCLES
	if [ $CYCLES -ne 1 ] ; then
		printf "s"
	fi
	if [ $CRASHES -gt 0 ] ; then
		printf ", %d crash" $CRASHES ;
		if [ $CRASHES -gt 1 ] ; then
			printf "es"
		fi ;
	fi
	if [ $CYCLES_WO -gt 0 ] ; then
		if [ $CYCLES_WO -eq 1 ] ; then
			printf ", 1 cycle without finds" ;
		else
			printf ", %d cycles without finds" $CYCLES_WO ;
		fi ;
	fi
	printf "\n"
	}

if [ "$1" = "stats" ] ; then
	for FUZZTYPE in ${FUZZTYPES} ; do
		show_stats "${FUZZTYPE}"
	done
	exit 0
fi

# If we're packaging up results, bundle everything up and exit.  There's
# no way to test whether there are files in a shell script apart from
# ugly hacks involving spawning subshells or using find or ls so we have
# to create our own function for it.

isempty()
	{
	for file in "$1"/*; do
		if [ -e "$file" ] ; then
			return 1 ;
		fi
	done

	return 0
	}

package()
	{
	DIR="./${OUTPUT_DIR_PARENT}/$1/default"

	if [ ! -d "${DIR}" ] ; then
		return 0 ;
	fi
	if isempty "$DIR"/crashes ; then
		debug_display "No results in ./${OUTPUT_DIR_PARENT}/$1" ;
		return 0 ;
	fi
	debug_display "Copying crash data from ./${OUTPUT_DIR_PARENT}/$1"
	mkdir "/tmp/$1"
	for file in "${DIR}"/crashes/id* ; do
		outFile="${file#*:}" ;
		cp "${file}" /tmp/$1/${outFile:0:6}.dat ;
	done
	cd /tmp || return
	zip -o9 ~/afl.zip "./$1/"*
	cd - > /dev/null
	rm -r "/tmp/$1"
	}

if [ "$1" = "package" ] ; then
	if [ -f ~/afl.zip ] ; then
		debug_display "Deleting existing ~/afl.zip" ;
		rm ~/afl.zip ;
	fi
	for FUZZTYPE in ${FUZZTYPES} ; do
		package "${FUZZTYPE}" ;
	done
	echo "Results saved to ~/afl.zip"
	exit 0
fi

# From this point onwards we're performing actual fuzzing rather than just
# admin tasks.  First, make sure that the necessary shell variables for afl
# to work have been set and coredump handling is set up correctly.  Without
# the first one, AFL will exit silently, or at least with the error report
# sent somewhere we can't see it due to redirection.

if [ "$(export | grep -c AFL_SKIP_CPUFREQ)" -le 0 ] ; then
	echo "$0: AFL shell variables aren't set." >&2 ;
	exit 1
fi

if [ "$(cat /proc/sys/kernel/core_pattern)" != "core" ] ; then
	echo "$0: /proc/sys/kernel/core_pattern is set wrong." >&2 ;
	exit 1
fi

# Create various directories.

mkdir_opt()
	{
	DIR=$1
	OPTION=$2

	# Try and create the directory
	if [ ! -d "${DIR}" ] ; then
		debug_display "Creating ${DIR}" ;
		mkdir "${DIR}" ;
		return 0 ;
	fi
	if [ -z "$OPTION" ] ; then
		return 0 ;
	fi

	# It already exists, handle it as per the caller's instructions
	case $OPTION in
		'clear-dup')
			echo "Warning: Input directory ${DIR} already exists, clearing files" ;
			rm "${DIR}*.dat" > /dev/null ;;

		'warn-dup')
			echo "Warning: Output directory ${DIR} already exists, were you" ;
			echo "         meaning to continue a previous run?" ;;

		*)
			echo "$0: Invalid mkdir_opt type $1." >&2 ;
			exit 1 ;;
	esac
	}

mkdir_opt ${INPUT_DIR_PARENT}
mkdir_opt ${OUTPUT_DIR_PARENT}

# If we're resuming from an aborted previous session, it's handled
# specially.

if [ "$1" = "resume" ] ; then
	shift
	if [ -z "$1" ] ; then
		echo "$0: Missing resume option.  Usage: '$0 resume <type>'" >&2
		exit 1
	fi
	echo "Resuming fuzzing '$1' from previous session"
	FUZZTYPE=$1
	OUTPUT_DIR=${OUTPUT_DIR_PARENT}/$1/default
	nohup "${FUZZER}" -m ${MEMORY_LIMIT} -i - -o "${OUTPUT_DIR}" ${PROGNAME} -z"${FUZZTYPE}" @@ &
#	nohup "${FUZZER}" -m ${MEMORY_LIMIT} -i - -o "${OUTPUT_DIR}" ${PROGNAME} -z"${FUZZTYPE}" @@ > /dev/null 2>&1 &
	exit 0
fi

# Set up files and directories.

FILEPATH="test/fuzz/"
case $1 in
	# Sessions reverse the argument, so to fuzz the xxx client we use
	# data from the xxx server.
	'ssh-client')
		FILENAME=${FILEPATH}ssh_svr.dat ;;

	'ssh-server')
		FILENAME=${FILEPATH}ssh_cli.dat ;;

	'tls-client')
		FILENAME=${FILEPATH}tls_svr.dat ;;

	'tls-server')
		FILENAME=${FILEPATH}tls_cli.dat ;;

	'cmp-client')
		FILENAME=${FILEPATH}cmp_svr.dat ;;

	'cmp-server')
		FILENAME=${FILEPATH}cmp_cli.dat ;;

	'tsp-client')
		FILENAME=${FILEPATH}tsp_svr.dat ;;

	'tsp-server')
		FILENAME=${FILEPATH}tsp_cli.dat ;;

	'ocsp-client')
		FILENAME=${FILEPATH}ocsp_svr.dat ;;

	'ocsp-server')
		FILENAME=${FILEPATH}ocsp_cli.dat ;;

	'rtcs-client')
		FILENAME=${FILEPATH}rtcs_svr.dat ;;

	'rtcs-server')
		FILENAME=${FILEPATH}rtcs_cli.dat ;;

	'scvp-client')
		FILENAME=${FILEPATH}scvp_svr.dat ;;

	'scvp-server')
		FILENAME=${FILEPATH}scvp_cli.dat ;;

	# HTTP uses underscores instead of dashes for the filename so can't
	# be handled by the default handler below.
	'http-req')
		FILENAME=${FILEPATH}http_req.dat ;;

	'http-resp')
		FILENAME=${FILEPATH}http_resp.dat ;;

	# Everything else uses the argument as the data source.
	*)
		FILENAME=${FILEPATH}$1.dat ;;
esac
if [ ! -f "${FILENAME}" ] ; then
	echo "$0: Couldn't find data file ${FILENAME}." >&2
	exit 1
fi
mkdir_opt "${INPUT_DIR}" clear-dup
mkdir_opt "${OUTPUT_DIR}" warn-dup
debug_display "Copying ${FILENAME} to ${INPUT_DIR}" ;
cp "${FILENAME}" "${INPUT_DIR}"
if [ ! -x  "${PROGNAME}" ] ; then
	debug_display "Copying ${PROGNAME_SRC} to ${PROGNAME}" ;
	cp "${PROGNAME_SRC}" "${PROGNAME}" ;
fi

# Run the fuzzer.  This takes files from ${INPUT_DIR} and pastes them into
# the '@@' location, with output in ${OUTPUT_DIR}/hangs and
# ${OUTPUT_DIR}/crashes.  If there are problems with timeouts, add something
# like -t 1000 (1s in ms).
#
# To start a single-instance fuzzer:
# nohup ${FUZZER} -m ${MEMORY_LIMIT} -i ${INPUT_DIR} -o ${OUTPUT_DIR} ${PROGNAME} -z${FUZZTYPE} @@ &
#
# This writes initial output to nohup.log, to make it completely silent
# append "> /dev/null 2>&1".

debug_display "Running ${FUZZER} for type ${FUZZTYPE} on input in ${INPUT_DIR} with output in ${OUTPUT_DIR}" ;
nohup "${FUZZER}" -m ${MEMORY_LIMIT} -t 1000 -i "${INPUT_DIR}" -o "${OUTPUT_DIR}" ${PROGNAME} -z"${FUZZTYPE}" @@ &
exit 0

echo "Running on ${NO_CPUS} CPUs"
${FUZZER} -m ${MEMORY_LIMIT} -i "${INPUT_DIR}" -o "${OUTPUT_DIR}" -M fuzzer1 ${PROGNAME} -z"${FUZZTYPE}" @@ &

# In theory afl can run across multiple CPU cores with multiple instances, one
# per core, but this doesn't seem to work properly.  If it gets sorted out then
# the master is started with -M, the slaves with -S, however since we're
# fuzzing multiple protocols doing one per core seems the best utilisation.

if [ $NO_CPUS -gt 1 ] ; then
	for i in $(seq 2 $NUM_FUZZERS) ; do
		${FUZZER} -m ${MEMORY_LIMIT} -i "${INPUT_DIR}" -o "${OUTPUT_DIR}" -S fuzzer${i} ${PROGNAME} -z"${FUZZTYPE}" @@ &
	done
fi
