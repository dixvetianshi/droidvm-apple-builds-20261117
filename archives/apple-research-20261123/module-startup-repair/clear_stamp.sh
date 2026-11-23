#!/system/bin/sh
# Own all boot-mark parsing and cleanup. Each attempt has a unique filename:
# an earlier watcher cannot unlink a later attempt's pending mark.
DIR=/data/adb/modules/gh-hugepage-reserve
MODULE=/sys/module/gh_hugepage_reserve

identity_ok() {
	case "$1" in ""|*[!a-fA-F0-9-]*) return 1 ;; esac
	[ "${#1}" = 36 ]
}
current_boot() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }
read_mark() {
	FORMAT= OWNER_BOOT= OWNER_ATTEMPT= STATE= RESULT= EXTRA=
	[ -f "$1" ] && read -r FORMAT OWNER_BOOT OWNER_ATTEMPT STATE RESULT EXTRA < "$1" || return 1
	[ "$FORMAT" = gh-v1 ] && [ -z "$EXTRA" ] &&
		identity_ok "$OWNER_BOOT" && identity_ok "$OWNER_ATTEMPT" || return 1
	[ "$1" = "$DIR/stamp.$OWNER_BOOT.$OWNER_ATTEMPT" ] || return 1
	case "$STATE:$RESULT" in loading:-|ready:0) return 0 ;; esac
	return 1
}
protect() {
	# Preserve an existing crash, and retain the original pending evidence.
	if ! [ -e "$DIR/crash" ]; then
		( set -C; printf 'gh-v1 %s %s\n' "$1" "$BOOT" > "$DIR/crash" ) 2>/dev/null
	fi
	touch "$DIR/disable"
	echo "boot protection: $1; pending evidence retained" >&2
	return 1
}
begin() {
	BOOT="$(current_boot)"
	identity_ok "$BOOT" || { echo "boot identity unavailable" >&2; return 1; }
	[ ! -e "$DIR/disable" ] || return 1
	if [ -e "$DIR/crash" ]; then
		touch "$DIR/disable"
		echo "boot protection: existing crash retained" >&2
		return 1
	fi
	[ ! -e "$DIR/stamp" ] || { protect legacy-unconfirmed; return 1; }
	for mark in "$DIR"/stamp.*; do
		[ -e "$mark" ] || continue
		read_mark "$mark" || { protect unknown-pending; return 1; }
		[ "$OWNER_BOOT" = "$BOOT" ] || { protect previous-boot-unconfirmed; return 1; }
	done
	ATTEMPT="$(cat /proc/sys/kernel/random/uuid 2>/dev/null)"
	identity_ok "$ATTEMPT" || { echo "attempt identity unavailable" >&2; return 1; }
	MARK="$DIR/stamp.$BOOT.$ATTEMPT"
	( set -C; printf 'gh-v1 %s %s loading -\n' "$BOOT" "$ATTEMPT" > "$MARK" ) || return 1
	# A userspace restart in the same kernel boot starts a fresh load attempt.
	# Preserve superseded evidence only after the new protection mark exists.
	mkdir -p "$DIR/bootmark-history" || return 1
	for mark in "$DIR"/stamp.*; do
		[ -f "$mark" ] && [ "$mark" != "$MARK" ] || continue
		read_mark "$mark" || return 1
		[ "$OWNER_BOOT" = "$BOOT" ] || return 1
		mv "$mark" "$DIR/bootmark-history/${mark##*/}" || return 1
	done
	printf '%s %s\n' "$BOOT" "$ATTEMPT"
}
finish() {
	BOOT=$1 ATTEMPT=$2 RC=$3
	identity_ok "$BOOT" && identity_ok "$ATTEMPT" || return 1
	MARK="$DIR/stamp.$BOOT.$ATTEMPT"
	[ "$(current_boot)" = "$BOOT" ] && read_mark "$MARK" &&
		[ "$STATE" = loading ] || return 1
	if [ "$RC" != 0 ] || ! [ -d "$MODULE" ]; then
		protect "load-failed-rc-$RC"
		[ "$RC" != 0 ] && return "$RC"
		return 66
	fi
	printf 'gh-v1 %s %s ready 0\n' "$BOOT" "$ATTEMPT" > "$MARK.tmp" &&
		mv "$MARK.tmp" "$MARK"
}
watch_one() {
	BOOT=$1 ATTEMPT=$2 STABLE=0 WATCH_LEFT=600
	identity_ok "$BOOT" && identity_ok "$ATTEMPT" || return 1
	MARK="$DIR/stamp.$BOOT.$ATTEMPT"
	# A killed load or missing late hook must not leave a permanent poller.
	# Exhausting this ten-minute observation budget preserves unknown pending.
	while [ "$WATCH_LEFT" -gt 0 ] && [ "$(current_boot)" = "$BOOT" ]; do
		[ ! -e "$DIR/crash" ] && [ ! -e "$DIR/disable" ] || return 1
		read_mark "$MARK" || return 1
		if [ "$STATE" = ready ]; then
			# A disappeared module or failed load never confirms a healthy boot.
			[ -d "$MODULE" ] || return 1
			if [ "$(getprop sys.boot_completed 2>/dev/null)" = 1 ]; then
				if [ "$STABLE" -ge 30 ]; then
					rm -f "$MARK"
					return $?
				fi
				STABLE=$((STABLE + 5))
			else
				STABLE=0
			fi
		else
			STABLE=0
		fi
		sleep 5
		WATCH_LEFT=$((WATCH_LEFT - 5))
	done
	return 1
}
case "${1:-watch}" in
	begin) begin ;;
	finish) shift; [ "$#" = 3 ] && finish "$@" ;;
	watch)
		[ "$#" = 0 ] || shift
		if [ "$#" = 2 ]; then
			watch_one "$@"
		elif [ "$#" = 0 ]; then
			for mark in "$DIR"/stamp.*; do
				read_mark "$mark" || continue
				watch_one "$OWNER_BOOT" "$OWNER_ATTEMPT" &
			done
			wait
		else
			exit 1
		fi ;;
	*) exit 1 ;;
esac
