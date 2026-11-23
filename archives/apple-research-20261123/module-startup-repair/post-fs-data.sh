#!/system/bin/sh
DIR=/data/adb/modules/gh-hugepage-reserve
[ -d "$DIR" ] || exit 1
IDENTITY="$(sh "$DIR/clear_stamp.sh" begin)"
BEGIN_RC=$?
[ "$BEGIN_RC" = 0 ] || exit "$BEGIN_RC"
set -- $IDENTITY
[ "$#" = 2 ] || exit 1
BOOT=$1 ATTEMPT=$2
exec > "$DIR/load.log" 2>&1
# load.sh owns settings and ABI preflight; this hook owns boot protection.
GH_BOOT=1 sh "$DIR/load.sh"
LOAD_RC=$?
sh "$DIR/clear_stamp.sh" finish "$BOOT" "$ATTEMPT" "$LOAD_RC"
FINISH_RC=$?
# A snapshot works with BusyBox dmesg implementations lacking -w.
dmesg > "$DIR/dmesg.log" 2>&1
if [ "$FINISH_RC" = 0 ]; then
	# Do not depend on a root manager calling Services or BootCompleted.
	sh "$DIR/clear_stamp.sh" watch "$BOOT" "$ATTEMPT" &
fi
exit "$FINISH_RC"
