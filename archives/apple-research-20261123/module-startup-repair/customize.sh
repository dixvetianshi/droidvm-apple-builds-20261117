set -e

REL="$(getprop ro.build.version.release)"
VER="$(getprop ro.kernel.version)"

echo "Android version: $REL"
echo "Kernel version: $VER"

mkdir -pv "$TMPDIR/$MODID"
cd "$TMPDIR/$MODID"
unzip -o "$ZIPFILE"
set -x

if [ -f /data/local/tmp/gh-hugepage-reserve.prop ]; then
	source /data/local/tmp/gh-hugepage-reserve.prop
fi

if [ -z "$KMI" ]; then
	VER="$(uname -r | sed 's/^\([0-9]*\.[0-9]*\).*/\1/')"
	if uname -r | grep -Eq -- "-android[0-9]{1,2}-"; then
		REL="$(uname -r | sed 's/.*\(android[0-9]*\).*/\1/')"
		KMI="${REL}-${VER}"
	elif [ "$(ls -1 ko/gh_hugepage_reserve/android*-$VER.ko 2>/dev/null | wc -l)" == 1 ]; then
		KMI="$(basename "$(ls -1 ko/gh_hugepage_reserve/android*-$VER.ko)" .ko)"
	else
		echo "ERROR: No match kernel module found for $(uname -r)"
		echo "Please set KMI=android?-?.? in /data/local/tmp/gh-hugepage-reserve.prop"
		exit 1
	fi
fi
echo "KMI: $KMI"

DSTDIR=/data/adb/modules_update/gh-hugepage-reserve
# Keep the caller's complete current configuration before staged defaults copy.
# The fresh-install default lives in this ZIP's module/settings.prop only.
CURRENT_SETTINGS=/data/adb/modules/gh-hugepage-reserve/settings.prop
SAVED_SETTINGS="$TMPDIR/$MODID/current-settings.prop"
HAVE_CURRENT_SETTINGS=0
if [ -f "$CURRENT_SETTINGS" ]; then
	cp -pv "$CURRENT_SETTINGS" "$SAVED_SETTINGS"
	HAVE_CURRENT_SETTINGS=1
fi
mkdir -pv "$DSTDIR"
for mod in gh_hugepage_reserve; do
	if ! [ -f "ko/$mod/$KMI.ko" ]; then
		echo "ERROR: Kernel module $mod is not supports with $KMI"
		exit 1
	fi
	cp -v "ko/$mod/$KMI.ko" "$DSTDIR/$mod.ko"
done
cp -v module.prop "$DSTDIR/"
cp -av module/* "$DSTDIR/"
if [ "$HAVE_CURRENT_SETTINGS" = 1 ]; then
	cp -pv "$SAVED_SETTINGS" "$DSTDIR/settings.prop"
fi
if ! [ -f "$DSTDIR/settings.prop" ]; then
	echo "ERROR: Required module settings.prop is missing"
	exit 1
fi
chmod +x "$DSTDIR/"*.sh
# Preserve the shipped helper bytes in the staged module. load.sh refuses to
# load if this required ABI preflight helper is unavailable or fails.
cp -v kapi_check "$DSTDIR/"
chmod +x "$DSTDIR/kapi_check"
cp -a "$DSTDIR" "/data/adb/modules/"
# Re-enable only after every required copy and the installed commit succeeded.
# Preserve crash and all pending evidence even on a successful reinstall.
rm -f "/data/adb/modules_update/gh-hugepage-reserve/disable" "/data/adb/modules/gh-hugepage-reserve/disable"
echo
echo -e "\xe2\x9c\x85 Module installed successfully. Please reboot to take effect."
echo
exit 0
