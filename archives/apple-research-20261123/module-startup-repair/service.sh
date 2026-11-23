#!/system/bin/sh
# Supplemental owned boot-mark cleanup. Global host policy belongs to the user.
sh /data/adb/modules/gh-hugepage-reserve/clear_stamp.sh watch &
exit 0
