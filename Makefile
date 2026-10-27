# Cross-compilers (override on the command line if yours are named differently)
CC32 ?= arm-linux-gnueabihf-gcc
CC64 ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O1 -static -Wall -Wextra

BINS := gpu_arb_write kfunc

.PHONY: all zig clean install

all: $(BINS)

gpu_arb_write: src/gpu_arb_write.c
	$(CC32) $(CFLAGS) -o $@ $<

kfunc: src/kfunc.c
	$(CC64) $(CFLAGS) -o $@ $<

# Same thing via zig, which needs no preinstalled cross toolchain.
ZIG ?= zig
zig:
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target arm-linux-musleabihf $(CFLAGS) -o gpu_arb_write src/gpu_arb_write.c
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target aarch64-linux-musl $(CFLAGS) -o kfunc src/kfunc.c

# Push to a device that is already reachable over adb.
install: all
	adb push $(BINS) run.sh roothelper.sh /data/local/tmp/
	adb shell 'cd /data/local/tmp && chmod 755 $(BINS) run.sh roothelper.sh'

clean:
	rm -f $(BINS)
