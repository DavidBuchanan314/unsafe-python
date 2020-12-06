import unsafe
import mmap
# TODO: I consider mmap to be cheating. I would like to write a shellcode
# loader that does not depend on the mmap library (e.g. using ROP to map the RWX buffer)

mem = unsafe.getmem()

# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

mm = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE|mmap.PROT_READ|mmap.PROT_EXEC)
mm.write(shellcode)

mm_addr = unsafe.addrof(mm)
shellcode_addr = int.from_bytes(mem[mm_addr+16:mm_addr+16+8], "little")

unsafe.setrip(shellcode_addr)
