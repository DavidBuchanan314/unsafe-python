import unsafe

# only tested/working on python 2.7, 3.8,  (x86_64)

gadgets = unsafe.find_gadgets()

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode_ptr = unsafe.refbytes(shellcode)
shellcode_page_base = shellcode_ptr & ~0xFFF
shellcode_page_end = (shellcode_ptr + len(shellcode)) & ~0xFFF
shellcode_page_len = shellcode_page_end - shellcode_page_base + 0x1000

print("Shellcode @", hex(shellcode_ptr))

rop_payload = unsafe.p64a(
	gadgets["pop rax; ret"],
	10,  # SYS_MPROTECT
	
	gadgets["pop rdi; ret"],
	shellcode_page_base,  # start
	
	gadgets["pop rsi; ret"],
	shellcode_page_len,  # len
	
	gadgets["pop rdx; pop rbx; ret"],
	7,  # prot (RWX)
	0,  #junk
	
	gadgets["syscall; ret"],
	
	shellcode_ptr # jump into the shellcode!
)

unsafe.do_rop(rop_payload)
