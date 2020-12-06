import unsafe

mem = unsafe.getmem()

print(hex(id(mem)))

print(type(mem))
print(hex(len(mem)))

# dump some memory
print(repr(mem[unsafe.addrof(mem):unsafe.addrof(mem)+0x40]))

# jump to 0xdeadbeef (check dmesg to see if it "worked")
unsafe.setrip(0xdeadbeef)
