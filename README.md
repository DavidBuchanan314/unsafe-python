# unsafe-python
A library to assist writing memory-unsafe code in "pure" python, without any imports (i.e. no ctypes etc.)

Supports CPython 3.11 and below (3.12 support coming soon?)

**Note: This is a toy.** You probably shouldn't use it for anything serious (or anything at all, really).

# Core features:

- `addrof(obj)` - A trivial alias of the `id()` builtin.
- `fakeobj(addr)` - Allows for crafting fake heap objects.
- `getmem()` - Returns a bytearray view of the current process's virtual memory.
- `setrip(addr)` - Sets the RIP register. Argument passing etc. coming soon™.
- `do_rop(payload)` - Execute a ROP payload.

A trivial example, showing how to dereference a null pointer in pure python. The future is now!
```python
>>> import unsafe  # (If "no imports" is a requirement, then you can just copy-paste the code)
>>> mem = unsafe.getmem()
>>> mem[0]
Segmentation fault (core dumped)
```

For a less trivial example, check out `shellcode_example_nocheats.py`, which uses ROP to
 `mprotect` a shellcode buffer, and then jump into it.

# Why?
I don't know.

# How?
The CPython bytecode interpreter has documented memory-unsafety bug/features. Notably, the `LOAD_CONST` opcode (used to load a constant from the `co_consts` tuple) does not have any bounds checks, presumably for performance reasons. This has been used in the past to [execute arbitrary code](https://doar-e.github.io/blog/2014/04/17/deep-dive-into-pythons-vm-story-of-load_const-bug/) and [escape sandboxes](https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html). Until now, these exploits have relied on custom bytecode generation, which is inherently fragile because the bytecode specification changes between different versions and/or implementations of python.

This project uses CPython's code object introspection APIs, along with a heap grooming technique, in order to craft "vulnerable" code objects using CPython's own bytecode compiler. This technique allows us to craft fake python objects on the heap, similar to the "`fakeobj()`" primitive you might see in exploits for JavaScript engines. For example, we can craft a bytearray with a base address of 0 and a length of `SSIZE_MAX`, giving us read and write access to raw memory.

# TODO:

 - Perform ROP gadget search without "cheating" by reading `/proc/self/maps`.
i.e. find a reliable way to leak libc base. (Edit: the buffered reader exploit linked below implements this)

# See Also:

An incomplete list of known CPython memory safety issues:

 - https://pwn.win/2022/05/11/python-buffered-reader.html - https://github.com/kn32/python-buffered-reader-exploit/blob/master/exploit.py
