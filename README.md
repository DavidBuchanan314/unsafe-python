# unsafe-python
A library to assist writing memory-unsafe code in pure python, without any imports (i.e. no ctypes etc.)

```python
>>> import unsafe  # (If "no imports" is a requirement, then you can just copy-paste the code)
>>> mem = unsafe.getmem()
>>> mem[0]
Segmentation fault (core dumped)
```

# Why?
I don't know.

# How?
The CPython bytecode interpreter has documented memory-unsafety bug/features. Notably, the `LOAD_CONST` opcode (used to load a constant from the `co_consts` tuple) does not have any bounds checks, presumably for performance reasons. This has been used in the past to [execute arbitrary code](https://doar-e.github.io/blog/2014/04/17/deep-dive-into-pythons-vm-story-of-load_const-bug/) and [escape sandboxes](https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html). Until now, these exploits have relied on custom bytecode generation, which is inherently fragile because the bytecode specification changes between different versions and/or implementations of python.

This project uses CPython's code object introspection APIs, along with a heap grooming technique, in order to craft "vulnerable" code objects using CPython's own bytecode compiler. This technique allows us to craft fake python objects on the heap, similar to the "`fakeobj()`" primitive you might see in explots for JavaScript engines. For example, we can craft a bytearray with a base addresss of 0 and a length of `SSIZE_MAX`, giving us read and write access to raw memory.
