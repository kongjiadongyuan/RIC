from ric import RIC, RICConfig

# Initialize RIC
config = RICConfig(
    binary="/Users/kjdy/Desktop/idatest/cmark",
    ida="/Applications/IDA Pro 8.0/idabin/idat64",
    log_file="/Users/kjdy/Desktop/idatest/ric.log",
    idb_path="/Users/kjdy/Desktop/idatest/omg.i64",
)
ric = RIC(config)
ric.start()

# "Import" from RIC
idaapi = ric.get_module("idaapi")
idc = ric.get_module("idc")
idautils = ric.get_module("idautils")
ida_nalt = ric.get_module("ida_nalt")
ida_kernwin = ric.get_module("ida_kernwin")
ida_hexrays = ric.get_module("ida_hexrays")

# Complete your "ida script"

def get_asm(func):
    instGenerator = idautils.FuncItems(func)
    asm_list = []
    for inst in instGenerator:
        asm_list.append(idc.GetDisasm(inst))
    return asm_list

def get_rawbytes(func):
    instGenerator = idautils.FuncItems(func)
    rawbytes_list = b""
    for inst in instGenerator:
        rawbytes_list += idc.get_bytes(inst, idc.get_item_size(inst))
    return rawbytes_list.hex()

def get_funcname(func):
    return idc.get_func_name(func)

def decompile(func):
    return str(ida_hexrays.decompile(func))

def get_functions(func):
    return {
        "address": hex(func),
        "name": get_funcname(func),
        # "rawbytes": get_rawbytes(func),
        # "assembly": get_asm(func)
    }

def get_decompile_code(func):
    return {
        "address": hex(func),
        "code": decompile(func),
    }

function_list = list(idautils.Functions())

def get_all_functions():
    return [get_functions(func) for func in function_list]

def get_name(func):
    return {
        "address": hex(func),
        "name": get_funcname(func),
    }

def get_func_address(func):
    return {
        "address": hex(func)
    }

print(get_all_functions())

# Do not forget to stop RIC
ric.stop()