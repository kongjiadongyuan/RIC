from ric import RIC, RICConfig

config = RICConfig(
    binary="/Users/kjdy/Desktop/idatest/cmark",
    ida="/Applications/IDA Pro 8.0/idabin/idat64",
    log_file="/Users/kjdy/Desktop/idatest/ric.log",
    idb_path="/Users/kjdy/Desktop/idatest/omg.i64",
) 

# Use RIC as a context manager

with RIC(config) as ric:
    idaapi = ric.get_module("idaapi")
    print(idaapi)