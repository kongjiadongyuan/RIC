from ric import RIC, RICConfig

config = RICConfig(
    binary="/workspace/idatest/openssh-tests/binaries/O0/mkdtemp",
    use_current_python=True
) 

# Use RIC as a context manager
with RIC(config) as ric:
    idaapi = ric.get_module("idaapi")
    import IPython; IPython.embed()