import idaapi

import rpyc
from rpyc.utils.server import OneShotServer
from rpyc.core.service import SlaveService



def main():
    port = idaapi.get_plugin_options("ricport")
    if port is None:
        port = 19702
    else:
        port = int(port)
    print(f"Starting server on port {port}")
    server = OneShotServer(SlaveService, port=port)
    server.start()
    server.close()
    print(f"Server closed")
    idaapi.qexit(0)

if __name__ == '__main__':
    main()