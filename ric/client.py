import rpyc
import socket
import random
import struct
import time
import subprocess
from pathlib import Path
from typing import Union, List
from enum import Enum
from .proc_utils import wait_for_stop

SERVER_SCRIPT = Path(__file__).parent / "ida_script" / "server.py"


def rpyc_connect(*args, **kwargs):
    timeout = kwargs.pop("timeout", 5)
    start_time = time.time()
    while True:
        try:
            conn = rpyc.connect(*args, **kwargs)
            return conn
        except ConnectionRefusedError:
            current_time = time.time() - start_time
            if current_time > timeout:
                raise
            time.sleep(0.05)

def get_free_port():
    while True:
        port = random.randint(1024, 50000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("localhost", port))
            sock.close()
            return port
        except OSError:
            sock.close()


def clear_broken_idb(idb_path: Path):
    idb_path_str = str(idb_path)
    assert idb_path_str.endswith(".idb") or idb_path_str.endswith(".i64")
    broken_suffix_list = [".id0", ".id1", ".id2", ".til", ".nam"]

    for suffix in broken_suffix_list:
        shard = Path(idb_path_str[:-4] + suffix)
        if shard.exists():
            shard.unlink()


class RICConfig:
    def __init__(
        self,
        binary: Union[Path, str],
        ida: Union[Path, str] = "idat64",
        idb_path: str = None,
        idb_suffix: str = ".i64",
        log_file: str = None,
        options: List[str] = [],
        re_analyze: bool = False,
        connect_timeout: int = 3,
    ):
        # Initialize normal variables
        self.ida = ida
        self.binary = binary
        self.log_file = log_file
        self.options = options
        self.connect_timeout = connect_timeout
        self.re_analyze = re_analyze

        if idb_path is not None:
            self.idb_path = Path(idb_path)
        else:
            self.idb_path = Path(str(binary) + idb_suffix)

class RIC:
    def __init__(self, config: RICConfig):
        self.config = config
        self._proc = None
        self._conn = None
        
        self._remote = None

    def start_cmd(self, port: int, re_analyze: bool = False):
        cmd = []
        cmd.append(str(self.config.ida))
        cmd.append("-A")
        cmd.append("-S" + str(SERVER_SCRIPT))
        if self.config.log_file is not None:
            cmd.append("-L" + str(self.config.log_file))
        cmd.append(f"-Oricport:{port}")
        cmd.extend(self.config.options)

        if self.config.idb_path.exists() and not re_analyze:
            cmd.append(str(self.config.idb_path))
        else:
            cmd.append(f"-o{str(self.config.idb_path)}")
            cmd.append(str(self.config.binary))
        return cmd
    
    def start(self):
        port = get_free_port()
        clear_broken_idb(self.config.idb_path)
        if self.config.idb_path.exists() and self.config.re_analyze:
            self.config.idb_path.unlink()
        cmd = self.start_cmd(port, self.config.re_analyze)
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Check if the server is running
        conn = rpyc_connect("localhost", port, timeout=self.config.connect_timeout)
        self._conn = conn

    def stop(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._proc is not None:
            wait_for_stop(self._proc)
            self._proc = None
    
    def __enter__(self):
        self.start()   
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
    
    def execute(self, *args, **kwargs):
        self._conn.root.execute(*args, **kwargs)
    
    def eval(self, *args, **kwargs):
        return self._conn.root.eval(*args, **kwargs)
    
    def get_module(self, module):
        self.execute(f"import {module}")
        return self.eval(module)
        