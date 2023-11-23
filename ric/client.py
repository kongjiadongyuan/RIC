import rpyc
import socket
import random
import struct
import time
import subprocess
from pathlib import Path
from typing import Union, List
from enum import Enum
import platform
from find_libpython import find_libpython
import tempfile
import os

from .proc_utils import wait_for_stop
from .find_idapython import libpython_wanted_linux

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
        use_current_python: bool = None
    ):
        # Initialize normal variables
        self.ida = ida
        self.binary = binary
        self.log_file = log_file
        self.options = options
        self.connect_timeout = connect_timeout
        self.re_analyze = re_analyze
        self.use_current_python = use_current_python
        
        if self.use_current_python and platform.system() != "Linux":
            raise ValueError("use_current_python is only supported on Linux now")

        if self.use_current_python is None and platform.system() == "Linux":
            self.use_current_python = True

        if idb_path is not None:
            self.idb_path = Path(idb_path)
        else:
            self.idb_path = Path(str(binary) + idb_suffix)

class RIC:
    def __init__(self, config: RICConfig):
        self.config = config
        self._proc = None
        self._conn = None
        self._tmpdir = None
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
    
    def spawn_ida(self, port: int):
        cmd = self.start_cmd(port, self.config.re_analyze)
        env = os.environ.copy()
        if self.config.use_current_python:
            try:
                if platform.system() == "Linux":
                    wanted_libpython = libpython_wanted_linux(self.config.ida)
                    current_libpython = find_libpython()
                    if wanted_libpython is not None and current_libpython is not None:
                        self._tmpdir = tempfile.TemporaryDirectory()
                        env = os.environ.copy()
                        tmp_dir_path_str = self._tmpdir.name
                        env["LD_LIBRARY_PATH"] = tmp_dir_path_str + (":" + env['LD_LIBRARY_PATH'] if 'LD_LIBRARY_PATH' in env else "")
                        os.symlink(current_libpython, self._tmpdir.name + "/" + wanted_libpython)
            except Exception:
                pass
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
                
    
    def start(self):
        port = get_free_port()
        clear_broken_idb(self.config.idb_path)
        if self.config.idb_path.exists() and self.config.re_analyze:
            self.config.idb_path.unlink()
        
        # Set self._proc and self._tmpdir
        self.spawn_ida(port)

        # Check if the server is running
        conn = rpyc_connect("localhost", port, timeout=self.config.connect_timeout)
        self._conn = conn

    def stop(self):
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
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
    
    def is_alive(self):
        if self._proc is None:
            return False
        return self._proc.poll() is None
    
    def exit_code(self):
        if self._proc is None:
            return None
        return self._proc.poll()
