from elftools.elf.elffile import ELFFile
import shutil
from typing import Union
from pathlib import Path
import re

def dt_needed_libpython_linux(path: Union[Path, str]) -> str:
    path = Path(path)
    with path.open("rb") as f:
        elf = ELFFile(f)
        for segment in elf.iter_segments():
            if segment.header["p_type"] == "PT_DYNAMIC":
                for tag in segment.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        # Check if it match pattern libpython3*.so* with regex
                        if re.match(r"libpython3.*\.so.*", tag.needed):
                            return tag.needed


def get_ida_home_linux(path: Union[Path, str]) -> Path:
    path = Path(path)
    # Find the path from PATH is it's not abspath
    if not Path(path).is_absolute():
        path = Path(shutil.which(path))
        if path is None:
            raise FileNotFoundError("Cannot find IDA from PATH")
    
    # Convert it to Path
    path = Path(path)
    # Follow path until it's not symblink
    while path.is_symlink():
        path = path.resolve()
    # Get the parent directory of the path
    path = path.parent
    return path

def libpython_wanted_linux(ida_path: Union[Path, str]) -> str:
    ida_path = Path(ida_path)
    ida_home = get_ida_home_linux(ida_path)
    for candidate_target in ida_home.glob("python/*/*/_ida_*.so"):
        libpython_wanted = dt_needed_libpython_linux(candidate_target)
        if libpython_wanted is not None:
            return libpython_wanted
        


if __name__ == '__main__':
    libpython_wanted = libpython_wanted_linux("idat64")
    print(libpython_wanted)