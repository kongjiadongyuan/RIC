# Remote IDA Call

This is a python package that allows you to call IDA functions from a remote process.

## Installation

```bash
pip install git+https://github.com/kongjiadongyuan/RIC.git
```

Make sure you have IDA installed and the IDA python plugin is enabled.

I highly recommend you to link `idat64` and `idat` to your PATH, such as `/usr/local/bin/idat64` and `/usr/local/bin/idat`.

```bash
ln -s /path/to/ida/idat64 /usr/local/bin/idat64
ln -s /path/to/ida/idat /usr/local/bin/idat
```

Do not add `/path/to/ida` to your PATH, this may cause some problems :-(

But if you don't want to do this, you can also specify the path to `idat64` and `idat` when you create a `RICConfig` object :-)

## Usage

There are two methods to use this package.

### "CLASSIC" method

This approach gives you the experience of writing a native IDA script.

Consider the following code:

```python
# Import ida module
import idautils

# Complete the following code
function_list = list(idautils.Functions())

# Save the result
import json
with open('result.txt', 'w') as f:
    json.dump(function_list, f, indent=4)
```

You may spawn the IDA python interpreter and run this script, then you will get a file named `result.txt` in your current directory.

```bash
idat64 -A -S/path/to/your/script.py /path/to/your/binary
```

Then you can read the result from `result.txt`.

```python
import json
with open('result.txt', 'r') as f:
    function_list = json.load(f)
```

The experience is cumbersome and fragmented.

Now, you can use `RIC` to make it easier, and only need to make some simple modifications to the code.

```diff
- # Import ida module
- import idautils

+ # Initialize RIC
+ from ric import RICConfig, RIC
+ config = RICConfig(
+     binary="/path/to/your/binary"
+ )
+ ric = RIC(config)
+ ric.start()
+ 
+ # "import" ida module
+ idautils = ric.get_module('idautils')

# Complete the following code
function_list = list(idautils.Functions())

+ # Stop RIC
+ ric.stop()

# Just do anything you want
# Here's normal python interpreter, not IDA python interpreter

- # Save the result
- import json
- with open('result.txt', 'w') as f:
-     json.dump(function_list, f, indent=4)
```

### "WITH" method

You should have noticed that if you want to maintain the original ida script code style, you still cannot avoid manually managing the life cycle of ric (behind it is the life cycle of the ida process). 

If you're willing to make some changes, our context manager will let you forget about ida's existence entirely.

```python
from ric import RICConfig, RIC
config = RICConfig(
    binary="/path/to/your/binary"
)

with RIC(config) as ric:
    idautils = ric.get_module('idautils')
    function_list = list(idautils.Functions())
```

## Config

`RICConfig` contains the following parameters:
- `binary`: The path to the binary to be analyzed, **required**.
- `ida`: The path to the IDA executable, default is `idat64`, you can also specify other path, such as `~/idapro/idat`. If you want to analyze a 32-bit program, remember to set it to `idat`.
- `idb_path`: The path to the IDB file, default is `None`, which means that the IDB file will be saved to the same directory as the binary file.
- `idb_suffix`: The suffix of the IDB file, default is `.i64`, which corresponds to the 64-bit IDB file. If you want to analyze a 32-bit program, remember to set it to `.idb`.
- `log_file`: The path to the log file, will be passed to `idat64` in `-L/path/to/log_file` format, default is `None`, which means no log file will be generated.
- `options`: Most of the time there is no need to pass arguments anymore. However, if you want to control some of the behavior of IDA, you can use this interface to add custom options. For example, if you want IDA to automatically load `dwarf` debug information, you can set `options=["-Odwarf:import_lnnums=1"]`.
- `re_analyze`: By default, `RIC` will reuse existing `.i64` databases (if exists), which means that if you analyze the same binary multiple times, the database will not be re-analyzed. If you want to re-analyze the database, you can set `re_analyze=True`.
- `connect_timeout`: `RIC` is implemented based on `rpyc`, so it is possible that the client cannot connect to the server (we are still in a very early development version).


## Best Practice

The `idapython` plug-in has its own independently specified python path, which means that the environment used by the python script you write using `RIC` may be different from that in `idapython`. For the `RIC` framework, it will work as long as the `rpyc` package is in the environment where `idapython` is located, but it is still recommended to use the same environment. You can specify it using `idapyswitch` under the ida installation path.

