# Pathfinder Scanner Setup
###### To be successful you must follow the sage advice: "copy, paste, change!"
## Example

```python
import os
import uuid
import asyncio

from plugins.pathfinder.scanners.fields import TextField
from plugins.pathfinder.scanners.fields import CheckboxField


class Scanner:

    def __init__(self, filename=None, dependencies=None, target=None, extra_parameter=None, another_parameter=None, **kwargs):
        self.name = 'example'
        self.id = str(uuid.uuid4())
        self.status = None
        self.returncode = None
        self.output = None
        self.filename = filename
        self.enabled = True
        self.fields = [TextField('target', label='Target', default='127.0.0.1'),
                       TextField('extra_parameter', label='First Example Parameter'),
                       CheckboxField('another_parameter', label='True/false parameter')]
        self.target = target
        self.extra_parameter = extra_parameter
        self.another_parameter = bool(another_parameter)

    async def scan(self):
        try:
            self.status = 'running'
            command = 'example_scanner -t %s' % self.target
            process = await asyncio.create_subprocess_exec(*command.split(' '), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=os.path.curdir)
            stdout, stderr = await process.communicate()
            self.output = dict(stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))
            self.returncode = process.returncode
        except Exception as e:
            self.returncode = -1
            self.output = dict(stderr='exception encountered when scanning, %s' % repr(e))
        finally:
            self.status = 'done'
```

# Tutorial

Adding a scanner to pathfinder was designed to be simple and flexible.
Before adding a scanner you should make sure to create a parser so that your results are able to be parsed into a caldera report upon scan completion.
Instructions are available [here](parser_creation.md)

Starting out you need to observe the directory structure of the scanners section in the pathfinder plugin repo:
<pre>
pathfinder
-- scanners
---- nmap
------ scanner.py
---- example_scanner
------ scanner.py
</pre>
For every new scanner you are adding you should create a folder in the `scanners` directory with the name of the scanner you are adding.
Within that folder you are only required to add a python module with the file name `scanner.py` which will follow the structural example above.
You then can add whatever other supporting files/code/modules are necessary for the scanner.

Within the scanner module there are two required methods: `__init__` and `scan`.

`__init__` builds out the class with all the parameters of the desired scan.
It has two required parameters `filename` and `dependencies`, for the output filename of the scan, and the dependencies checked on plugin initialization for the system by the server.
It teechnically has a 'third' required parameter, which is `**kwargs` which could be any of the named parameters you need to take in for your scanner.  you can either add them as named arguments or leave them as kwargs and pull them from the dictionary.

`scan` kicks off the actual scanning and is spun up as a background process to be ran and periodically checked in upon.

The way scanning works is that a scanner object is initialized with all the parameters needed for scanning and an asynchronous background process is kicked off to do the scanning (`scan` method).
When the scanning finishes it should set the `status` on the `Scanner` object to `done` and then the pathfinder UI thread when checking running scans sees this it can proceed.
The pathfinder service will then feed the output of the scan into a parser of the same name as the scanner and import the report into caldera so it can be visualized and the facts from it can be used.


