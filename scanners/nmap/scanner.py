import os
import glob
import asyncio


class Scanner:

    def __init__(self, filename=None, target_specification=None, scripts=None):
        self.name = 'nmap'
        self.status = None
        self.returncode = None
        self.output = None
        self.filename = filename
        self.target_specification = target_specification
        self.script_folder = 'plugins/pathfinder/scanners/nmap/scripts'
        self.scripts = scripts or self.list_available_scripts()

    async def scan(self):
        try:
            self.status = 'running'
            scripts = ','.join([os.path.join(self.script_folder, s) for s in self.scripts])
            command = 'nmap --script %s -sV -Pn -oX %s %s' % (scripts, self.filename, self.target_specification)
            process = await asyncio.create_subprocess_exec(*command.split(' '), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            self.status = 'done'
            self.output = dict(stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))
            self.returncode = process.returncode
        except Exception as e:
            self.status = 'done'
            self.returncode = -1
            self.output = dict(stderr='exception encountered when scanning, %s' % repr(e))

    def list_available_scripts(self):
        return [os.path.basename(p) for p in glob.iglob('%s/*' % self.script_folder)]
