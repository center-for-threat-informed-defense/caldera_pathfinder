import os
import glob
import asyncio


class Scanner:

    def __init__(self, filename=None, target_specification=None, scripts=None, script_args=None, ports=None):
        self.name = 'nmap'
        self.status = None
        self.returncode = None
        self.output = None
        self.filename = filename
        self.target_specification = target_specification
        self.script_folder = 'plugins/pathfinder/scanners/nmap/scripts'
        self.scripts = scripts or self.list_available_scripts()
        self.script_args = script_args
        self.ports = ports

    async def scan(self):
        try:
            self.status = 'running'
            script_args = '--script-args %s' % self.script_args if self.script_args else ''
            ports = '-p %s' % self.ports if self.ports else ''
            command = 'nmap --script %s %s -sV -Pn -oX %s %s %s' % (','.join(self.scripts), script_args, os.path.abspath(self.filename), ports, self.target_specification)
            process = await asyncio.create_subprocess_exec(*command.split(' '), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=self.script_folder)
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
