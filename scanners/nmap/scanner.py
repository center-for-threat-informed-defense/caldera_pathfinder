import os
import glob
import uuid
import asyncio
# from plugins.pathfinder.app.pathfinder_gui import get_machine_ip


class Scanner:

    def __init__(self, filename=None, target_specification=None, script=None, script_args=None, ports=None, dependencies=None, pingless=None):
        self.name = 'nmap'
        self.id = str(uuid.uuid4())
        self.status = None
        self.returncode = None
        self.output = None
        self.filename = filename
        self.target_specification = target_specification
        self.script_folder = 'plugins/pathfinder/scanners/nmap/scripts'
        self.script = script or ''
        self.script_args = script_args
        self.ports = ports
        self.pingless = pingless
        self.enabled = self.check_dependencies(dependencies)
        self.fields = [dict(name='Target Specification', param='target_specification', type='text', default=0),
                       dict(name='Scanner Script', param='script', type='pulldown', values=self.list_available_scripts(), prompt='Select the nmap script to use'),
                       dict(name='Script Arguments', param='script_args', type='text'),
                       dict(name='Ports', param='ports', type='text'),
                       dict(name='No Ping', param='pingless', type='checkbox')]

    async def scan(self):
        try:
            self.status = 'running'
            script_args = '--script-args %s' % self.script_args if self.script_args else ''
            no_ping = '-Pn' if self.pingless else ''
            ports = '-p %s' % self.ports if self.ports else ''
            command = 'nmap --script %s %s -sV %s -oX %s %s %s' % (self.script, script_args, no_ping, os.path.abspath(self.filename), ports, self.target_specification)
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

    def check_dependencies(self, dependencies):
        return dependencies.get('nmap', False)
