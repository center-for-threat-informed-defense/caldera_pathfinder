import os
import glob
import uuid
import asyncio
import subprocess
import xmltodict
from plugins.pathfinder.app.pathfinder_util import get_machine_ip
from plugins.pathfinder.scanners.fields import TextField, PulldownField, CheckboxField
from plugins.pathfinder.app.interfaces.i_scanner import ScannerInterface


class Scanner(ScannerInterface):

    def __init__(self, filename=None, target_specification=None, script=None, script_args=None, ports=None, dependencies=None, pingless=None, **kwargs):
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
        self.enabled = self.check_dependencies(dependencies or {})
        self.scripts = dict(builtin=self.get_builtin_scripts(), local=self.list_available_scripts())
        self.fields = [TextField('target_specification', label='Target Specification', default=get_machine_ip()),
                       PulldownField('script', label='Scanner Script', values=self.scripts['local']+self.scripts['builtin'], prompt='Select the nmap script to use'),
                       TextField('script_args', label='Script Arguments'),
                       TextField('ports', label='Ports'),
                       CheckboxField('pingless', label='No Ping (-Pn)')]

    async def scan(self):
        try:
            self.status = 'running'
            script_args = '--script-args %s' % self.script_args if self.script_args else ''
            no_ping = '-Pn' if int(self.pingless) else ''
            ports = '-p %s' % self.ports if self.ports else ''
            command = 'nmap --script %s %s -sV %s -oX %s %s %s' % (self.format_script(self.script),
                                                                   script_args,
                                                                   no_ping,
                                                                   os.path.abspath(self.filename),
                                                                   ports,
                                                                   self.target_specification)
            process = await asyncio.create_subprocess_exec(*[p for p in command.split(' ') if p],
                                                           stdout=asyncio.subprocess.PIPE,
                                                           stderr=asyncio.subprocess.PIPE,
                                                           cwd=self.script_folder)
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

    @staticmethod
    def get_builtin_scripts(category='vuln'):
        def get_script_name(script):
            return script.get('@filename').split('/')[-1].replace('.nse', '')

        scripts = [category]
        command = 'nmap --script-help %s -oX -' % category
        output = subprocess.run(command.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not output.returncode:
            data = xmltodict.parse(output.stdout)
            scripts.extend([get_script_name(item) for item in data['nse-scripts']['script']])
        return scripts

    def format_script(self, script):
        if script in self.scripts['local']:
            return os.path.join(script, '') if os.path.isdir(os.path.join(self.script_folder, script)) else script
        return script

    def check_dependencies(self, dependencies):
        return dependencies.get('nmap', False)
