import os
import subprocess


class Scanner:

    def __init__(self):
        self.name = 'nmap'

    async def scan(self, *args, filename=None, target_specification=None, scripts=None, **kwargs):
        command = 'nmap --script plugins/crag/scanners/nmap/scripts/nmap-vulners -sV -Pn -oX %s %s' % (filename, target_specification)
        return subprocess.call(command.split(' '), shell=False)
