import asyncio


class Scanner:

    def __init__(self, filename, target_specification):
        self.name = 'nmap'
        self.status = None
        self.returncode = None
        self.output = None
        self.filename = filename
        self.target_specification = target_specification

    async def scan(self):
        self.status = 'running'
        command = 'nmap --script plugins/pathfinder/scanners/nmap/scripts/nmap-vulners -sV -Pn -oX %s %s' % (self.filename, self.target_specification)
        process = await asyncio.create_subprocess_exec(*command.split(' '), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        self.status = 'done'
        self.output = dict(stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))
        self.returncode = process.returncode
