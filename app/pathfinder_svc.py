import os
import glob
import logging
from importlib import import_module

from app.utility.base_world import BaseWorld
from app.objects.c_source import Source
from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship

temp_file = 'plugins/pathfinder/data/_temp_report_file.tmp'


class PathfinderService:
    def __init__(self, services):
        self.services = services
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.log = logging.getLogger('pathfinder_svc')
        self.parsers = self.load_parsers()

    async def import_scan(self, scan_format, report):
        # grab and decrypt the file contents and crate a file object to pass to the parser
        try:
            _, contents = await self.file_svc.read_file(report, location='reports')
            with open(temp_file, 'wb') as f:
                f.write(contents)
            parsed_report = self.parsers[scan_format].parse(temp_file)
            if parsed_report:
                await self.data_svc.store(parsed_report)
                return await self.create_source(parsed_report)
            return None
        finally:
            os.remove(temp_file)

    async def create_source(self, report):
        def add_fact(fact_list, trait, value):
            fact_list.append(Fact(trait, value, collected_by='pathfinder'))
            return fact_list[-1:][0]

        if not report:
            return None
        facts = []
        relationships = []
        for host in report.hosts.values():
            ip_fact = add_fact(facts, 'scan.host.ip', host.ip)
            if host.hostname:
                relationships.append(Relationship(ip_fact, 'has_hostname', add_fact(facts, 'scan.host.hostname', host.hostname)))
            for num, port in host.ports.items():
                port_fact = add_fact(facts, 'scan.host.port', num)
                for cve in port.cves:
                    cve_fact = add_fact(facts, 'scan.found.cve', cve)
                    relationships.append(Relationship(ip_fact, 'has_vulnerability', cve_fact))
                    relationships.append(Relationship(port_fact, 'has_vulnerability', cve_fact))
        source = Source(report.id, report.name, facts, relationships)
        source.access = BaseWorld.Access.RED
        await self.data_svc.store(source)
        return source

    async def generate_adversary(self, report, initial_host, target_host):
        attack_paths = await self.find_paths(report, initial_host, target_host)
        shortest_path = attack_paths[0]
        for path in attack_paths:
            if len(path) < len(shortest_path):
                shortest_path = path
        technique_list = [t.id for host in shortest_path[1:] for t in await self.gather_techniques(report, host)]
        # // need more

    async def gather_techniques(self, report, host):
        if host not in report.hosts:
            return []
        host_vulnerabilities = report.hosts[host].cves
        available_techniques = [t for cve in host_vulnerabilities for t in await self.data_svc.locate('abilities', match=dict(cve=cve)) or []]
        return available_techniques

    async def find_paths(self, report, start, end, path=None, avoid=None):
        path = path or []
        path.append(start)
        if start == end:
            return [path]
        if start not in report.network_map:
            return None
        paths = []
        for next_host in report.network_map[start]:
            if not report.hosts[next_host].cves or next_host in path or next_host in avoid:
                continue
            next_paths = self.find_paths(report, next_host, end, path)
            [paths.append(next_path) for next_path in next_paths]
        return paths

    @staticmethod
    def load_parsers():
        parsers = {}
        for filepath in glob.iglob('plugins/pathfinder/app/parsers/*.py'):
            module = import_module(filepath.replace('/', '.').replace('\\', '.').replace('.py', ''))
            p = module.ReportParser()
            parsers[p.format] = p
        return parsers


