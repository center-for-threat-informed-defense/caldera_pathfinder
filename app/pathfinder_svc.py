import os
import glob
import uuid
import yaml
import logging
from importlib import import_module

from app.utility.base_world import BaseWorld
from app.objects.c_source import Source
from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from app.objects.c_adversary import Adversary
import plugins.pathfinder.settings as settings


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
            temp_file = '%s/_temp_report_file.tmp' % settings.data_dir
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
        technique_list = [t.ability_id for host in shortest_path[1:] for t in await self.gather_techniques(report, host)]
        cves = [c for h in shortest_path[1:] for c in report.hosts[h].cves]
        # create adversary
        adv_id = uuid.uuid4()
        obj_default = (await self.data_svc.locate('objectives', match=dict(name='default')))[0]
        adv = dict(id=str(adv_id), name='pathfinder adversary', description='auto generated adversary for pathfinder',
                   atomic_ordering=technique_list, tags=cves, objective=obj_default.id)
        await self.save_adversary(adv)
        return shortest_path, adv['id']

    async def save_adversary(self, adversary):
        folder_path = '%s/adversaries/' % settings.data_dir
        file = os.path.join(folder_path, '%s.yml' % adversary['id'])
        with open(file, 'w+') as f:
            f.seek(0)
            f.write(yaml.dump(adversary))
            f.truncate()
        await self.data_svc.reload_data()

    async def gather_techniques(self, report, host):
        if host not in report.hosts:
            return []
        host_vulnerabilities = report.hosts[host].cves
        available_techniques = [t for cve in host_vulnerabilities for t in await self.data_svc.search(cve, 'abilities') or []]
        available_adversaries = [t for cve in host_vulnerabilities for t in await self.data_svc.search(cve, 'adversaries') or []]
        return available_techniques

    async def find_paths(self, report, start, end, past=None, avoid=None):
        past = past or []
        path = list(past) + [start]
        avoid = avoid or []
        if start == end:
            return [path]
        if start not in report.network_map:
            return []
        paths = []
        for next_host in report.network_map[start]:
            if not report.hosts[next_host].cves or next_host in path or next_host in avoid:
                continue
            next_paths = await self.find_paths(report, next_host, end, path)
            [paths.append(next_path) for next_path in next_paths if next_path]
        return paths

    @staticmethod
    def load_parsers():
        parsers = {}
        for filepath in glob.iglob('plugins/pathfinder/app/parsers/*.py'):
            module = import_module(filepath.replace('/', '.').replace('\\', '.').replace('.py', ''))
            p = module.ReportParser()
            parsers[p.format] = p
        return parsers


