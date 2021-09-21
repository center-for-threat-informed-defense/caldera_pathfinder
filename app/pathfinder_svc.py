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
import plugins.pathfinder.app.enrichment.cve as cve


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
            parsed_report = self.enrich_report(parsed_report)
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

    async def generate_adversary(self, report, initial_host, target_host, tags=None):
        def retrieve_shortest_path(paths):
            shortest = paths[0]
            for path in paths:
                if len(path) < len(shortest):
                    shortest = path
            return shortest

        async def create_cve_adversary(techniques, tags):
            adv_id = uuid.uuid4()
            obj_default = (await self.data_svc.locate('objectives', match=dict(name='default')))[0]
            return dict(id=str(adv_id), name='pathfinder adversary', description='auto generated adversary for pathfinder',
                        atomic_ordering=techniques, tags=tags, objective=obj_default.id)

        def get_all_tags(objlist):
            return [t for a in objlist for t in a.tags]

        attack_paths = await self.find_paths(report, initial_host, target_host)
        shortest_path = retrieve_shortest_path(attack_paths)
        technique_list = await self.gather_techniques(report, path=shortest_path)
        implemented_cves = [c for h in shortest_path[1:] for c in report.hosts[h].cves if c in get_all_tags(technique_list)]
        adv = await create_cve_adversary([t.ability_id for t in technique_list], implemented_cves)

        if tags:
            tagged_adversaries = await self.collect_tagged_adversaries([t.strip() for t in tags.split(',')])
            adv['atomic_ordering'] = await self.join_adversary_abilities(adv, *tagged_adversaries)
            adv['tags'].extend([t for a in tagged_adversaries for t in a['tags'] if t in tags])
        await self.save_adversary(adv)
        return shortest_path, adv['id']

    @staticmethod
    async def join_adversary_abilities(*args):
        return [a for arg in args for a in arg.get('atomic_ordering')]

    async def save_adversary(self, adversary):
        folder_path = '%s/adversaries/' % settings.data_dir
        file = os.path.join(folder_path, '%s.yml' % adversary['id'])
        with open(file, 'w+') as f:
            f.seek(0)
            f.write(yaml.dump(adversary))
            f.truncate()
        await self.data_svc.reload_data()

    async def gather_techniques(self, report, targetedhost=None, path=None):
        async def get_host_exploits(host):
            if host not in report.hosts:
                return []
            host_vulnerabilities = report.hosts[host].cves
            available_techniques = await self.collect_tagged_abilities(host_vulnerabilities)
            return available_techniques

        if path:
            return [t for h in path[1:] for t in await get_host_exploits(h)]
        else:
            return get_host_exploits(targetedhost)

    async def collect_tagged_abilities(self, ability_tags):
        return [a for tag in ability_tags for a in await self.data_svc.search(tag, 'abilities') or []]

    async def collect_tagged_adversaries(self, adversary_tags):
        return [a.display for tag in adversary_tags for a in await self.data_svc.search(tag, 'adversaries') or []]

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
            if next_host in path: #not report.hosts[next_host].cves or next_host in path or next_host in avoid:
                continue
            next_paths = await self.find_paths(report, next_host, end, path)
            [paths.append(next_path) for next_path in next_paths if next_path]
        return paths

    def enrich_report(self, report):
        for key, host in report.hosts.items():
            for soft in host.software:
                try:
                    cves = cve.keyword_cve(soft.subtype)
                except Exception as e:
                    continue
                ids = [cve.id for cve in cves]
                if len(ids) != 0:
                    host.cves.append(ids)
            if host.os:
                try:
                    cves = cve.keyword_cve(host.os.os_type)
                except Exception as e:
                    continue
                ids = [cve.id for cve in cves]
                if len(ids) != 0:
                    host.cves.append(ids)
        report.hosts[key] = host
        return report

    @staticmethod
    def load_parsers():
        parsers = {}
        for filepath in glob.iglob('plugins/pathfinder/app/parsers/*.py'):
            module = import_module(filepath.replace('/', '.').replace('\\', '.').replace('.py', ''))
            p = module.ReportParser()
            parsers[p.format] = p
        return parsers


