import os
import glob
from sre_constants import SUCCESS
import uuid
import yaml
import logging
from importlib import import_module

import networkx as nx

from app.utility.base_world import BaseWorld
from app.objects.c_source import Source
from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from plugins.pathfinder.app.objects.secondclass.c_host import Ability
from plugins.pathfinder.app.objects.c_cve import CVE
import plugins.pathfinder.settings as settings
import plugins.pathfinder.app.enrichment.cve as cve


DEFAULT_SUCCESS_PROB = 0.8
DEFAULT_LATERAL_MOVEMENT_MATCH = {
    'tactic': 'lateral-movement',
    'technique_id': 'T1570',
    }
DEFAULT_FREEBIE_MATCH = {
    'tactic': 'initial-access'
}


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
            parsed_report = self.parsers[scan_format].parse(temp_file, name=report)
            parsed_report = await self.enrich_report(parsed_report)
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
                relationships.append(
                    Relationship(
                        ip_fact,
                        'has_hostname',
                        add_fact(facts, 'scan.host.hostname', host.hostname),
                    )
                )
            for num, port in host.ports.items():
                port_fact = add_fact(facts, 'scan.host.port', num)
                for cve_ in port.cves:
                    cve_fact = add_fact(facts, 'scan.found.cve', cve_)
                    relationships.append(
                        Relationship(ip_fact, 'has_vulnerability', cve_fact)
                    )
                    relationships.append(
                        Relationship(port_fact, 'has_vulnerability', cve_fact)
                    )
        source = Source(report.id, report.name, facts, relationships)
        source.access = BaseWorld.Access.RED
        await self.data_svc.store(source)
        return source

    async def generate_adversary(self, report, initial_host, target_host, tags=None):
        async def create_cve_adversary(techniques, tags):
            adv_id = uuid.uuid4()
            obj_default = (
                await self.data_svc.locate('objectives', match=dict(name='default'))
            )[0]
            return dict(
                id=str(adv_id),
                name='pathfinder adversary',
                description='auto generated adversary for pathfinder',
                atomic_ordering=techniques,
                tags=tags,
                objective=obj_default.id,
            )

        def get_all_tags(objlist):
            return [t for a in objlist for t in a.tags]

        shortest_path = nx.shortest_path(report.network_map, initial_host, target_host)
        technique_list = await self.gather_techniques(report, path=shortest_path)
        implemented_cves = [
            c
            for h in shortest_path[1:]
            for c in report.hosts[h].cves
            if c in get_all_tags(technique_list)
        ]
        adv = await create_cve_adversary(
            [t.ability_id for t in technique_list], implemented_cves
        )

        if tags:
            tagged_adversaries = await self.collect_tagged_adversaries(
                [t.strip() for t in tags.split(',')]
            )
            adv['atomic_ordering'] = await self.join_adversary_abilities(
                adv, *tagged_adversaries
            )
            adv['tags'].extend(
                [t for a in tagged_adversaries for t in a['tags'] if t in tags]
            )
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
            available_techniques = await self.collect_tagged_abilities(
                host_vulnerabilities
            )
            return available_techniques

        if path:
            # path[1:] because the first node is assumed to be under control already.
            return [t for h in path[1:] for t in await get_host_exploits(h)]
        else:
            return get_host_exploits(targetedhost)

    async def collect_tagged_abilities(self, ability_tags):
        """
        Args:
            ability_tags (list): CVE IDs
        """
        return [
            a
            for tag in ability_tags
            for a in await self.data_svc.search(tag, 'abilities') or []
        ]

    async def collect_tagged_adversaries(self, adversary_tags):
        return [
            a.display
            for tag in adversary_tags
            for a in await self.data_svc.search(tag, 'adversaries') or []
        ]

    async def enrich_report(self, report):  # adapted for better vuln report
        for key, host in report.hosts.items():
            if host.os:
                os_type = host.os.os_type
                os_type = os_type.lower()
                if os_type in ['linux', 'windows', 'debian']:
                    executor = os_type
                    lm_abilities = await self.get_access_abilities(executor=executor) or self.get_freebie_abilities(executor=executor)
                    lm_objs = [Ability(uuid=a.ability_id, success_prob=DEFAULT_SUCCESS_PROB) for a in lm_abilities]
                    host.possible_abilities = lm_objs
                else:
                    continue
            report.hosts[key] = host
        return report

    def _has_executor(self, ability, executor):
        if not ability.executors:
            return False
        else:
            for potential_executor in ability.executors:
                if potential_executor.platform == executor:
                    return True
            return False

    async def get_access_abilities(self, executor: str = 'windows'):
        lm_abilities = await self.data_svc.locate('abilities', match=DEFAULT_LATERAL_MOVEMENT_MATCH)
        lm_abilities = [a for a in lm_abilities if self._has_executor(a, executor)]
        return lm_abilities
    
    async def get_freebie_abilities(self, executor: str = 'windows'):
        fb_abilities = await self.data_svc.locate('abilities', match=DEFAULT_FREEBIE_MATCH)
        fb_abilities = [a for a in fb_abilities if self._has_executor(a, executor)]
        return fb_abilities

    def software_enrich(self, software):
        exploits = []
        for soft in software:
            if soft.subtype:
                try:
                    cves = cve.keyword_cve(soft.subtype)
                except Exception as e:
                    self.log.error(f'exception when enriching: {repr(e)}')
                    continue
                ids = [cve.id for cve in cves]
                if ids:
                    exploits.append(ids)
        return exploits

    def host_enrich(self, os):
        exploits = []
        try:
            cves = cve.keyword_cve(os.os_type)
        except Exception as e:
            self.log.error(f'exception when enriching: {repr(e)}')
            return []
        ids = [cve.id for cve in cves if isinstance(cve, CVE)]
        if ids:
            exploits.append(ids)
        return exploits

    @staticmethod
    def load_parsers():
        parsers = {}
        for filepath in glob.iglob('plugins/pathfinder/app/parsers/*.py'):
            module = import_module(
                filepath.replace('/', '.').replace('\\', '.').replace('.py', '')
            )
            p = module.ReportParser()
            parsers[p.format] = p
        return parsers
