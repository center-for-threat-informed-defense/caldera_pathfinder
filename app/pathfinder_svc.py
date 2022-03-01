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
from plugins.pathfinder.app.objects.c_cve import CVE

import networkx as nx


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
                relationships.append(
                    Relationship(
                        ip_fact,
                        'has_hostname',
                        add_fact(facts, 'scan.host.hostname', host.hostname),
                    )
                )
            for num, port in host.ports.items():
                port_fact = add_fact(facts, 'scan.host.port', num)
                for cve in port.cves:
                    cve_fact = add_fact(facts, 'scan.found.cve', cve)
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
    
    async def generate_path_analysis_report(self, vuln_report, start, target):  
        """
        """
        r = dict()
        r['exploitability_graph'] = await self.generate_exploitability_graph(vuln_report)
        # print(r['exploitability_graph'].nodes,r['exploitability_graph'].edges)
        r['exploitability_paths'] = await self.generate_exploitable_paths(vuln_report, r['exploitability_graph'], start, target)
        return r

    async def generate_exploitability_graph(self, report):
        """"""
        def _is_edge_exploitable(owned, candidate):
            """
                Determines if candidate node is exploitable from current node. Exploitability on the
                target node is defined as obtaining presence (either normal or privileged access) on the
                candidate node.
            Args:
                owned (): source node to determine exploitability from
                candidate (): target node to determine exploitability to
            Returns: 
                (bool)
            """
            # Steps:
            # - Is candidate node/ability a freebie?
            # - return True
            # - Is candidate node/ability probabalistic?
            # - return True
            # - Is candidate node/ability blacklisted?
            # - return False
            # - Does current node have an ability to laterally move to the candidate node? Or does it have a probabilitic 
            # - If lateral movement ability present, are pre conditions met to use it?
            # - return True
            if candidate.is_denied():
                return False
            if not candidate.can_access():
                return False
            if candidate.freebie_abilities:
                return True
            if candidate.cves:
                return True
            return False

        exploit_map = nx.Graph()
        for edge_ in report.network_map.edges:
            source_node = report.retrieve_host_by_id(edge_[0])
            target_node = report.retrieve_host_by_id(edge_[1])
            if _is_edge_exploitable(source_node, target_node):
                exploit_map.add_node(source_node)
                exploit_map.add_node(target_node)
                exploit_map.add_edge(source_node, target_node)
        return exploit_map

    async def generate_exploitable_paths(self, report, exploitability_graph, source, target):
        """Find all paths from source to target for the given exploitability graph.
        Args:
            exploitability_graph (networkx.Graph)
            source (node):
            target (node):
        Returns: 
            (generator) list of paths
        """
        ret = list()
        for node in [source, target]:
            if (report.retrieve_host_by_id(node) not in exploitability_graph.nodes):
                return None
        paths = nx.all_simple_paths(exploitability_graph, report.retrieve_host_by_id(source), report.retrieve_host_by_id(target))
        # create adversaries for every path
        for path in paths:
            ret.append(dict(path=path, adversary= await self.create_adversary_from_path(report, path)))
        return ret

    async def create_adversary_from_path(self, report, path):
        """Create an adversary prototype(list) based on the given path. If the path has
        missing abilities, just mark requried steps as freebies. Thus this will create real
        adversary if possible, if not it will create an incomplete prototype.
            [
            "3aad5312-d48b-4206-9de4-39866c12e60f",
            "3aad5312-d48b-4206-9de4-39866c12e60f",
            (AbilityFreebie, "3aad5312-d48b-4206-9de4-39866c12e60f"),
            "3aad5312-d48b-4206-9de4-39866c12e60f",
            (NodeFreebie, ""),
            (AbilityProbabilistic, "3aad5312-d48b-4206-9de4-39866c12e60f", .3)
            ]
        """
        adversary = dict()
        for node in path:
            adversary[node] = await self.gather_techniques(report, targeted_host=node)
        return adversary

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

    async def gather_techniques(self, report, targeted_host=None, path=None):
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
            return await get_host_exploits(targeted_host)

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

    def enrich_report(self, report):
        for key, host in report.hosts.items():
            if host.software:
                cves = self.software_enrich(host.software)
                if cves:
                    host.cves.append(cves)
            if host.os:
                cves = self.host_enrich(host.os)
                if cves:
                    host.cves.append(cves)
        report.hosts[key] = host
        return report

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
