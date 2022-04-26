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
    
    async def generate_path_analysis_report(self, vuln_report, start, target, whitelist: list, blacklist: list):  
        """
        """
        r = dict()
        r['exploitability_graph'] = await self.generate_exploitability_graph(vuln_report, whitelist, blacklist)
        r['exploitability_paths'] = await self.generate_exploitable_paths(vuln_report, r['exploitability_graph'], start, target)
        return r

    async def generate_exploitability_graph(self, report, whitelist, blacklist):
        """
            Explores and evaluates the nodes and edges of the report.network map. Removes any nodes that are on the blacklist or 
            do not have any abilities that provide lateral movement.

        Args:
            report (): Caldera vulnerability report
            whitelist (): list of nodes that are known owned or are considered freebies
            blacklist (): list of nodes that should not be used during exploitability analysis
        Returns
            (NetworkX Graph)

        """ 
        exploit_map = nx.DiGraph()
        for node in report.network_map.nodes:
            report_node = report.retrieve_host_by_id(node)
            if await self._is_edge_exploitable(report, report_node, whitelist, blacklist):
                exploit_map.add_node(report_node)
            
        for edge_ in report.network_map.edges:
            source_node = report.retrieve_host_by_id(edge_[0])
            target_node = report.retrieve_host_by_id(edge_[1])
            if source_node in exploit_map.nodes and target_node in exploit_map.nodes:
                exploit_map.add_edge(source_node, target_node)
                exploit_map.add_edge(target_node, source_node)
        return exploit_map

    async def _is_edge_exploitable(self, report, candidate, whitelist, blacklist):
            """
                Determines if candidate node is exploitable. Exploitability on the
                target node is defined as obtaining presence (either normal or privileged access) on the
                candidate node.
            Args:
                candidate (): target node to determine exploitability to
            Returns: 
                (bool)
            """
            if not candidate.can_access():
                return False
            if candidate.is_denied():
                return False
            if candidate in blacklist:
                return False
            if candidate.freebie_abilities:
                return True
            if candidate.cves and await self.get_host_exploits(report, candidate):
                return True
            if candidate in whitelist:
                return True
            # Defaults to true since we want to mark nodes that aren't offlimits as a freebie potentially (in generate_exp_paths)
            return True

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
        for path in paths:
            adv = await self.create_adversary_from_path(report, path)
            path = await self.jsonify_path(path)
            ret.append(dict(path=path, adversary = adv, probability = self.calc_adversary_probability(adv)))
        return ret

    async def create_adversary_from_path(self, report, path):
        """Create an adversary prototype(list) based on the given path. If the path has
        missing abilities, just mark requried steps as freebies. Thus this will create real
        adversary if possible, if not it will create an incomplete prototype.
            Old plan:
            [
            "3aad5312-d48b-4206-9de4-39866c12e60f",
            "3aad5312-d48b-4206-9de4-39866c12e60f",
            (AbilityFreebie, "3aad5312-d48b-4206-9de4-39866c12e60f"),
            "3aad5312-d48b-4206-9de4-39866c12e60f",
            (NodeFreebie, ""),
            (AbilityProbabilistic, "3aad5312-d48b-4206-9de4-39866c12e60f", .3)
            ]
            Kyle's plan:
            {
                "nodeA":['abilityA', 'abilityD'],
                "nodeB":['abilityB'],
                "nodeD":['nodeFreebie']
                "nodeC":['abilityC', 'abilityE'],
            }
        """
        adversary = dict()
        for node in path:
            techniques = await self.gather_techniques(report, targeted_host=node)
            if not techniques:
                adversary[node.hostname] = [("abilityFreebie", 1)]
            else:
                for tech in techniques:
                    adversary[node.hostname] = [(tech, .9)] #getattr(tech, 'probability', .9)
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
        if path:
            # path[1:] because the first node is assumed to be under control already.
            return [t for h in path[1:] for t in await self.get_host_exploits(report, h)]
        else:
            return await self.get_host_exploits(report, targeted_host)
    
    async def get_host_exploits(self, report, host):
            if host not in report.hosts:
                return []
            host_vulnerabilities = report.hosts[host].cves
            available_techniques = await self.collect_tagged_abilities(
                host_vulnerabilities
            )
            return available_techniques

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
    
    def calc_adversary_probability(self, adv):
        prob = 0.75
        for node_ability in adv.values():
            node_prob = 1.0
            for ability in node_ability:
                node_prob = node_prob * ability[1]
        return prob
    
    async def jsonify_path(self, path):
        path = [await self.jsonify_host(node) for node in path]
        return path
    
    async def jsonify_host(self, node):
        temp = node.__dict__
        if getattr(node, '_access') and not isinstance(temp['_access'],int):
            temp['_access'] = node._access.__dict__
        if getattr(node, 'os') and not isinstance(temp['os'], dict):
            temp['os'] = node.os.__dict__
            temp['os']['_access'] = temp['os']['_access'].__dict__
        if getattr(node, 'software'):
            temp['software'] = [soft.__dict__ for soft in node.software if not isinstance(soft, dict)]
        return temp

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
