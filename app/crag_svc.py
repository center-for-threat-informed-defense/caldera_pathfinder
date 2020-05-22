import os
import glob
import logging
from importlib import import_module

from app.utility.base_world import BaseWorld
from app.objects.c_source import Source
from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship

temp_file = 'plugins/crag/data/_temp_report_file.tmp'

class CragService:
    def __init__(self, services):
        self.services = services
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.log = logging.getLogger('crag_svc')
        self.parsers = self.load_parsers()

    async def import_scan(self, scan_format, report):
        # grab and decrypt the file contents and crate a file object to pass to the parser
        try:
            _, contents = await self.file_svc.read_file(report, location='reports')
            open(temp_file, 'wb').write(contents)
            parsed_report = self.parsers[scan_format].parse(temp_file)
            return await self.create_source(parsed_report)
        finally:
            os.remove(temp_file)

    async def create_source(self, report):
        def add_fact(fact_list, trait, value):
            fact_list.append(Fact(trait, value, collected_by='CRAG'))
            return fact_list[-1:][0]

        if not report:
            return None, None
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
        return source.name, source.id



    @staticmethod
    def load_parsers():
        parsers = {}
        for filepath in glob.iglob('plugins/crag/app/parsers/*.py'):
            module = import_module(filepath.replace('/', '.').replace('\\', '.').replace('.py', ''))
            p = module.ReportParser()
            parsers[p.format] = p
        return parsers


