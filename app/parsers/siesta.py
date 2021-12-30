import json
import logging
from collections import defaultdict

from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.objects.secondclass.c_host import Host
from plugins.pathfinder.app.objects.secondclass.c_port import Port
from plugins.pathfinder.app.interfaces.i_parser import ParserInterface


class ReportParser(ParserInterface):
    def __init__(self):
        self.format = 'siesta'
        self.log = logging.getLogger('siesta parser')

    def parse(self, report):
        try:
            with open(report, 'r') as f:
                siesta_report = json.load(f)
            caldera_report = self.parse_json_report(siesta_report)
            self.generate_network_map(caldera_report)
        except Exception as e:
            self.log.error('exception when parsing siesta report: %s' % repr(e))
            return None

        return caldera_report

    def parse_json_report(self, siesta_report):
        report = VulnerabilityReport()
        hosts = siesta_report['facts']['components']
        all_ports = siesta_report['facts']['ports']
        all_vulnerabilities = siesta_report['facts']['vulnerabilities']
        for h in hosts:
            host = Host(h['target'], hostname=h['host_name'])
            ports = [p for p in all_ports if p['target'] == host.ip]
            for p in ports:
                port = Port(
                    p['port_number'],
                    protocol=p['protocol'],
                    service=p['service'],
                    state=p['port_state'],
                )
                vulnerabilities = [
                    v
                    for v in all_vulnerabilities
                    if v['target'] == host.ip and v['port_number'] == port.number
                ]
                for v in vulnerabilities:
                    if v['severity'] != '0 - info':
                        port.cves.append(v['check_id'])
                        host.cves.append(v['check_id'])
                host.ports[port.number] = port
            report.hosts[host.ip] = host
        return report

    def generate_network_map(self, report):
        report_hosts_values = report.hosts.values()
        network_map = nx.Graph()
        for host in report_hosts_values:
            network_map.add_node(host.hostname)
            if report.hosts[host].ports:
                network_map.add_edge(host.hostname, h2.hostname) for h2 in report_hosts_values if h2 != host

        report.network_map = network_map
