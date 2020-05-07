import re

from plugins.crag.app.objects.c_report import VulnerabilityReport
from plugins.crag.app.objects.secondclass.c_host import Host
from plugins.crag.app.objects.secondclass.c_port import Port


class ReportParser:

    def __init__(self):
        self.format = 'nmap'

    def parse(self, report):
        caldera_report = VulnerabilityReport()
        caldera_report.hosts = [self.parse_host(section) for section in self.separate_hosts(report)]
        return caldera_report

    def separate_hosts(self, report):
        return ['section']

    def parse_host(self, section):
        host = Host('192.168.1.1')
        return host

