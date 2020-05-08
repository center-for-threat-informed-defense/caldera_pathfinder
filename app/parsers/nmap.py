import re
import logging
import xml.etree.ElementTree as ET

from plugins.crag.app.objects.c_report import VulnerabilityReport
from plugins.crag.app.objects.secondclass.c_host import Host
from plugins.crag.app.objects.secondclass.c_port import Port


class ReportParser:

    def __init__(self):
        self.format = 'nmap'
        self.log = logging.getLogger('nmap parser')

    def parse(self, report):
        caldera_report = VulnerabilityReport()
        try:
            xml_report = ET.parse(report)
            root = xml_report.getroot()
        except Exception as e:
            self.log.error('exception when parsing nmap results xml: %s' % repr(e))
            return None

        self.parse_xml_report(root, caldera_report)
        # caldera_report.hosts = [self.parse_host(section) for section in self.separate_hosts(report)]
        return caldera_report

    def separate_hosts(self, report):
        return ['section']

    def parse_host(self, section):
        host = Host('192.168.1.1')
        return host

    def parse_xml_report(self, root, report):
        for host in root.findall('host'):
            report_host = Host(host.find('address').get('addr'))
            self.log.debug(report_host.ip)
            if host.find('hostnames') is not None:
                if host.find('hostnames').find('hostname') is not None:
                    report_host.hostname = host.find('hostnames').find('hostname').get('name')
                    self.log.debug(report_host.hostname)
            for port in host.find('ports').findall('port'):
                report_port = Port(port.get('portid'), '')
                report_port.protocol = port.get('protocol', '')
                self.log.debug(f'{report_port.protocol}:{report_port.number}')
                if port.find('service') is not None:
                    if port.find('service').get('name') is not None:
                        report_port.service = port.find('service').get('name')
                        self.log.debug(report_port.service)
                    if port.find('service').get('product') is not None:
                        report_port.product = port.find('service').get('product')
                        self.log.debug(report_port.product)
                    if port.find('service').get('version') is not None:
                        report_port.version = port.find('service').get('version')
                        self.log.debug(report_port.version)
                report_host.ports.append(report_port)
            report.hosts.append(report_host)
        return report
