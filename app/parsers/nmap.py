import os
import re
import yaml
import logging
import argparse
import xml.etree.ElementTree as ET

from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.objects.secondclass.c_host import Host
from plugins.pathfinder.app.objects.secondclass.c_port import Port


class ReportParser:

    def __init__(self):
        self.format = 'nmap'
        self.log = logging.getLogger('nmap parser')

    def parse(self, report):
        caldera_report = VulnerabilityReport()
        try:
            xml_report = ET.parse(report)
            root = xml_report.getroot()
            self.parse_xml_report(root, caldera_report)
        except Exception as e:
            self.log.error('exception when parsing nmap results xml: %s' % repr(e))
            return None

        return caldera_report

    def parse_xml_report(self, root, report):
        cve_pattern = r'(CVE-\d{4}-\d{4,})'

        for host in root.findall('host'):
            cves = []
            report_host = Host(host.find('address').get('addr'))
            if host.find('hostnames') is not None:
                if host.find('hostnames').find('hostname') is not None:
                    report_host.hostname = host.find('hostnames').find('hostname').get('name')
            for port in host.find('ports').findall('port'):
                report_port = Port(port.get('portid'), '')
                report_port.protocol = port.get('protocol', '')
                port_service = port.find('service')
                if port_service is not None:
                    report_port.service = port_service.get('name')
                    report_port.product = port_service.get('product')
                    report_port.version = port_service.get('version')
                for script in port.findall('script'):
                    if script.get('output') is not None:
                        script_output = script.get('output')
                        port_cves = list(set(re.findall(cve_pattern, script_output)))
                        report_port.cves = port_cves
                        cves.extend(port_cves)
                report_host.ports[report_port.number] = report_port
            report_host.cves = cves
            report.hosts[report_host.ip] = report_host
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser('nmap xml report parser')
    parser.add_argument('-D', '--debug', action='store_const', required=False, const=logging.DEBUG, default=logging.INFO)
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=False)
    args = parser.parse_args()

    logging.basicConfig(level=args.debug)
    parser = ReportParser()
    report = parser.parse(args.filename)
    logging.info('parsed %s and produced output report: %s' % (os.path.basename(args.filename), report.name))
    if args.output:
        with open(args.output, 'w') as o:
            o.write(yaml.dump(report.display))
            logging.info('output report saved to: %s' % args.output)
    else:
        logging.info(yaml.dump(report.display))
