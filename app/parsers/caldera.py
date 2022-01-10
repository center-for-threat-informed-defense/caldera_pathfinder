import logging
import networkx as nx
from collections import defaultdict

from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.interfaces.i_parser import ParserInterface


class ReportParser(ParserInterface):
    def __init__(self):
        self.format = 'caldera'
        self.log = logging.getLogger('caldera parser')

    def parse(self, report, name=None):
        try:
            caldera_report = VulnerabilityReport.load(BaseWorld.strip_yml(report)[0])
            self.generate_network_map(caldera_report)
            return caldera_report
        except ValidationError as err:
            print(err.messages)  
            print(err.valid_data)
            return None
        except Exception as e:
            self.log.error('exception when loading caldera report: %s' % repr(e))
            return None

    def generate_network_map(self, report):
        network_map = nx.Graph()
        for key,value in report.hosts.items():
            network_map.add_node(value.hostname)
            for h2 in report.hosts.values():
                if h2 != value:
                    network_map.add_edge(value.hostname, h2.hostname)
        report.network_map = network_map
