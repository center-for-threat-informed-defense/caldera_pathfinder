import logging

from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.interfaces.i_parser import ParserInterface


class ReportParser(ParserInterface):

    def __init__(self):
        self.format = 'caldera'
        self.log = logging.getLogger('caldera parser')

    def parse(self, report):
        try:
            caldera_report = VulnerabilityReport.load(BaseWorld.strip_yml(report)[0])
            return caldera_report
        except Exception as e:
            self.log.error('exception when loading caldera report: %s' % repr(e))
            return None
