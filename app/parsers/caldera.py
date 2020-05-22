import os
import logging

from app.utility.base_world import BaseWorld
from plugins.crag.app.objects.c_report import VulnerabilityReport


class ReportParser:

    def __init__(self):
        self.format = 'caldera'
        self.log = logging.getLogger('caldera parser')

    def parse(self, report):
        try:
            open('_tempreport.yml', 'w').write(report.read())
            caldera_report = VulnerabilityReport.load(BaseWorld.strip_yml('_tempreport.yml'))  # need to fix this as we get a file object, not a path
            os.remove('_tempreport.yml')
            return caldera_report
        except Exception as e:
            self.log.error('exception when loading caldera report: %s' % repr(e))
            return None
