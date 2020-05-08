import io
import glob
import logging

from importlib import import_module


class CragService:
    def __init__(self, services):
        self.services = services
        self.file_svc = services.get('file_svc')
        self.log = logging.getLogger('crag_svc')
        self.parsers = self.load_parsers()

    async def import_scan(self, scan_format, report):
        # grab and decrypt the file contents and crate a file object to pass to the parser
        _, contents = await self.file_svc.read_file(report, location='reports')
        file = io.BytesIO(contents)
        parsed_report = self.parsers[scan_format].parse(file)
        await self.create_source(parsed_report)

    async def create_source(self, report):
        for host in report.hosts:
            pass

    @staticmethod
    def load_parsers():
        parsers = {}
        for filepath in glob.iglob('plugins/crag/app/parsers/*.py'):
            module = import_module(filepath.replace('/', '.').replace('\\', '.').replace('.py', ''))
            p = module.ReportParser()
            parsers[p.format] = p
        return parsers


