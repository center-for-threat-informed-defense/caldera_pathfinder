import json
import logging
from aiohttp import web
from aiohttp_jinja2 import template

from app.service.auth_svc import check_authorization
from app.utility.base_world import BaseWorld

from plugins.crag.app.crag_svc import CragService
from plugins.crag.nmap.nmap_svc import NmapService


class CragGui(BaseWorld):

    def __init__(self, services, nmap_installed):
        self.services = services
        self.auth_svc = services.get('auth_svc')
        self.file_svc = services.get('file_svc')
        self.nmap_installed = 1 if nmap_installed else 0
        self.crag_svc = CragService(services)
        self.nmap_svc = NmapService(services)
        self.log = logging.getLogger('crag_gui')

    @check_authorization
    @template('crag.html')
    async def splash(self, request):
        return dict(nmap=self.nmap_installed, input_parsers=self.crag_svc.parsers.keys())

    @check_authorization
    async def crag_core(self, request):
        try:
            data = dict(await request.json())
            index = data.pop('index')
            options = dict(
                DELETE=dict(),
                PUT=dict(),
                POST=dict(
                    scan=lambda d: self.scan(),
                    import_scan=lambda d: self.import_report(d)
                )
            )
            if index not in options[request.method]:
                return web.HTTPBadRequest(text='index: %s is not a valid index for the crag plugin' % index)
            return web.json_response(await options[request.method][index](data))
        except Exception as e:
            self.log.error(repr(e), exc_info=True)

    async def scan(self):
        report = await self.nmap_svc.generate_report()
        await self.crag_svc.import_scan('nmap', report)
        return dict(output=json.dumps(report, indent=4))

    async def import_report(self, data):
        self.log.debug(json.dumps(data))
        scan_type = data.get('format')
        report_name = data.get('filename')
        return dict(output=await self.crag_svc.import_scan(scan_type, report_name))

    @check_authorization
    async def store_report(self, request):
        return await self.file_svc.save_multipart_file_upload(request, 'plugins/crag/data/reports/')
