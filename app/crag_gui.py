import json
import logging
from aiohttp import web
from aiohttp_jinja2 import template

from app.service.auth_svc import check_authorization
from app.utility.base_world import BaseWorld

from plugins.crag.app.crag_svc import CragService


class CragGui(BaseWorld):

    def __init__(self, services, nmap_installed):
        self.services = services
        self.auth_svc = services.get('auth_svc')
        self.nmap_installed = 1 if nmap_installed else 0
        self.crag_svc = CragService(services)
        self.log = logging.getLogger('crag_gui')

    @check_authorization
    @template('crag.html')
    async def splash(self, request):
        return dict(nmap=self.nmap_installed, input_parsers=[dict(name='nmap'), dict(name='nessus'), dict(name='siesta')])

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
                    import_scan=lambda d: self.import_scan(d)
                )
            )
            if index not in options[request.method]:
                return web.HTTPBadRequest(text='index: %s is not a valid index for the crag plugin' % index)
            return web.json_response(await options[request.method][index](data))
        except Exception as e:
            self.log.error(repr(e), exc_info=True)

    async def scan(self):
        return dict(output=json.dumps(await self.crag_svc.scan_network(), indent=4))

    async def import_scan(self, data):
        self.log.debug(json.dumps(data))
        scan_type = data.get('format')
        report = data.get('file')
        return dict(output=await self.crag_svc.import_scan(scan_type, report))

