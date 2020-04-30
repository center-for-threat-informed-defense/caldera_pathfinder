from aiohttp_jinja2 import template

from app.service.auth_svc import check_authorization
from app.utility.base_world import BaseWorld


class CragGui(BaseWorld):

    def __init__(self, services, nmap_installed):
        self.services = services
        self.auth_svc = services.get('auth_svc')
        self.nmap_installed = nmap_installed

    @check_authorization
    @template('crag.html')
    async def splash(self, request):
        return dict(nmap=self.nmap_installed, input_parsers=[dict(name='nmap'), dict(name='nessus'), dict(name='siesta')])
