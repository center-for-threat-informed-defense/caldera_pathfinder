from app.utility.base_world import BaseWorld
from plugins.crag.app.crag_gui import CragGui

name = 'CRAG'
description = 'CALDERA Rapid Attack Grapher'
address = '/plugin/crag/gui'
access = BaseWorld.Access.RED


async def enable(services):
    app = services.get('app_svc').application
    nmap_installed = await services.get('app_svc').validate_requirement('nmap', dict(type='installed_program', command='nmap --version', version='0.0.0'))
    await services.get('data_svc').apply('vulnerabilityreports')
    crag_gui = CragGui(services, nmap_installed)
    app.router.add_static('/crag', 'plugins/crag/static/', append_version=True)
    app.router.add_route('GET', '/plugin/crag/gui', crag_gui.splash)
    app.router.add_route('GET', '/plugin/crag/graph', crag_gui.graph)
    app.router.add_route('*', '/plugin/crag/api', crag_gui.crag_core)
    app.router.add_route('POST', '/plugin/crag/upload', crag_gui.store_report)
