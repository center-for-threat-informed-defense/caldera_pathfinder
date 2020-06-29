import os

from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.pathfinder_gui import PathfinderGui
import plugins.pathfinder.settings as settings

name = 'pathfinder'
description = 'CALDERA Rapid Attack Grapher'
address = '/plugin/%s/gui' % name
access = BaseWorld.Access.RED
data_dir = os.path.join('plugins', name, 'data')


async def enable(services):
    app = services.get('app_svc').application
    nmap_installed = await services.get('app_svc').validate_requirement('nmap', dict(type='installed_program', command='nmap --version', version='0.0.0'))
    await services.get('data_svc').apply('vulnerabilityreports')
    plugin_gui = PathfinderGui(services, nmap_installed)
    app.router.add_static('/%s' % name, 'plugins/%s/static/' % name, append_version=True)
    app.router.add_route('GET', '/plugin/%s/gui' % name, plugin_gui.splash)
    app.router.add_route('GET', '/plugin/%s/graph' % name, plugin_gui.graph)
    app.router.add_route('*', '/plugin/%s/api' % name, plugin_gui.pathfinder_core)
    app.router.add_route('POST', '/plugin/%s/upload' % name, plugin_gui.store_report)
    settings.init(dict(name=name, description=description, address=address, access=access, data_dir=data_dir))
