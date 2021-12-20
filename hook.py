import os

from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.pathfinder_gui import PathfinderGUI
import plugins.pathfinder.settings as settings

name = 'Pathfinder'
description = 'CALDERA Rapid Attack Grapher'
address = '/plugin/pathfinder/gui'
access = BaseWorld.Access.RED
data_dir = os.path.join('plugins', name, 'data')


async def enable(services):
    def init_dirs(dirs):
        for d in dirs:
            os.makedirs(d, exist_ok=True)
    app = services.get('app_svc').application
    nmap_installed = await services.get('app_svc').validate_requirement('nmap', dict(type='installed_program',
                                                                                     command='nmap --version',
                                                                                     version='0.0.0'))
    await services.get('data_svc').apply('vulnerabilityreports')
    pathfinder_gui = PathfinderGUI(services=services, name=name, description=description,  installed_dependencies=dict(nmap=nmap_installed))
    app.router.add_static('/pathfinder', 'plugins/pathfinder/static/', append_version=True)
    app.router.add_route('GET', '/plugin/pathfinder/gui', pathfinder_gui.splash)
    app.router.add_route('GET', '/plugin/pathfinder/graph', pathfinder_gui.graph)
    app.router.add_route('GET', '/plugin/pathfinder/download', pathfinder_gui.download_report)
    app.router.add_route('*', '/plugin/pathfinder/api', pathfinder_gui.pathfinder_core)
    app.router.add_route('POST', '/plugin/pathfinder/upload', pathfinder_gui.store_report)
    settings.init(dict(name=name, description=description, address=address, access=access, data_dir=data_dir))
    init_dirs([os.path.join(settings.data_dir, 'abilities'),
               os.path.join(settings.data_dir, 'adversaries'),
               os.path.join(settings.data_dir, 'reports')
               ])
