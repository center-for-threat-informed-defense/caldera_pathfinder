import os
import socket
import logging
import asyncio
from aiohttp import web
from aiohttp_jinja2 import template
from datetime import date

from app.service.auth_svc import check_authorization
from app.utility.base_world import BaseWorld

from plugins.pathfinder.app.pathfinder_svc import PathfinderService
from plugins.pathfinder.scanners.nmap.scanner import Scanner


class PathfinderGui(BaseWorld):

    def __init__(self, services, nmap_installed):
        self.services = services
        self.auth_svc = services.get('auth_svc')
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.nmap_installed = 1 if nmap_installed else 0
        self.pathfinder_svc = PathfinderService(services)
        self.log = logging.getLogger('pathfinder_gui')
        self.loop = asyncio.get_event_loop()
        self.running_scans = dict()

    @check_authorization
    @template('pathfinder.html')
    async def splash(self, request):
        reports = [vr.display for vr in await self.data_svc.locate('vulnerabilityreports')]
        return dict(nmap=self.nmap_installed, input_parsers=self.pathfinder_svc.parsers.keys(), machine_ip=self.get_machine_ip(), vulnerability_reports=reports)

    @check_authorization
    @template('graph.html')
    async def graph(self, request):
        requested_report = request.query.get('report')
        data = await self.build_visualization_dataset(requested_report)
        return dict(report_data=data)

    async def build_visualization_dataset(self, report):
        visualization_data = dict(nodes=[], links=[])
        vr = await self.data_svc.locate('vulnerabilityreports', match=dict(id=report))
        if not vr:
            return visualization_data

        scanner_node = 'scanner'
        visualization_data['nodes'].append(dict(id=scanner_node, group=1))
        for ip, host in vr[0].hosts.items():
            visualization_data['nodes'].append(dict(id=ip, group=2, ports=list(host.ports.keys())))
            visualization_data['links'].append(dict(source=scanner_node, target=ip, value=1))
            for cve in host.cves:
                visualization_data['nodes'].append(dict(id=cve, group=3))
                visualization_data['links'].append(dict(source=ip, target=cve, value=5))

        return visualization_data

    @check_authorization
    async def pathfinder_core(self, request):
        try:
            data = dict(await request.json())
            index = data.pop('index')
            options = dict(
                DELETE=dict(),
                PUT=dict(),
                POST=dict(
                    scan=lambda d: self.scan(d),
                    import_scan=lambda d: self.import_report(d),
                    reports=lambda d: self.retrieve_reports(),
                    status=lambda d: self.check_scan_status()
                )
            )
            if index not in options[request.method]:
                return web.HTTPBadRequest(text='index: %s is not a valid index for the pathfinder plugin' % index)
            return web.json_response(await options[request.method][index](data))
        except Exception as e:
            self.log.error(repr(e), exc_info=True)

    async def scan(self, data):
        target = data.pop('target', None) or self.get_machine_ip()
        report_file = 'plugins/pathfinder/data/reports/%s_%s.xml' % (target.replace('.', '_').replace('/', '-'), date.today().strftime("%b-%d-%Y"))
        self.log.debug('scanning %s' % target)
        try:
            self.running_scans[target] = Scanner(filename=report_file, target_specification=target)
            self.loop.create_task(self.running_scans[target].scan())
            return dict(status='pass', output='scan initiated, depending on scope it may take a few minutes')
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(status='fail', output='exception occurred while starting scan')

    async def import_report(self, data):
        scan_type = data.get('format')
        report_name = data.get('filename')
        source = await self.pathfinder_svc.import_scan(scan_type, report_name)
        if source:
            return dict(status='pass', output='source: %s' % source.name, source=source.id)
        return dict(status='fail', output='failure occurred during report importing, please check server logs')

    async def retrieve_reports(self):
        reports = [vr.display for vr in await self.data_svc.locate('vulnerabilityreports')]
        return dict(reports=reports)

    async def check_scan_status(self):
        pending = [s.target_specification for s in self.running_scans.values() if s.status != 'done']
        finished = dict()
        errors = dict()
        for target in [t for t in self.running_scans.keys() if self.running_scans[t].status == 'done']:
            scan = self.running_scans.pop(target)
            if not scan.returncode:
                source = await self.pathfinder_svc.import_scan('nmap', os.path.basename(scan.filename))
                finished[scan.target_specification] = dict(source=source.name, source_id=source.id)
            else:
                self.log.debug(scan.output['stderr'])
                errors[scan.target_specification] = dict(message=scan.output['stderr'])

        return dict(pending=pending, finished=finished, errors=errors)

    @check_authorization
    async def store_report(self, request):
        return await self.file_svc.save_multipart_file_upload(request, 'plugins/pathfinder/data/reports')

    @staticmethod
    def get_machine_ip():
        # this gets the exit IP, so if you are on a VPN it will get you the IP on the VPN network and not your local network IP
        def get_ip():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('10.255.255.255', 1))
                ip = s.getsockname()[0]
            except Exception:
                ip = '127.0.0.1'
            finally:
                s.close()
            return ip

        return get_ip()
