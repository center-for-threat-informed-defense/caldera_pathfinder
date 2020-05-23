import os
import socket
import logging
import asyncio
from aiohttp import web
from aiohttp_jinja2 import template
from datetime import date

from app.service.auth_svc import check_authorization
from app.utility.base_world import BaseWorld

from plugins.crag.app.crag_svc import CragService
from plugins.crag.scanners.nmap.scanner import Scanner


class CragGui(BaseWorld):

    def __init__(self, services, nmap_installed):
        self.services = services
        self.auth_svc = services.get('auth_svc')
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.nmap_installed = 1 if nmap_installed else 0
        self.crag_svc = CragService(services)
        self.log = logging.getLogger('crag_gui')
        self.loop = asyncio.get_event_loop()
        self.running_scans = dict()

    @check_authorization
    @template('crag.html')
    async def splash(self, request):
        reports = [vr.display for vr in await self.data_svc.locate('vulnerabilityreports')]
        return dict(nmap=self.nmap_installed, input_parsers=self.crag_svc.parsers.keys(), machine_ip=self.get_machine_ip(), vulnerability_reports=reports)

    @check_authorization
    @template('graph.html')
    async def graph(self, request):
        requested_report = request.query.get('report')
        report = await self.data_svc.locate('vulnerabilityreports', match=dict(name=requested_report))

        return dict(vulnerability_reports=report.display)

    @check_authorization
    async def crag_core(self, request):
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
                return web.HTTPBadRequest(text='index: %s is not a valid index for the crag plugin' % index)
            return web.json_response(await options[request.method][index](data))
        except Exception as e:
            self.log.error(repr(e), exc_info=True)

    async def scan(self, data):
        target = data.pop('target', None) or self.get_machine_ip()
        report_file = 'plugins/crag/data/reports/%s_%s.xml' % (target.replace('.', '_').replace('/', '-'), date.today().strftime("%b-%d-%Y"))
        self.log.debug('scanning %s' % target)
        try:
            self.running_scans[target] = Scanner(filename=report_file, target_specification=target)
            self.loop.create_task(self.running_scans[target].scan())
            return dict(status='pass', output='scan initiated, depending on scope it may take a few minutes')
        except Exception as e:
            return dict(status='fail', output='exception occurred while starting scan')

    async def import_report(self, data):
        scan_type = data.get('format')
        report_name = data.get('filename')
        source, source_id = await self.crag_svc.import_scan(scan_type, report_name)
        if source:
            return dict(status='pass', output='source: %s' % source, source=source_id)
        return dict(status='fail', output='failure occurred during report importing, please check server logs')

    async def retrieve_reports(self):
        reports = [vr.display for vr in await self.data_svc.locate('vulnerabilityreports')]
        return dict(reports=reports)

    async def check_scan_status(self):
        pending = [s.target_specification for s in self.running_scans.values() if s.status != 'done']
        finished = dict()
        for target in [t for t in self.running_scans.keys() if self.running_scans[t].status == 'done']:
            scan = self.running_scans.pop(target)
            if not scan.returncode:
                source, source_id = await self.crag_svc.import_scan('nmap', os.path.basename(scan.filename))
                finished[scan.target_specification] = dict(source=source, source_id=source_id)

        return dict(pending=pending, finished=finished)

    @check_authorization
    async def store_report(self, request):
        return await self.file_svc.save_multipart_file_upload(request, 'plugins/crag/data/reports')

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
