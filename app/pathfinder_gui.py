import os
import glob
import yaml
import logging
import asyncio
from aiohttp import web
from aiohttp_jinja2 import template
from datetime import date
from importlib import import_module

from app.service.auth_svc import for_all_public_methods, check_authorization
from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.pathfinder_svc import PathfinderService
from plugins.pathfinder.app.pathfinder_util import sanitize_filename
import plugins.pathfinder.settings as settings


@for_all_public_methods(check_authorization)
class PathfinderGUI(BaseWorld):
    def __init__(self, services, name, description, installed_dependencies):
        self.name = name
        self.description = description
        self.services = services
        self.installed_dependencies = installed_dependencies
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('pathfinder_gui')
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.loop = asyncio.get_event_loop()
        self.running_scans = dict()
        self.scanners = dict()
        self.pathfinder_svc = PathfinderService(services)

    async def _get_access(self, request):
        return dict(access=tuple(await self.auth_svc.get_permissions(request)))

    @template('pathfinder.html')
    async def splash(self, request):
        reports = [
            vr.display
            for vr in await self.data_svc.locate(
                'vulnerabilityreports', match=await self._get_access(request)
            )
        ]
        loaded_scanners = await self.load_scanners()
        self.scanners = loaded_scanners
        return dict(
            name=self.name,
            description=self.description,
            scanners=list(loaded_scanners.keys()),
            input_parsers=list(self.pathfinder_svc.parsers.keys()),
            vulnerability_reports=reports,
        )

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
        visualization_data['nodes'].append(
            dict(id=scanner_node, label='scanner', group='scanners')
        )
        for ip, host in vr[0].hosts.items():
            visualization_data['nodes'].append(dict(id=ip, label=ip, group='hosts'))
            for pnum, port in {
                pn: p for pn, p in host.ports.items() if p.state == 'open'
            }.items():
                id = '%s:%s' % (ip, pnum)
                visualization_data['nodes'].append(
                    dict(id=id, label=pnum, group='ports')
                )
                visualization_data['links'].append(
                    dict(source=ip, target=id, type='port')
                )
                for cve in port.cves:
                    id2 = '%s:%s' % (id, cve)
                    dim = (
                        False
                        if await self.pathfinder_svc.collect_tagged_abilities([cve])
                        != []
                        else True
                    )
                    visualization_data['nodes'].append(
                        dict(id=id2, label=cve, group='cves', dim=dim)
                    )
                    visualization_data['links'].append(
                        dict(source=id, target=id2, type='cve')
                    )
        for link in vr[0].network_map:
            for to_node in vr[0].network_map[link]:
                visualization_data['links'].append(
                    dict(source=link, target=to_node, type='network')
                )

        return visualization_data

    @check_authorization
    async def pathfinder_core(self, request):
        try:
            data = dict(await request.json())
            index = data.pop('index')
            options = dict(
                DELETE=dict(report=lambda d: self.delete_report(d)),
                PUT=dict(),
                POST=dict(
                    scan=lambda d: self.scan(d),
                    import_scan=lambda d: self.import_report(d),
                    reports=lambda d: self.retrieve_reports(),
                    status=lambda d: self.check_scan_status(),
                    create_adversary=lambda d: self.generate_adversary(d),
                    scanner_config=lambda d: self.return_scanner_configuration(d),
                    source_name=lambda d: self.get_source_name(d),
                ),
                PATCH=dict(report=lambda d: self.rename_report(d)),
            )
            if index not in options[request.method]:
                return web.HTTPBadRequest(
                    text='index: %s is not a valid index for the pathfinder plugin'
                    % index
                )
            return web.json_response(await options[request.method][index](data))
        except Exception as e:
            self.log.error(repr(e), exc_info=True)

    async def scan(self, data):
        scanner = data.pop('scanner', None)
        fields = data.pop('fields', None)
        filename = fields.pop('filename') or sanitize_filename(
            f'pathfinder_{date.today().strftime("%b-%d-%Y")}'
        )
        filename = filename.replace(' ', '_')
        report_file = f'{settings.data_dir}/reports/{filename}.xml'
        try:
            loaded_scanner = await self.load_scanner(scanner)
            scan = loaded_scanner.Scanner(
                filename=report_file, dependencies=self.installed_dependencies, **fields
            )
            self.running_scans[scan.id] = scan
            self.loop.create_task(scan.scan())
            return dict(
                status='pass',
                id=scan.id,
                output='scan initiated, depending on scope it may take a few minutes',
            )
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(status='fail', output='exception occurred while starting scan')

    async def import_report(self, data):
        scan_type = data.get('format')
        report_name = data.get('filename')
        source = await self.pathfinder_svc.import_scan(scan_type, report_name)
        if source:
            return dict(
                status='pass', output='source: %s' % source.name, source=source.id
            )
        return dict(
            status='fail',
            output='failure occurred during report importing, please check server logs',
        )

    async def rename_report(self, data):
        try:
            report_id = data.get('id')
            report = await self.data_svc.locate(
                'vulnerabilityreports', match=dict(id=report_id)
            )
            report = report[0]
            report.name = data.get('rename')
            await self.data_svc.remove('vulnerabilityreports', match=dict(id=report_id))
            await self.data_svc.store(report)
            return dict(status='success')
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(
                status='fail', output='exception occurred while patching report'
            )

    async def delete_report(self, data):
        try:
            report_id = data.get('id')
            await self.data_svc.remove('vulnerabilityreports', match=dict(id=report_id))
            return dict(status='success')
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(
                status='fail', output='exception occurred while removing report'
            )

    async def retrieve_reports(self):
        reports = [
            vr.display for vr in await self.data_svc.locate('vulnerabilityreports')
        ]
        return dict(reports=reports)

    async def check_scan_status(self):
        pending = [s.id for s in self.running_scans.values() if s.status != 'done']
        finished = dict()
        errors = dict()
        for target in [
            t
            for t in self.running_scans.keys()
            if self.running_scans[t].status == 'done'
        ]:
            scan = self.running_scans.pop(target)
            if not scan.returncode:
                source = await self.pathfinder_svc.import_scan(
                    scan.name, os.path.basename(scan.filename)
                )
                finished[scan.id] = dict(source=source.name, source_id=source.id)
            else:
                self.log.debug(scan.output['stderr'])
                errors[scan.id] = dict(message=scan.output['stderr'])
        return dict(pending=pending, finished=finished, errors=errors)

    async def generate_adversary(self, data):
        def generate_links(path):
            if path and len(path) >= 2:
                return [
                    dict(source=path[n], target=path[n + 1], type='path')
                    for n in range(len(path) - 1)
                ]
            return []

        start = data.pop('start')
        target = data.pop('target')
        report_id = data.pop('id')
        report = await self.data_svc.locate(
            'vulnerabilityreports', match=dict(id=report_id)
        )
        tags = data.pop('adversary_tags')
        if report and start and target:
            path, adversary_id = await self.pathfinder_svc.generate_adversary(
                report[0], start, target, tags
            )
            return dict(adversary_id=adversary_id, new_links=generate_links(path))

    async def get_source_name(self, data):
        source = await self.data_svc.locate('sources', dict(id=data['source_id']))
        if source:
            return dict(name=source[0].name)
        return dict()

    @check_authorization
    async def store_report(self, request):
        return await self.file_svc.save_multipart_file_upload(
            request, '%s/reports' % settings.data_dir
        )

    @check_authorization
    async def download_report(self, request):
        report_id = request.query.get('report_id')
        report = await self.data_svc.locate(
            'vulnerabilityreports', match=dict(id=report_id)
        )
        if report:
            try:
                filename = f'{report[0].name}.yml'
                content = yaml.dump(report[0].display).encode('utf-8')
                headers = dict(
                    [
                        ('CONTENT-DISPOSITION', f'attachment; filename={filename}'),
                        ('FILENAME', filename),
                    ]
                )
                return web.Response(body=content, headers=headers)
            except FileNotFoundError:
                return web.HTTPNotFound(body='Report not found')
            except Exception as e:
                return web.HTTPNotFound(body=str(e))

    async def return_scanner_configuration(self, data):
        scanner = data.pop('name')
        if scanner in self.scanners:
            return dict(
                name=scanner,
                fields=[f.__dict__ for f in self.scanners[scanner].fields],
                enabled=self.scanners[scanner].enabled,
                error=False,
            )
        else:
            return dict(name=scanner, error='scanner not able to be found')

    async def load_scanners(self):
        scanners = {}
        for filepath in glob.iglob(
            os.path.join('plugins', 'pathfinder', 'scanners', '*', 'scanner.py')
        ):
            module = import_module(
                filepath.replace('/', '.').replace('\\', '.').replace('.py', '')
            )
            scanner = module.Scanner(dependencies=self.installed_dependencies)
            scanners[scanner.name] = scanner
        return scanners

    async def load_scanner(self, name):
        return import_module('plugins.pathfinder.scanners.%s.scanner' % name)
