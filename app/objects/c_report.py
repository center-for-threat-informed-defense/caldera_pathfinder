import uuid
from datetime import date

import marshmallow as ma
import networkx as nx

from app.utility.base_object import BaseObject
from app.objects.interfaces.i_object import FirstClassObjectInterface
from plugins.pathfinder.app.objects.secondclass.c_host import HostSchema


class ReportSchema(ma.Schema):

    id = ma.fields.String(missing=None)
    name = ma.fields.String()
    hosts = ma.fields.Dict(
        keys=ma.fields.String(), values=ma.fields.Nested(HostSchema())
    )
    scope = ma.fields.String()
    network_map_nodes = ma.fields.List(ma.fields.String())
    network_map_edges = ma.fields.List(ma.fields.Tuple((ma.fields.String(),
                                                        ma.fields.String())))

    @ma.post_load()
    def build_report(self, data, **_):
        return VulnerabilityReport(**data)


class VulnerabilityReport(FirstClassObjectInterface, BaseObject):

    schema = ReportSchema()

    @property
    def unique(self):
        return self.hash('%s' % self.id)

    def __init__(self, id=None, name=None, hosts=None, scope=None, network_map_nodes=None, network_map_edges=None, **kwargs):
        super().__init__()
        self.id = id or str(uuid.uuid4())
        self.name = (
            name
            if name
            else 'vulnerability-report-%s' % date.today().strftime('%b-%d-%Y')
        )
        self.hosts = hosts or dict()
        self.scope = scope
        self.network_map = nx.Graph()
        self.network_map_nodes = network_map_nodes or []
        self.network_map_edges = network_map_edges or []
        self.network_map.add_nodes_from(self.network_map_nodes)
        self.network_map.add_edges_from(self.network_map_edges)

    def store(self, ram):
        existing = self.retrieve(ram['vulnerabilityreports'], self.unique)
        if not existing:
            ram['vulnerabilityreports'].append(self)
            return self.retrieve(ram['vulnerabilityreports'], self.unique)
        existing.update('name', self.name)
        existing.update('hosts', self.hosts)
        existing.update('network_map', self.network_map)
        return existing

    def retrieve_host_by_id(self, id):
        return self.hosts[id]
