import uuid
from datetime import date

import marshmallow as ma

import networkx as nx

from app.utility.base_object import BaseObject
from app.objects.interfaces.i_object import FirstClassObjectInterface
from plugins.pathfinder.app.objects.secondclass.c_host import HostSchema
from plugins.pathfinder.app.objects.secondclass.c_os import OS


class ReportSchema(ma.Schema):

    id = ma.fields.String(missing=None)
    name = ma.fields.String()
    hosts = ma.fields.Dict(
        keys=ma.fields.String(), values=ma.fields.Nested(HostSchema())
    )
    scope = ma.fields.String()
    network_map_nodes = ma.fields.List(ma.fields.String())
    network_map_edges = ma.fields.List(ma.fields.Tuple((ma.fields.String(), ma.fields.String())))


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

    def get_host_freebie_abilities(self, id):
        return self.hosts[id].freebie_abilities
        
    def set_host_freebie_abilities(self, id, abilities: list):
        self.hosts[id].freebie_abilities = abilities
            
    def get_host_access(self, id):
        return self.hosts[id].access
        
    def set_host_access(self, id, access):
        self.hosts[id].access = access
            
    def get_host_denied_abilities(self, id):
        return self.hosts[id].denied_abilities
        
    def set_host_denied_abilities(self, id, denied: list):
        self.hosts[id].denied_abilities = denied

    def get_host_ip(self, id):
        return self.hosts[id].ip
        
    def set_host_ip(self, id, ip):
        self.hosts[id].ip = ip
            
    def get_host_ports(self, id):
        return self.hosts[id].ports
        
    def set_host_ports(self, id, ports: dict):
        self.hosts[id].ports = ports
            
    def get_host_cves(self, id):
        return self.hosts[id].cves

    def set_host_cves(self, id, cves: list):
        self.hosts[id].cves = cves

    def get_host_software(self, id):
        return self.hosts[id].software
        
    def set_host_software(self, id, software: list):
        self.hosts[id].software = software

    def get_host_os(self, id):
        return self.hosts[id].os
        
    def set_host_os(self, id, os: OS):
        self.hosts[id].os = os

    def get_host_hostname(self, id):
        return self.hosts[id].hostname
        
    def set_host_hostname(self, id, hostname):
        self.hosts[id].hostname = hostname
            
    def get_host_mac(self, id):
        return self.hosts[id].mac
        
    def set_host_mac(self, id, mac):
        self.hosts[id].mac = mac
            
    def get_host_possible_abilities(self, id):
        return self.hosts[id].possible_abilities
        
    def set_host_possible_abilities(self, id, possible_abilities: dict):
        self.hosts[id].possible_abilities = possible_abilities
    
    def get_host_access_prob(self, id):
        return self.hosts[id].access_prob
        
    def set_host_access_prob(self, id, access_prob):
        self.hosts[id].access_prob = access_prob
