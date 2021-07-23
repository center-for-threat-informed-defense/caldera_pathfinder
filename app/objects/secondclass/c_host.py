import marshmallow as ma

from app.utility.base_object import BaseObject
from plugins.pathfinder.app.objects.secondclass.c_port import PortSchema
from plugins.pathfinder.app.objects.secondclass.c_os import OSSchema
from plugins.pathfinder.app.objects.secondclass.c_service import ServiceSchema

class HostSchema(ma.Schema):

    hostname = ma.fields.String()
    ip = ma.fields.String()
    ports = ma.fields.Dict(keys=ma.fields.Integer(), values=ma.fields.Nested(PortSchema()))
    cves = ma.fields.List(ma.fields.String())
    software = ma.fields.List(ma.fields.Nested(ServiceSchema()))
    os = ma.fields.Nested(OSSchema())
    mac = ma.fields.String()

    @ma.post_load()
    def build_host(self, data, **_):
        return Host(**data)


class Host(BaseObject):

    schema = HostSchema()

    def __init__(self, ip, hostname=None, ports=None, cves=None, software=None, os=None, mac=None, match='.*'):
        super().__init__()
        self.hostname = hostname
        self.ip = ip
        self.ports = ports or dict()
        self.cves = cves or []
        self.software = software or []
        self.os = os
        self.mac = mac
