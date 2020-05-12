import uuid
import marshmallow as ma

from datetime import date

from app.utility.base_object import BaseObject
from app.objects.interfaces.i_object import FirstClassObjectInterface
from plugins.crag.app.objects.secondclass.c_host import HostSchema


class ReportSchema(ma.Schema):

    unique = ma.fields.String()
    id = ma.fields.String()
    name = ma.fields.String()
    hosts = ma.fields.Dict(keys=ma.fields.String(), values=ma.fields.Nested(HostSchema()))

    @ma.post_load()
    def build_report(self, data, **_):
        return VulnerabilityReport(**data)


class VulnerabilityReport(FirstClassObjectInterface, BaseObject):

    schema = ReportSchema()

    @property
    def unique(self):
        return self.hash('%s' % self.id)

    def __init__(self, name=None):
        super().__init__()
        self.id = str(uuid.uuid4())
        self.name = name if name else 'crag-report-%s' % date.today().strftime("%b-%d-%Y")
        self.hosts = dict()  # dict(ip=Host())

    def store(self, ram):
        existing = self.retrieve(ram['vulnerabilityreports'], self.unique)
        if not existing:
            ram['vulnerabilityreports'].append(self)
            return self.retrieve(ram['vulnerabilityreports'], self.unique)
        existing.update('name', self.name)
        existing.update('hosts', self.hosts)
        return existing
