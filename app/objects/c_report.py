import uuid

from datetime import date

from app.objects.interfaces.i_object import FirstClassObjectInterface
from app.utility.base_object import BaseObject


class VulnerabilityReport(FirstClassObjectInterface, BaseObject):

    @property
    def unique(self):
        return self.hash('%s' % self.id)

    def __init__(self, name=None, hosts=None):
        super().__init__()
        self.id = str(uuid.uuid4())
        self.name = name if name else 'crag-report-%s' % date.today().strftime("%b-%d-%Y")
        self.hosts = hosts if hosts else []

    def store(self, ram):
        existing = self.retrieve(ram['vulnerabilityreports'], self.unique)
        if not existing:
            ram['vulnerabilityreports'].append(self)
            return self.retrieve(ram['vulnerabilityreports'], self.unique)
        existing.update('name', self.name)
        existing.update('hosts', self.hosts)
        return existing
