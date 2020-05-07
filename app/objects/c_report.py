import uuid

from app.objects.interfaces.i_object import FirstClassObjectInterface
from app.utility.base_object import BaseObject


class VulnerabilityReport(FirstClassObjectInterface, BaseObject):

    @property
    def unique(self):
        return self.hash('%s' % self.id)

    def __init__(self, name='', hosts=None):
        super().__init__()
        self.id = uuid.uuid4()
        self.name = name
        self.hosts = hosts if hosts else []

    def store(self, ram):
        existing = self.retrieve(ram['vulnerabilityreports'], self.unique)
        if not existing:
            ram['vulnerabilityreports'].append(self)
            return self.retrieve(ram['vulnerabilityreports'], self.unique)
        existing.update('name', self.name)
        existing.update('hosts', self.hosts)
        return existing
