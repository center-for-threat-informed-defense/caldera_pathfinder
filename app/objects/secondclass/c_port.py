import marshmallow as ma

from app.utility.base_object import BaseObject


class PortSchema(ma.Schema):

    number = ma.fields.Integer()
    protocol = ma.fields.String()
    cves = ma.fields.List(ma.fields.String())
    service = ma.fields.String(missing=None)
    version = ma.fields.String(missing=None)
    product = ma.fields.String(missing=None)
    state = ma.fields.String(missing='open')

    @ma.post_load()
    def build_port(self, data, **_):
        return Port(**data)


class Port(BaseObject):

    schema = PortSchema()

    def __init__(self, number, protocol='TCP', cves=None, service=None, version=None, product=None, state='open', match='.*'):
        super().__init__()
        self.number = number
        self.protocol = protocol
        self.cves = cves or []
        self.service = service
        self.version = version
        self.product = product
        self.state = state

