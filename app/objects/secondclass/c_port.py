import marshmallow as ma

from app.utility.base_object import BaseObject


class PortSchema(ma.Schema):

    unique = ma.fields.String()
    number = ma.fields.Integer()
    protocol = ma.fields.String()
    cves = ma.fields.List(ma.fields.String())
    service = ma.fields.String()
    version = ma.fields.String()
    product = ma.fields.String()

    @ma.post_load()
    def build_port(self, data, **_):
        return Port(**data)


class Port(BaseObject):

    schema = PortSchema()

    def __init__(self, port, protocol='TCP', match='.*'):
        super().__init__()
        self.number = port
        self.protocol = protocol
        self.cves = []
        self.service = None
        self.version = None
        self.product = None

