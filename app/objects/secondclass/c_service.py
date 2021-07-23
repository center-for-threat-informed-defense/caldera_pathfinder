import marshmallow as ma

from app.utility.base_object import BaseObject


class ServiceSchema(ma.Schema):

    serviceType = ma.fields.String()
    subtype = ma.fields.String()
    notes = ma.fields.String()

    @ma.post_load()
    def build_service(self, data, **_):
        return Service(**data)


class Service(BaseObject):

    schema = ServiceSchema()

    def __init__(self, serviceType, subtype=None, notes=None, match='.*'):
        super().__init__()
        self.serviceType = serviceType
        self.subtype = subtype
        self.notes = notes
