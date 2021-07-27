import marshmallow as ma

from app.utility.base_object import BaseObject


class OSSchema(ma.Schema):
    osType = ma.fields.String()
    subtype = ma.fields.String()
    notes = ma.fields.String()

    @ma.post_load()
    def build_os(self, data, **_):
        return OS(**data)


class OS(BaseObject):

    schema = OSSchema()

    def __init__(self, osType, subtype=None, notes=None, match='.*'):
        super().__init__()
        self.osType = osType
        self.subtype = subtype
        self.notes = notes
