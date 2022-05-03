import marshmallow as ma

from app.utility.base_object import BaseObject


class OSSchema(ma.Schema):

    os_type = ma.fields.String(allow_none=True)
    subtype = ma.fields.String(missing=None)
    notes = ma.fields.String(missing=None)

    @ma.post_load()
    def build_os(self, data, **_):
        return OS(**data)


class OS(BaseObject):

    schema = OSSchema()

    def __init__(self, os_type, subtype=None, notes=None, match='.*'):
        super().__init__()
        self.os_type = os_type
        self.subtype = subtype
        self.notes = notes
