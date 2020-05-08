from app.utility.base_object import BaseObject


class Port(BaseObject):

    def __init__(self, port, protocol='TCP', cve=None, match='.*'):
        super().__init__()
        self.number = port
        self.protocol = protocol
        self.cve = cve
        self.service = None
        self.version = None
        self.product = None

