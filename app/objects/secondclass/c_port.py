from app.utility.base_object import BaseObject


class Port(BaseObject):

    def __init__(self, port, protocol='TCP', match='.*'):
        super().__init__()
        self.number = port
        self.protocol = protocol
        self.cves = []
        self.service = None
        self.version = None
        self.product = None

