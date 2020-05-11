from app.utility.base_object import BaseObject


class Host(BaseObject):

    def __init__(self, ip, hostname=None, match='.*'):
        super().__init__()
        self.hostname = hostname
        self.ip = ip
        self.ports = dict()  # dict(port#=Port())
        self.cves = []
