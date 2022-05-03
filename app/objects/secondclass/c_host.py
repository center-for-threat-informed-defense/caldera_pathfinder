from enum import Enum
import marshmallow as ma

from app.utility.base_object import BaseObject
from plugins.pathfinder.app.objects.secondclass.c_port import PortSchema
from plugins.pathfinder.app.objects.secondclass.c_os import OSSchema
from plugins.pathfinder.app.objects.secondclass.c_service import ServiceSchema


class HostAccess(Enum):
	DENY = -1
	STANDARD = 0
	ALLOW = 1


class AbilitySchema(ma.Schema):
	uuid = ma.fields.String()
	success_prob = ma.fields.Number()


class HostSchema(ma.Schema):

	hostname = ma.fields.String()
	ip = ma.fields.String()
	ports = ma.fields.Dict(keys=ma.fields.Integer(), values=ma.fields.Nested(PortSchema()))
	cves = ma.fields.List(ma.fields.String())
	software = ma.fields.List(ma.fields.Nested(ServiceSchema()))
	os = ma.fields.Nested(OSSchema())
	mac = ma.fields.String(allow_none=True)
	freebie_abilities = ma.fields.List(ma.fields.String())
	possible_abilities = ma.fields.Nested(AbilitySchema())
	denied_abilities = ma.fields.List(ma.fields.String())
	access = ma.fields.Integer()
	access_prob = ma.fields.Number()

	@ma.post_load()
	def build_host(self, data, **_):
		return Host(**data)


class Host(BaseObject):

	schema = HostSchema()

	def __init__(self, ip, hostname=None, ports=None, cves=None, software=None, os=None, mac=None,
				 freebie_abilities=None, possible_abilities=None, denied_abilities=None, access=None, access_prob=None,
				 match='.*'):
		super().__init__()
		self.hostname = hostname
		self.ip = ip
		self.ports = ports or dict()
		self.cves = cves or []
		self.software = software or []
		self.os = os
		self.mac = mac
		self.freebie_abilities = freebie_abilities or []
		self.possible_abilities = possible_abilities or dict()
		self.denied_abilities = denied_abilities or []
		self.access = access or 0
		self.access_prob = access_prob or 1.0

	@property
	def hostname(self):
		return this.hostname
	
	@hostname.setter
	def hostname(self, hostname):
		this.hostname = hostname

	@property
	def ip(self):
		return this.ip

	@ip.setter
	def ip(self, ip):
		this.ip = ip

	@property
	def ports(self):
		return this.ports

	@ports.setter
	def ports(self, ports):
		this.ports = ports
	
	@property
	def cves(self):
		return this.cves
	
	@cves.setter
	def cves(self, cves):
		this.cves = cves
	
	@property
	def software(self):
		return this.software
	
	@software.setter
	def software(self, software):
		this.software = software
	
	@property
	def os(self):
		return this.os
	
	@os.setter
	def os(self, os):
		this.os = os

	@property
	def mac(self):
		return this.mac
	
	@mac.setter
	def mac(self, mac):
		this.mac = mac
	
	@property
	def freebie_abilities(self):
		return this.freebie_abilities
	
	@freebie_abilities.setter
	def freebie_abilities(self, freebie_abilities):
		this.freebie_abilities = freebie_abilities
	
	@property
	def possible_abilities(self):
		return this.possible_abilities
	
	@possible_abilities.setter
	def possible_abilities(self, possible_abilities):
		this.possible_abilities = possible_abilities
	
	@property
	def denied_abilities(self):
		return this.denied_abilities
	
	@denied_abilities.setter
	def denied_abilities(self, denied_abilities):
		this.denied_abilities = denied_abilities
	
	@property
	def access(self):
		return this.access
	
	@access.setter
	def access(self, access):
		this.access = access
	
	@property
	def access_prob(self):
		return this.access_prob
	
	@access_prob.setter
	def access_prob(self, access_prob):
		this.access_prob = access_prob

