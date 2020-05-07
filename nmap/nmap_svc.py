import re
import socket
import logging
import subprocess


class NmapService:
    def __init__(self, services):
        self.services = services
        self.machine_ip = self.get_machine_ip()
        self.log = logging.getLogger('nmap_svc')

    @staticmethod
    def get_machine_ip():
        # this gets the exit IP, so if you are on a VPN it will get you the IP on the VPN network and not your local network IP
        def get_ip():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('10.255.255.255', 1))
                ip = s.getsockname()[0]
            except Exception:
                ip = '127.0.0.1'
            finally:
                s.close()
            return ip
        return get_ip()

    async def find_hosts(self, option='sn'):
        hosts = []
        pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        command = 'nmap -%s %s/24' % (option, self.machine_ip)
        output = subprocess.check_output(command.split(' '), shell=False)
        results = re.findall(pattern, output.decode('utf-8'))
        if results:
            hosts = [ip for ip in results]
        return hosts

    async def scan_host_cves(self, ip):
        self.log.debug('scanning %s' % ip)
        command = 'nmap --script plugins/crag/nmap/scripts/nmap-vulners -sV %s' % ip
        pattern = r'(CVE-\d{4}-\d{4,})'
        output = subprocess.check_output(command.split(' '), shell=False)
        results = list(set(re.findall(pattern, output.decode('utf-8'))))
        return results

    async def scan_network(self):
        hosts = await self.find_hosts()
        self.log.info('found %s network devices, will scan each for vulnerabilities' % len(hosts))
        scan_result = {host: await self.scan_host_cves(host) for host in hosts}
        return scan_result

    async def generate_report(self):
        return await self.scan_network()
