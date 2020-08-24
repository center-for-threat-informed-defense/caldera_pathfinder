#Pathfinder Parser Creation
######Enter your happy place, prime your keyboard and, "copy, paste, change!"
##example

```python
import logging
from collections import defaultdict

from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.objects.secondclass.c_host import Host
from plugins.pathfinder.app.objects.secondclass.c_port import Port


class ReportParser:

    def __init__(self):
        self.format = 'example'
        self.log = logging.getLogger('example parser')

    def parse(self, report_filename):
        try:
            caldera_report = self.parse_report(report_filename)
            self.generate_network_map(caldera_report)
        except Exception as e:
            self.log.error('exception when parsing example report format: %s' % repr(e))
            return None

        return caldera_report

    def parse_report(self, report_file):
        report = VulnerabilityReport()
        # populate report with hosts and ports as you parse through it in python
        host = Host('0.0.0.0')
        port = Port(80)
        port.cves = ['bad1', 'bad2']
        host.ports.append(port)
        host.cves.extend(port.cves)
        report.hosts.append(host)
        
        return report

    def generate_network_map(self, report):
        # a simple network map assuming all open ports are visible to all computers on the same subnet
        network_map = defaultdict(list)
        report_hosts = report.hosts.keys()
        for host in report_hosts:
            if report.hosts[host].ports:
                [network_map[h2].append(host) for h2 in report_hosts if h2 != host]
        report.network_map = dict(network_map)
```

#Tutorial

From the example above you can see a very simplified and pruned down example of a report parser.
The format of a report parser is very simple and starts as a python module with a `ReportParser` class within it.

The class requires 2 methods, one for initialization and one for parsing.
You can add additional methods to logically split up your parsing of the report as needed.
The `parse` method needs to return a `VulnerabilityReport` object or `None` if the parsing of the report fails.

Starting out the `__init__` method only need to setup the parsing format name, and the logger, so copy past that over and change as needed.

The `parse` method is where things start to get more involved.
The input to `parse` is a full filename path to the file containing the report to be parsed.
You can then take this path and manipulate it as needed to build out a full caldera vulnerability report.

To get an idea of how you would want to build this out you will need to take into consideration the structure of your vulnerability report, and the structure as is represented in a caldera report.
The caldera format uses a nested representation where a report has hosts, which in turn have ports, which have vulnerabilities (among other properties).
Hosts also have a vulnerability list of the collection of all vulnerabilities represented on their open ports.

Once you determine how you want to map between the reports you can build out the objects and build up the report.

If your report contains a more complex network topology you can create a custom network mapping compared to the example above.
But if it is just a scan of a subnet or set of hosts that have visibility to each other the method in the example will create a network map that links them all to each other based on the availibility of open ports.

Once those steps are done you just return the report you created and your parser is done.