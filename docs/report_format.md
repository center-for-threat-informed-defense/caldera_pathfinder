# Native Caldera Vulnerability Report Format

## example
<pre>
id: d64be1a7-c698-49bb-939e-0b18bfb018a5
name: crag-report-May-12-2020
scope: 172.31.32.237
hosts:
  172.31.32.237:
    cves:
    - CVE-2019-16905
    - CVE-2019-9740
    - CVE-2019-9947
    - CVE-2019-18348
    - CVE-2018-1000117
    - CVE-2018-1060
    - CVE-2019-9636
    - CVE-2019-10160
    hostname: bvb-172-31-32-237.mitre.org
    ip: 172.31.32.237
    ports:
      22:
        cves:
        - CVE-2019-16905
        number: 22
        product: OpenSSH
        protocol: tcp
        service: ssh
        version: '7.9'
      3283:
        cves: []
        number: 3283
        product: null
        protocol: tcp
        service: netassistant
        version: null
      5900:
        cves: []
        number: 5900
        product: Apple remote desktop vnc
        protocol: tcp
        service: vnc
        version: null
      8089:
        cves: []
        number: 8089
        product: Splunkd httpd
        protocol: tcp
        service: http
        version: null
      8888:
        cves:
        - CVE-2019-9740
        - CVE-2019-9947
        - CVE-2019-18348
        - CVE-2018-1000117
        - CVE-2018-1060
        - CVE-2019-9636
        - CVE-2019-10160
        number: 8888
        product: aiohttp
        protocol: tcp
        service: http
        version: 3.6.2
</pre>

## Field requirements

<pre>
id: uuid4 (string/optional)
name: descriptive name (string)
hosts:  // dictionary of key=ip, value=dictionary for host
scope: 127.0.0.1/24 (string)
  127.0.0.1:
    hostname: machine hostname (string)
    ip: 127.0.0.1 (string)
    cves:  // list of CVE names found on host
    - CVE-2020-0001
    - CVE-2020-0002
    ports:  dictionary of key=port number, value=dictionary for port
      22:
        number: 22 (integer)
        product: OpenSSH (string)
        protocol: tcp (string)
        service: ssh (string)
        version: '7.9' (string)
        cves:  // list of CVE names found for port/service/version
        - CVE-2019-16905
</pre>