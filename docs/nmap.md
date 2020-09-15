# nmap

## Overview
nmap is a network scanning tool


## useful parameters/settings
### scanning
<pre>
-sS       scan all open ports
-O        try to determine OS version
-sV       scan ports for version/service running on them
-sP       ping based scan for devices on a network
-sL       scan all IPs from a file list
-sU       scan UDP ports as well (long)
</pre>

### evasion
<pre>
-D             scan from deceptive address
--spoofmac     spoof mac address for scan
</pre>

# scripts
nmap has a built in scripting engine where simple lua scripts can be executed in parallel against the nmap output

there are a number of built in and external scripts for vulnerability scanning

nmap has some more documentation on using their scripting engine here:
https://nmap.org/book/nse-usage.html


the ones we have considered for gathering CVEs are:
<pre>
nmap-vulners
vulscan
vuln
</pre>


# examples
these commands were run on a vlan with a handful of devices put up for testing on it


simple ping presence report:
<pre>
$nmap -sP 192.168.44.1/24

Starting Nmap 7.60 ( https://nmap.org ) at 2020-04-29 09:34 CDT
Nmap scan report for unknown-lan1 (192.168.44.1)
Host is up (0.00035s latency).
Nmap scan report for RT-AC66U (192.168.44.2)
Host is up (0.00048s latency).
Nmap scan report for 192.168.44.107
Host is up (0.00053s latency).
Nmap scan report for 192.168.44.110
Host is up (0.055s latency).
Nmap scan report for dev-box-1 (192.168.44.126)
Host is up (0.00044s latency).
Nmap scan report for 192.168.44.128
Host is up (0.0014s latency).
Nmap scan report for 192.168.44.143
Host is up (0.0092s latency).
Nmap scan report for NPI7851E5 (192.168.44.145)
Host is up (0.0048s latency).
Nmap done: 256 IP addresses (8 hosts up) scanned in 3.21 seconds
</pre>



port version report:
<pre>
$nmap -sv 192.168.44.1

Starting Nmap 7.60 ( https://nmap.org ) at 2020-04-29 09:34 CDT
Nmap scan report for unknown-lan1 (192.168.44.1)
Host is up (0.012s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        Dropbear sshd 2015.71 (protocol 2.0)
23/tcp  open  tcpwrapped
53/tcp  open  domain     dnsmasq 2.73
443/tcp open  ssl/http   Tomato WAP firmware httpd
Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for RT-AC66U (192.168.44.2)
Host is up (0.00093s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
80/tcp   open  http       httpd/2.0
515/tcp  open  printer
9100/tcp open  jetdirect?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Nmap scan report for 192.168.44.107
Host is up (0.0014s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.9p1 Raspbian 10+deb10u2 (protocol 2.0)
53/tcp   open  domain          ISC BIND dnsmasq-pi-hole-2.80
80/tcp   open  http            lighttpd 1.4.53
6789/tcp open  ibm-db2-admin?
8080/tcp open  http-proxy
8443/tcp open  ssl/nagios-nsca Nagios NSCA
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Nmap scan report for 192.168.44.110
Host is up (0.033s latency).
All 1000 scanned ports on 192.168.44.110 are closed

Nmap scan report for dev-box-1 (192.168.44.126)
Host is up (0.00023s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.44.128
Host is up (0.0011s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.44.143
Host is up (0.010s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for NPI7851E5 (192.168.44.145)
Host is up (0.0050s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Virata-EmWeb/R6_2_1
443/tcp  open  ssl/https
515/tcp  open  printer
631/tcp  open  ssl/ipp    Virata-EmWeb/R6_2_1
8080/tcp open  http-proxy Virata-EmWeb/R6_2_1
9100/tcp open  jetdirect?
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
=== service fingerprints deleted ======
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (8 hosts up) scanned in 160.68 seconds
</pre>



vulnerability scan report output:
<pre>
$nmap --script nmap-vulners -sV 192.168.44.1/24

Starting Nmap 7.60 ( https://nmap.org ) at 2020-04-29 09:51 CDT
Nmap scan report for unknown-lan1 (192.168.44.1)
Host is up (0.0079s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        Dropbear sshd 2015.71 (protocol 2.0)
23/tcp  open  tcpwrapped
53/tcp  open  domain     dnsmasq 2.73
| vulners: 
|   cpe:/a:thekelleys:dnsmasq:2.73: 
|     	CVE-2019-14513	5.0	https://vulners.com/cve/CVE-2019-14513
|_    	CVE-2019-14834	4.3	https://vulners.com/cve/CVE-2019-14834
443/tcp open  ssl/http   Tomato WAP firmware httpd
Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for RT-AC66U (192.168.44.2)
Host is up (0.00068s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
80/tcp   open  http       httpd/2.0
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Server: httpd/2.0
|     x-frame-options: SAMEORIGIN
|     x-xss-protection: 1; mode=block
|     Date: Wed, 29 Apr 2020 14:52:14 GMT
|     Content-Type: text/html
|     Connection: close
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: httpd/2.0
|     x-frame-options: SAMEORIGIN
|     x-xss-protection: 1; mode=block
|     Date: Wed, 29 Apr 2020 14:52:09 GMT
|     Content-Type: text/html
|     Connection: close
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.0 501 Not Implemented
|     Server: httpd/2.0
|     x-frame-options: SAMEORIGIN
|     x-xss-protection: 1; mode=block
|     Date: Wed, 29 Apr 2020 14:52:09 GMT
|     Content-Type: text/html
|     Connection: close
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Server: httpd/2.0
|     x-frame-options: SAMEORIGIN
|     x-xss-protection: 1; mode=block
|     Date: Wed, 29 Apr 2020 14:52:29 GMT
|     Content-Type: text/html
|     Connection: close
|_http-server-header: httpd/2.0
515/tcp  open  printer
9100/tcp open  jetdirect?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Nmap scan report for 192.168.44.107
Host is up (0.00035s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.9p1 Raspbian 10+deb10u2 (protocol 2.0)
53/tcp   open  domain          ISC BIND dnsmasq-pi-hole-2.80
80/tcp   open  http            lighttpd 1.4.53
|_http-server-header: lighttpd/1.4.53
6789/tcp open  ibm-db2-admin?
8080/tcp open  http-proxy
| fingerprint-strings: 
|   DNSVersionBindReq, RPCCheck: 
|     HTTP/1.1 400 
|     Date: Wed, 29 Apr 2020 14:52:14 GMT
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 796
|     Date: Wed, 29 Apr 2020 14:52:08 GMT
|     Connection: close
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 302 
|     Location: http://localhost:8080/manage
|     Content-Length: 0
|     Date: Wed, 29 Apr 2020 14:52:08 GMT
|     Connection: close
|   RTSPRequest, Socks4, Socks5: 
|     HTTP/1.1 400 
|     Date: Wed, 29 Apr 2020 14:52:08 GMT
|_    Connection: close
8443/tcp open  ssl/nagios-nsca Nagios NSCA
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Nmap scan report for 192.168.44.110
Host is up (0.0089s latency).
All 1000 scanned ports on 192.168.44.110 are closed

Nmap scan report for dev-box-1 (192.168.44.126)
Host is up (0.00029s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.44.128
Host is up (0.0013s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.44.143
Host is up (0.020s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for NPI7851E5 (192.168.44.145)
Host is up (0.0037s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Virata-EmWeb/R6_2_1
| fingerprint-strings: 
|   DNSStatusRequest, DNSVersionBindReq, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, WMSRequest, X11Probe, afp, giop, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|_    HTTP/1.1 505 HTTP Version not supported
|_http-server-header: Virata-EmWeb/R6_2_1
443/tcp  open  ssl/https
| fingerprint-strings: 
|   DNSStatusRequest, DNSVersionBindReq, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, WMSRequest, X11Probe, afp, giop, oracle-tns, tor-versions: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|_    HTTP/1.1 505 HTTP Version not supported
515/tcp  open  printer
631/tcp  open  ssl/ipp    Virata-EmWeb/R6_2_1
| fingerprint-strings: 
|   DNSStatusRequest, DNSVersionBindReq, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, WMSRequest, X11Probe, afp, giop, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|_    HTTP/1.1 505 HTTP Version not supported
|_http-server-header: Virata-EmWeb/R6_2_1
8080/tcp open  http-proxy Virata-EmWeb/R6_2_1
| fingerprint-strings: 
|   DNSStatusRequest, DNSVersionBindReq, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, Socks4, Socks5, TLSSessionReq, TerminalServer, WMSRequest, X11Probe, afp, giop, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|_    HTTP/1.1 505 HTTP Version not supported
|_http-server-header: Virata-EmWeb/R6_2_1
9100/tcp open  jetdirect?
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============service fingerprints deleted==============

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (8 hosts up) scanned in 143.79 seconds
</pre>
