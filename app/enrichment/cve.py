"""
CVE query utilities for network context enrichment.

Uses CVE REST API: https://cve.circl.lu/api/ or NIST REST API:
https://nvd.nist.gov/general/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement
"""

import re
import requests

from plugins.pathfinder.app.objects.c_cve import CVE


CVE_SEARCH_URL = 'https://cvepremium.circl.lu/api'
CVE_KEYWORD_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0/?keyword='
CPE_MATCH_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString='
CVE_PATTERN = r'CVE-\d{4}-\d{4,7}'


def get_cve(cve_id):
    """Retrieve vulnerable os/software configuration details from CVE id.

    Args:
        cve_id (str): Common Vulnerability Enumeration (CVE)

    Returns: (CVE obj)
    """
    sess = _get_sess()
    full_cve = _get_cve_info(sess, cve_id)
    return _create_pyd_cve(full_cve)


def search_cve(service, service_version=None, os=None, os_version=None, greedy=False):
    """Map CVEs to services using a remote query of the cvelist-master repository.

    Args:
        service (str): Software/service name.
        service_version (str): Software/service version.
        os (str): Operating system name.
        os_version (str): Operating system version.
        greedy (bool): Boolean to determine whether OS and version data is
          omited when obtaining CVEs (default: False)

    Returns (list): of CVE objects
    """
    sess = _get_sess()
    query = _get_service_query(service_name=service,
                               service_version=service_version, os_name=os,
                               os_version=os_version, greedy=greedy)
    cve_json = _get_cve_from_api(sess=sess, query=query)
    cve = []
    for cve_ in cve_json['data']:
        cve.append(_create_pyd_cve(cve_))
    return cve


def keyword_cve(keyword, exact_match=False):
    """Map CVEs to arbitrary keywords using an API call to the NIST CVE database.

    Args:
        keyword (str or list): CVE search keyword(s).
        exact_match (bool): Software/service version (default: False).

    Returns (list): of CVE objects
    """
    sess = _get_sess()
    if isinstance(keyword, str):
        keyword_url = f'{CVE_KEYWORD_URL}{keyword}'
    elif isinstance(keyword, list):
        keyword_search = '+'.join(keyword)
        keyword_url = f'{CVE_KEYWORD_URL}{keyword_search}'
    else:
        raise NotImplementedError
    if exact_match:
        keyword_url = f'{keyword_url}?isExactMatch=true'
    cve_json = sess.get(keyword_url, verify=False,
                        timeout=8).json()
    cve = []
    for cve_ in cve_json['result']['CVE_Items']:
        r = sess.get(url=f'{CVE_SEARCH_URL}/cve/{cve_["cve"]["CVE_data_meta"]["ID"]}',
                     verify=False,
                     timeout=8).json()
        cve.append(_create_pyd_cve(r))
    return cve


def match_cve(service, service_version=None, os=None, os_version=None, greedy=False,
  exact_match=False):
    """Find CVEs from CPE match strings using an API call to the NIST CVE database.

    Args:
        service (str): Software/service name.
        service_version (str): Software/service version.
        os (str): Operating system name.
        os_version (str): Operating system version.
        greedy (bool): Boolean to determine whether OS and version data is
          omited when obtaining CVEs (default: False)
        exact_match (bool): Software/service version (default: False).

    Returns (list): of CVE objects
    """
    sess = _get_sess()
    match_url = f'{CPE_MATCH_URL}cpe:2.3:a:*:{service}:{service_version or "*"}'
    if exact_match:
        match_url = f'{match_url}?isExactMatch=true'
    cve_json = sess.get(match_url, verify=False,
                        timeout=8).json()
    cve = []
    for cve_ in cve_json['result']['CVE_Items']:
        r = sess.get(url=(f'{CVE_SEARCH_URL}/cve/{cve_["cve"]["CVE_data_meta"]["ID"]}'),
                     verify=False,
                     timeout=8).json()
        match = _create_pyd_cve(r)
        if greedy or (not os):
            cve.append(match)
        else:
            try:
                match_e_os = match.e_os
                for k, v in match_e_os.items():
                    if os in k and ('-' in v or os_version in v):
                        cve.append(match)
            except (KeyError, ValueError):
                continue  # NOTE: if the e_os dict is empty, the CVE is OS-agnostic, include.
                cve.append(match)
    return cve


def get_cve_id(full_cve):
    """Get CVE id from full CVE dictionary returned by API call.

    Args:
        full_cve (dict): Full CVE data as a JSON dictionary from API call.

    Returns (list): list of unique CVE id's found in the full CVE dictionary.
    """
    cves = []
    cve = None
    for json in full_cve[0]['data']:
        if json != '':
            cve = _get_cve_id(json)
        if cve:
            cves.append(cve)
    return cves


def parse_cve_id(text):
    """ """
    return re.findall(CVE_PATTERN, text)


""" PRIVATE """


def _create_pyd_cve(cve_full):
    """
    Args:
        cve_full (dict):

    Returns: CVE obj
    """
    # extract software and os details and put under additional fields
    cve_full['e_os'], cve_full['e_software'] = _get_vuln_info_from_cve(cve_full)

    # field normalizing
    clean = {}
    for k, v in cve_full.items():
        k = k.replace('-', '_')
        k = k.lower()
        clean[k] = v
    try:
        return CVE(**clean)
    except ValueError as e:
        return f'Error creating CVE obj: {e}.'


def _search_to_regex(search):
    """ """
    return f'.*{search}'


def _get_search_filter(service_name, service_version=None, os_name=None, os_version=None):
    """Create a pymongo-style search filter using the system configuration,
    as described by software and OS on host.

    Args:
        service_name (str); Software/service name.
        service_version (str): Software/service version.
        os_name (str): Operating system name.
        os_version (str): Operating system version.

    Returns (dict): pymongo-style search filter.
    """
    return {'products': service_name,
            'vendors': os_name or {'$regex': r'.*'},
            'vulnerable_configuration': {'$regex': _search_to_regex(os_version or ''), '$options': "six"},
            'vulnerable_product': {'$regex': _search_to_regex(service_version or ''), '$options': "six"}
            }


def _get_service_query(service_name, service_version='', os_name='', os_version='',
  greedy=False):
    """Create a query using the system configuration, as described by software and OS on host.

    Args:
        service_name (str); Software/service name.
        service_version (str): Software/service version.
        os_name (str): Operating system name.
        os_version (str): Operating system version.
        greedy (bool): Boolean to determine whether OS and version data
          is omited when obtaining CVEs (default: False)

    Returns (dict): Complete search query for API call.
    """
    if greedy:
        return _get_search_filter(service_name=service_name,
                                  service_version='',
                                  os_name='',
                                  os_version='')
    return _get_search_filter(service_name=service_name,
                              service_version=service_version,
                              os_name=os_name,
                              os_version=os_version)


def _get_cve_from_api(sess, query):
    """Post query containing configuration details to session.

    Args:
        sess (requests.Session): session object with configured headers.
        query (dict): pymongo-style dictionary filer for document-oriented db search.

    Returns (dict): JSON containing full CVE information for all CVEs
      matching the system described in query.
    """
    return sess.post(url=(CVE_SEARCH_URL + '/query'),
                     json={'retrieve': 'cves',
                           'dict_filter': query,
                           'limit': 10,
                           'skip': 25,
                           'sort': 'cvss',
                           'sort_dir': 'ASC'},
                     verify=False,
                     timeout=8).json()


def _get_cve_info(sess, cve):
    """Get request using CVE ID.

    Args:
        sess (requests.Session): session object with configured headers.
        cve (str): cve enumeration to search.

    Returns (dict): JSON containing full CVE information for all CVEs
      matching the system described in query.
    """
    return sess.get(url=(CVE_SEARCH_URL + '/cve/' + cve),
                    verify=False,
                    timeout=8).json()


def _get_vuln_info_from_cve(full_cve):
    """Return the vulnerable configurations of operating system and
    software for a given CVE.

    Args:
        full_cve (dict): Full CVE data as a JSON dictionary from API call.

    Returns (dict, dict): ({os: [version,]}, {software: [version,])
    """
    vulnerable_configs = _get_vulnerable_configs(full_cve)
    software = _get_software_from_cve(vulnerable_configs)
    os = _get_os_from_cve(vulnerable_configs)
    return os, software


def _get_vulnerable_configs(full_cve):
    """Return the vulnerable configurations as a list from CVE JSON.

    Args:
        full_cve (dict): Full CVE data as a JSON dictionary from API call.

    Returns (list): list of vulnerable configuration details
    """
    if 'vulnerable_configuration' in full_cve:
        return full_cve['vulnerable_configuration']
    else:
        return []


def _get_software_from_cve(vulnerable_configs):
    """Return the software with versions from the list of
    vulnerable configurations.

    Args:
        vulnerable_configs (list): List of vulnerable configurations
         from full cve.

    Returns (list): list of (software, version) tuples from vulnerable
     configurations
    """
    software = {}
    for vuln in vulnerable_configs:
        if isinstance(vuln, dict):
            # NOTE: this check is due to a spec mismatch in CVE json returned
            # from API. If the CVE was retrieved with a GET endpoint, the
            # 'vulnerable_configuration' key is a list of dict's, but if the CVE was
            # retrieved search endpoint, the key is a list of str's.
            vuln = vuln['id']
        if vuln.split(':')[2] == 'a':
            soft = vuln.split(':')[4]
            version = vuln.split(':')[5]
            if soft in software:
                software[soft].add(version)
            else:
                software[soft] = set([version])
    software = {k: list(v) for k, v in software.items()}
    return software


def _get_os_from_cve(vulnerable_configs):
    """Return the operating systems with versions from the list of
    vulnerable configurations.

    Args:
        vulnerable_configs (list): List of vulnerable configurations
         from full cve.

    Returns (list): list of (os, version) tuples from vulnerable
     configurations
    """
    os = {}
    for vuln in vulnerable_configs:
        if isinstance(vuln, dict):
            # NOTE: this check is due to a spec mismatch in CVE json returned
            # from API. If the CVE was retrieved with a GET endpoint, the
            # 'vulnerable_configuration' key is a list of dict's, but if the CVE was
            # retrieved search endpoint, the key is a list of str's.
            vuln = vuln['id']
        if vuln.split(':')[2] == 'o':
            os_ = f'os.{vuln.split(":")[3]}.{vuln.split(":")[4]}'
            version = vuln.split(":")[5]
            if os_ in os:
                os[os_].add(version)
            else:
                os[os_] = set([version])
    os = {k: list(v) for k, v in os.items()}
    return os


def _get_cve_id(full_cve):
    """Return the CVE id from the full CVE JSON dictionary.

    Args:
        full_cve (dict): Full CVE data as a JSON dictionary from API call.

    Returns (str): CVE id (e.g. CVE-2021-26068).
    """
    try:
        return full_cve['id']
    except KeyError:
        return None


def _get_sess():
    """Create a new web requests session and set the headers to
    facilitate structured API query.

    Args:
        None

    Returns: requests Session object.
    """
    sess = requests.Session()
    sess.headers.update({'Content-Type': 'application/json'})
    return sess
