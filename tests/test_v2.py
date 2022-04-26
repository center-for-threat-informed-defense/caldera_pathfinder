import os, sys, pytest
import asyncio

from plugins.pathfinder.app.pathfinder_svc import PathfinderService
from plugins.pathfinder.app.parsers import caldera
import networkx as nx

TEST_REPORT_PATH = os.path.join(os.path.dirname(__file__), 'data/v2_algo_testcase.yml')
PATHFINDER_V2_ID = 'deadbeef-6a18-4dcf-b659-79b8dd0d8d89'

@pytest.fixture
def test_report():
    return caldera.ReportParser().parse(TEST_REPORT_PATH)


@pytest.fixture
def pathfinder_svc():
    return PathfinderService(services={})

@pytest.fixture
def expected_graph(test_report):
    graph = test_report.network_map
    graph.remove_node('1-3')
    return graph


@pytest.mark.asyncio
class TestV2:

    async def test_generate_exploit_graph(self, test_report, pathfinder_svc, expected_graph):
        '''
            Tests the Pathfinder Service 'generate_exploitability_graph()'
        '''
        func_result = await pathfinder_svc.generate_exploitability_graph(test_report, [], [])
        assert nx.is_isomorphic(expected_graph,func_result)

    async def test_create_adversary_from_path(self, test_report, pathfinder_svc, mocker):
        '''
            Tests the Pathfinder Service 'create_adversary_from_path()'
        '''
        start = '1-1'
        end = '2-3'
        vuln_graph = await pathfinder_svc.generate_exploitability_graph(test_report, [], [])
        vuln_path = nx.all_simple_paths(vuln_graph, test_report.retrieve_host_by_id(start), test_report.retrieve_host_by_id(end))

        expected_id = ['315f8fcc-c05a-4db0-9f9a-5daade661540']
        future = asyncio.Future()
        future.set_result(expected_id)
        mocker.patch('plugins.pathfinder.app.pathfinder_svc.PathfinderService.get_host_exploits', return_value=future)

        expected_result = {
            'node1.local': [('315f8fcc-c05a-4db0-9f9a-5daade661540', 0.9)],
            'node2.local': [('315f8fcc-c05a-4db0-9f9a-5daade661540', 0.9)],
            'node3.local': [('315f8fcc-c05a-4db0-9f9a-5daade661540', 0.9)],
            'node4.local': [('315f8fcc-c05a-4db0-9f9a-5daade661540', 0.9)],
            'node5.local': [('315f8fcc-c05a-4db0-9f9a-5daade661540', 0.9)],
            'node6.local': [('315f8fcc-c05a-4db0-9f9a-5daade661540', 0.9)]
            }

        func_result = await pathfinder_svc.create_adversary_from_path(test_report, next(vuln_path))
        assert func_result == expected_result

    async def test_gather_techniques(self, test_report, pathfinder_svc, mocker):
        '''
            Tests the Pathfinder Service 'gather_techniques()'
        '''
        node_id = '1-2'
        node = test_report.retrieve_host_by_id(node_id)
        
        expected_result = ['315f8fcc-c05a-4db0-9f9a-5daade661540']
        future = asyncio.Future()
        future.set_result(expected_result)
        mocker.patch('plugins.pathfinder.app.pathfinder_svc.PathfinderService.get_host_exploits', return_value=future)
        
        func_result = await pathfinder_svc.gather_techniques(test_report, targeted_host=node_id)
        assert func_result == expected_result

    async def test_jsonify_host(self, test_report, pathfinder_svc, mocker):
        '''
            Tests the json-ify functionality of Pathfinder Service.
        '''
        start = '1-1'
        start_node = test_report.retrieve_host_by_id(start)

        expected_result = {'_access': 0, '_created': '2022-04-26T15:14:43Z', 
                'hostname': 'node1.local', 'ip': '10.0.0.1', 'ports': {}, 'cves': ['CVE-2014-0160'], 
                'software': [{'_access': <Access.APP: 0>, '_created': '2022-04-26T15:14:43Z', 'service_type': 'Web Browser', 'subtype': 'Google Chrome', 'notes': None}], 
                'os': {'_access': {'_value_': 0, '_name_': 'APP', '__objclass__': <enum 'Access'>}, '_created': '2022-04-26T15:14:43Z', 'os_type': 'Linux', 'subtype': None, 
                'notes': 'User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31'}, 
                'mac': None, 'freebie_abilities': ['Root password available'], 'possible_abilities': {}, 'denied_abilities': [], 'access_prob': 0.56
            }

        result = await pathfinder_svc.jsonify_host(start_node)
        assert expected_result == result
