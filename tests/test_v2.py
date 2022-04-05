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
        func_result = await pathfinder_svc.generate_exploitability_graph(test_report)
        assert nx.is_isomorphic(expected_graph,func_result)

    async def test_generate_exploitable_paths(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'generate_exploitable_paths()'
        '''
        start = '1-1'
        end = '2-3'
        start_node = test_report.retrieve_host_by_id(start)
        end_node = test_report.retrieve_host_by_id(end)
        vuln_graph = await pathfinder_svc.generate_exploitability_graph(test_report)
        expected_result = nx.all_simple_paths(vuln_graph, start, end)
        
        func_result = await pathfinder_svc.generate_exploitable_paths(test_report, vuln_graph, start, end)
        assert func_result == expected_result

    async def test_create_adversary_from_path(self, test_report, pathfinder_svc, mocker):
        '''
            Tests the Pathfinder Service 'create_adversary_from_path()'
        '''
        start = '1-1'
        end = '2-3'
        vuln_graph = await pathfinder_svc.generate_exploitability_graph(test_report)
        print(vuln_graph)
        vuln_path = nx.all_simple_paths(vuln_graph, test_report.retrieve_host_by_id(start), test_report.retrieve_host_by_id(end))
        for path in vuln_path:
            print(len(path))

        expected_id = '315f8fcc-c05a-4db0-9f9a-5daade661540'
        future = asyncio.Future()
        future.set_result(expected_id)
        mocker.patch('plugins.pathfinder.app.pathfinder_svc.PathfinderService.get_host_exploits', return_value=future)

        expected_result = {}

        func_result = await pathfinder_svc.create_adversary_from_path(test_report, vuln_path)
        print(len(func_result))
        assert func_result == expected_result

    async def test_gather_techniques(self, test_report, pathfinder_svc, mocker):
        '''
            Tests the Pathfinder Service 'gather_techniques()'
        '''
        node_id = '1-2'
        node = test_report.retrieve_host_by_id(node_id)
        
        expected_result = '315f8fcc-c05a-4db0-9f9a-5daade661540'
        future = asyncio.Future()
        future.set_result(expected_result)
        mocker.patch('plugins.pathfinder.app.pathfinder_svc.PathfinderService.get_host_exploits', return_value=future)
        
        func_result = await pathfinder_svc.gather_techniques(test_report, targeted_host=node_id)
        assert func_result == expected_result
