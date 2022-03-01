import os, sys, pytest


from plugins.pathfinder.app.pathfinder_svc import PathfinderService
from plugins.pathfinder.app.parsers import caldera
import networkx as nx

TEST_REPORT_PATH = os.path.join(os.path.dirname(__file__), 'data/v2_algo_testcase.yml')
PATHFINDER_V2_ID = 'deadbeef-6a18-4dcf-b659-79b8dd0d8d89'

@pytest.fixture
def test_report():
    # with open(TEST_REPORT_PATH, 'r') as fp:
        # vuln_report = 
    return caldera.ReportParser().parse(TEST_REPORT_PATH)
    # return vuln_report


@pytest.fixture
def pathfinder_svc():
    return PathfinderService(services={})

@pytest.mark.asyncio
class TestV2:
    
    async def test_generate_path_analysis(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'generate_path_analysis_report()'
        '''
        start = '1-1'
        end = '2-3'
        expected_result = {

        }
        func_result = await pathfinder_svc.generate_path_analysis_report(test_report, start, end)
        assert func_result == expected_result

    async def test_generate_exploit_graph(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'generate_exploitability_graph()'
        '''
        expected_result = {
            
        }
        func_result = await pathfinder_svc.generate_exploitability_graph(test_report)
        assert func_result == expected_result

    async def test_generate_exploitable_paths(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'generate_exploitable_paths()'
        '''
        start = '1-1'
        end = '2-3'
        exploit_graph = nx.Graph()
        nodes = []
        edges = []
        exploit_graph.add_nodes_from(nodes)
        exploit_graph.add_edges_from(edges)
        expected_result = {
            
        }
        func_result = await pathfinder_svc.generate_exploitable_paths(test_report,exploit_graph, start, end)
        assert func_result == expected_result

    async def test_create_adversary_from_path(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'create_adversary_from_path()'
        '''
        path = ['1-1','1-2','2-2','2-3']
        expected_result = {

        }
        func_result = await pathfinder_svc.create_adversary_from_path(test_report, path)
        assert func_result == expected_result

    async def test_gather_techniques(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'gather_techniques()'
        '''
        node_id = '1-2'
        node = test_report.retrieve_host_by_id(node_id)
        expected_result = False
        func_result = await pathfinder_svc.gather_techniques(test_report, targeted_host=node)
        assert func_result == expected_result
