import os, sys, pytest


from plugins.pathfinder.app.pathfinder_svc import PathfinderService
from plugins.pathfinder.app.parsers import caldera


TEST_REPORT_PATH = os.path.join(os.path.dirname(__file__), 'data/v2_algo_testcase.yml')
PATHFINDER_V2_ID = 'deadbeef-6a18-4dcf-b659-79b8dd0d8d89'


@pytest.fixture
def test_report():
    with open(TEST_REPORT_PATH, 'rb') as fp:
        vuln_report = caldera.ReportParser().parse(fp.read())
    return vuln_report


@pytest.fixture
def pathfinder_svc():
    return PathfinderService(services={})


class TestV2:
    
    # def test_generate_path_analysis(self):
    #     '''
    #         Tests the Pathfinder Service 'generate_path_analysis_report()'
    #     '''
    #     expected_result = {

    #     }
    #     assert pfs.generate_path_analysis_report(self.vuln_report,'1-1','2-3') ==

    # def test_generate_exploit_graph(self):
    #     '''
    #         Tests the Pathfinder Service 'generate_exploitability_graph()'
    #     '''
    #     expected_result = {
            
    #     }
    #     assert pfs.generate_exploitability_graph(self.vuln_report)

    # def test_generate_exploitable_paths(self):
    #     '''
    #         Tests the Pathfinder Service 'generate_exploitable_paths()'
    #     '''
    #     expected_result = {
            
    #     }
    #     assert func(3) == 5

    # def test_create_adversary_from_path(self):
    #     '''
    #         Tests the Pathfinder Service 'generate_path_analysis_report()'
    #     '''
    #     expected_result = {
            
    #     }
    #     assert func(3) == 5

    def test_gather_techniques(self, test_report, pathfinder_svc):
        '''
            Tests the Pathfinder Service 'gather_techniques()'
        '''
        node_id = '1-2'
        node = test_report.retrieve_host_by_id(node_id)
        expected_result = False
        func_result = pathfinder_svc.gather_techniques(test_report, targeted_host=node)
        print(func_result)
        assert func_result == expected_result
