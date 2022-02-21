import os, sys;

os.chdir('../app')
print(os.getcwd())

from pathfinder_svc import PathfinderService as pfs
from parsers import caldera


class V2TestClass:
    v2_test_file = './v2_algo_testcase.yml'
    v2_id = 'deadbeef-6a18-4dcf-b659-79b8dd0d8d89'

    with open(v2_test_file, 'rb') as f:
        vuln_report = caldera.ReportParser.parse(f.read())

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

    def test_gather_techniques(self):
        '''
            Tests the Pathfinder Service 'gather_techniques()'
        '''
        node_id = '1-2'
        node = self.vuln_report.retrieve_host_by_id(node_id)
        expected_result = False
        func_result = pfs.gather_techniques(self.vuln_report, targeted_host=node)
        print(func_result)
        assert func_result == expected_result
