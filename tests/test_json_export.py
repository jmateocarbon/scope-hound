import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if 'wappalyzer' not in sys.modules:
    stub = types.ModuleType('wappalyzer')
    stub.Wappalyzer = object
    sys.modules['wappalyzer'] = stub
import asm

class JSONExportTests(unittest.TestCase):
    def test_ai_report_omits_images_and_preserves_triage(self):
        with tempfile.TemporaryDirectory() as d, patch.object(asm, 'SCRIPT_DIR', d):
            path = asm.write_ai_report([{'url': 'https://example.com/', 'parent_domain': 'example.com', 'ip': '1.2.3.4', 'port': 443, 'port_source': 'Fallback candidates (unverified)', 'status': 200, 'software': ['Python'], 'b64_img': 'PRIVATE_SCREENSHOT'}],
                [{'status': 'Potential takeover', 'hostname': 'docs.example.com'}], [{'url':'https://example.com/config.json', 'status': 403, 'assessment':'Access restricted'}])
            data = json.loads(path.read_text())
            self.assertEqual(data['schema_version'], '1.0')
            self.assertEqual(data['tool_version'], '0.2.0')
            self.assertEqual(data['summary']['potential_takeovers'], 1)
            self.assertEqual(data['summary']['exposure_checks'], 1)
            self.assertNotIn('PRIVATE_SCREENSHOT', path.read_text())
            self.assertNotIn('b64_img', data['assets'][0])
    def test_only_scoped_origins_used_for_path_probes(self):
        targets = [
            {'url':'https://example.com/', 'parent_domain':'example.com'},
            {'url':'https://example.com.evil.test/', 'parent_domain':'example.com'},
            {'url':'file:///etc/passwd', 'parent_domain':'example.com'},
        ]
        with patch.object(asm, 'probe_exposure', side_effect=lambda base,path:{'url':base+path}) as mock:
            got = asm.run_exposure_checks(targets, ['/.git/HEAD'])
        self.assertEqual(len(got), 1)
        self.assertEqual(mock.call_count, 1)
    def test_report_script_is_csp_pinned(self):
        with tempfile.TemporaryDirectory() as d, patch.object(asm, 'SCRIPT_DIR', d):
            asm.generate_html([{'url':'https://example.com/', 'parent_domain':'example.com', 'ip':'1.2.3.4', 'status': 200, 'port':443,'software':['</script><script>alert(1)</script>'], 'b64_img':None}], [])
            reports = list((Path(d)/'reports').glob('*.html'))
            self.assertEqual(len(reports),1)
            body = reports[0].read_text()
            self.assertIn('Content-Security-Policy', body)
            self.assertNotIn('</script><script>alert(1)</script>', body)
if __name__ == '__main__': unittest.main()
