"""Isolated tests for optional status-only path checking (no network requests)."""
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


class FakeResponse:
    def __init__(self, status):
        self.status_code = status
        self.entered = False
        self.exited = False
    def __enter__(self):
        self.entered = True
        return self
    def __exit__(self, *args):
        self.exited = True


class FakeSession:
    def __init__(self, status):
        self.status = status
        self.trust_env = True
        self.get_args = None
        self.response = FakeResponse(status)
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def get(self, *args, **kwargs):
        self.get_args = (args, kwargs)
        return self.response


class ExposureTests(unittest.TestCase):
    def test_status_mapping_and_safe_options(self):
        cases = {200:'Needs review', 401:'Access restricted', 403:'Access restricted',
                 404:'Not found', 410:'Not found', 302:'Redirect', 500:'Other response'}
        for status, label in cases.items():
            with self.subTest(status=status):
                fake = FakeSession(status)
                with patch.object(asm.requests, 'Session', return_value=fake):
                    record = asm.probe_exposure('https://example.com', '/.git/HEAD')
                self.assertEqual(record['status'], status)
                self.assertIn(label, record['assessment'])
                self.assertEqual(record['url'], 'https://example.com/.git/HEAD')
                self.assertEqual(set(record), {'url', 'status', 'assessment'})
                self.assertFalse(fake.trust_env)
                self.assertFalse(fake.get_args[1]['allow_redirects'])
                self.assertTrue(fake.get_args[1]['stream'])
                self.assertTrue(fake.response.exited)

    def test_network_error_classified_unreachable(self):
        from requests import Timeout
        fake = FakeSession(200)
        fake.get = lambda *a, **k: (_ for _ in ()).throw(Timeout())
        with patch.object(asm.requests, 'Session', return_value=fake):
            record = asm.probe_exposure('https://example.com', '/config.json')
        self.assertIsNone(record['status'])
        self.assertEqual(record['assessment'], 'Unreachable')

    def test_dedup_origins_and_no_browser(self):
        targets = [{'url':'https://example.com/'}, {'url':'https://example.com/.git'},
                   {'url':'http://example.com:8080/'}, {'url':'https://example.com/'}]
        with patch.object(asm, 'probe_exposure', side_effect=lambda base,p: {'url':base+p}) as probe:
            results = asm.run_exposure_checks(targets, ['/.env', '/config.json'])
        self.assertEqual(len(results), 4)
        self.assertEqual(probe.call_count, 4)
        self.assertEqual([x['url'] for x in results], sorted(x['url'] for x in results))

    def test_report_contains_no_response_bodies(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(asm, 'SCRIPT_DIR', d):
                path = asm.write_exposure_report([{'url':'https://example.com/.env','status':200,
                                                    'assessment':'Needs review'}])
                content = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(content['schema_version'], '1.0')
                self.assertEqual(len(content['checks']), 1)
                self.assertEqual(path.parent, Path(d)/'reports')
                self.assertNotIn('body', content['checks'][0])


if __name__ == '__main__':
    unittest.main()
