import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import takeover

class Response:
    status_code = 404
    text = "There isn't a GitHub Pages site here."
    def close(self): pass

class TakeoverTests(unittest.TestCase):
    def test_known_provider_fingerprint(self):
        def dns(host, typ, resolver=None):
            if (host, typ) == ('docs.example.com', 'CNAME'):
                return ['old.github.io']
            if typ == 'A': return ['1.2.3.4']
            return []
        with patch.object(takeover, 'query_records', side_effect=dns):
            result = takeover.inspect_host('docs.example.com', 'example.com', http_get=lambda *a, **k: Response())
        self.assertEqual(result['status'], 'Potential takeover')

    def test_generic_404_not_fingerprint(self):
        def dns(host, typ, resolver=None):
            return ['old.github.io'] if typ == 'CNAME' and host == 'docs.example.com' else ['1.2.3.4'] if typ == 'A' else []
        class Generic(Response): text = '404 page not found'
        with patch.object(takeover, 'query_records', side_effect=dns):
            result = takeover.inspect_host('docs.example.com', 'example.com', http_get=lambda *a, **k: Generic())
        self.assertEqual(result['status'], 'No indicator')

    def test_dangling_cname(self):
        with patch.object(takeover, 'query_records', side_effect=lambda host, typ, resolver=None: ['gone.invalid'] if typ=='CNAME' and host=='x.example.com' else []):
            result = takeover.inspect_host('x.example.com','example.com')
        self.assertEqual(result['status'], 'Needs review')

    def test_out_of_scope(self):
        with self.assertRaises(ValueError):
            takeover.inspect_host('notexample.com', 'example.com')

    def test_unresolved_host_is_included(self):
        with patch.object(takeover, 'query_records', return_value=[]):
            result = takeover.scan_takeovers({'example.com':['x.example.com']})
        self.assertEqual(len(result), 1)
