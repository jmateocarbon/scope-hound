import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

# CLI dependencies are optional for these pure input-loader unit tests.
import sys
import types
if 'wappalyzer' not in sys.modules:
    module = types.ModuleType('wappalyzer')
    module.Wappalyzer = object
    sys.modules['wappalyzer'] = module
from asm import load_supplied_hosts


class InputTests(unittest.TestCase):
    def test_exact_host_list_and_dedup(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'hosts.txt'
            p.write_text('# comment\napi.example.com\napi.example.com\nportal.example.com\n')
            self.assertEqual(load_supplied_hosts(str(p), ['example.com']),
                             {'example.com': ['api.example.com', 'portal.example.com']})

    def test_scope_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'hosts.txt'
            p.write_text('example.com.evil.test\n')
            with self.assertRaises(ValueError):
                load_supplied_hosts(str(p), ['example.com'])

    def test_file_not_found(self):
        with self.assertRaises(ValueError):
            load_supplied_hosts('/not-present.txt', ['example.com'])


if __name__ == '__main__':
    unittest.main()
