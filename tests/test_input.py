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
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from asm import load_supplied_hosts, load_exposure_paths, PATHS_TO_CHECK, MAX_EXPOSURE_PATHS, parse_extra_web_ports, select_web_ports


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


class ExposurePathTests(unittest.TestCase):
    def load(self, content):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'paths.txt'
            p.write_text(content, encoding='utf-8')
            return load_exposure_paths(str(p))

    def test_only_root_screenshotted(self):
        self.assertEqual(PATHS_TO_CHECK, ['/'])

    def test_comment_blank_and_dedup(self):
        self.assertEqual(self.load('# comment\n/.git/HEAD\n\n/config.json\n/.git/HEAD\n'),
                         ['/.git/HEAD', '/config.json'])

    def test_reject_unsafe_paths(self):
        invalid = ['https://evil.test/x', '//evil.test/x', '/a/../b', '/%2e%2e',
                   '/a?x=1', '/foo#x', '/a\\b', '/bad\tpath']
        for value in invalid:
            with self.subTest(path=value):
                with self.assertRaises(ValueError):
                    self.load(value + '\n')

    def test_empty_and_missing_file(self):
        with self.assertRaises(ValueError):
            self.load('# comment only\n')
        with self.assertRaises(ValueError):
            load_exposure_paths('/definitely-not-existing-paths-77381.txt')

    def test_limit_enforced(self):
        with self.assertRaises(ValueError):
            self.load(''.join(f'/path{i}\n' for i in range(MAX_EXPOSURE_PATHS+1)))


class WebPortTests(unittest.TestCase):
    def test_default_standard_ports_only(self):
        self.assertEqual(select_web_ports([80, 81, 443, 8000, 8080, 8443]), [80, 443])

    def test_opt_in_common_alt_ports(self):
        extras = parse_extra_web_ports('8443,8080,8080')
        self.assertEqual(extras, (8080, 8443))
        self.assertEqual(select_web_ports([80, 81, 443, 8000, 8080, 8443], extras), [80, 443, 8080, 8443])

    def test_no_new_probe_of_unreported_alt_ports(self):
        self.assertEqual(select_web_ports([80, 443], (8080, 8443)), [80, 443])

    def test_reject_unknown_or_bad_ports(self):
        for raw in ('22', '65536', '-1', '8080,', '8080,abc', '443', '8080;8443'):
            with self.subTest(value=raw), self.assertRaises(ValueError):
                parse_extra_web_ports(raw)


if __name__ == '__main__':
    unittest.main()
