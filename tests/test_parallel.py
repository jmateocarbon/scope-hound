import unittest
import sys
import types
from pathlib import Path
from unittest.mock import patch

if 'wappalyzer' not in sys.modules:
    module = types.ModuleType('wappalyzer')
    module.Wappalyzer = object
    sys.modules['wappalyzer'] = module
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from asm import choose_domain_workers

class WorkerSelectionTests(unittest.TestCase):
    def test_small_list_auto(self):
        with patch('asm.os.cpu_count', return_value=12):
            self.assertEqual(choose_domain_workers('auto', 3), 3)
    def test_large_list_bounded(self):
        with patch('asm.os.cpu_count', return_value=64):
            self.assertEqual(choose_domain_workers('auto', 10000), 8)
    def test_low_cpu(self):
        with patch('asm.os.cpu_count', return_value=1):
            self.assertEqual(choose_domain_workers('auto', 100), 2)
    def test_override(self):
        self.assertEqual(choose_domain_workers('12', 1000), 12)
        self.assertEqual(choose_domain_workers('12', 3), 3)
    def test_reject_bad_values(self):
        for value in ('0', '17', 'abc', '-1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                choose_domain_workers(value, 10)

if __name__ == '__main__':
    unittest.main()
