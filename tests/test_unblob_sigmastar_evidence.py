"""Regression tests for firmware identities recovered through unblob-extra."""
import importlib.util
import json
import unittest
from pathlib import Path

from irobot_firmware.completeness import build_completeness_ledger

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'data/research/unblob-sigmastar-sku-evidence-2026-11-10.json'


class UnblobSigmastarIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.research = json.loads(EVIDENCE.read_text())
        cls.catalog = json.loads((ROOT / 'data/catalog.json').read_text())
        cls.platforms = json.loads((ROOT / 'config/platforms.json').read_text())

    def test_evidence_has_sha256_verified_catalog_sources_and_correlated_skus(self):
        records = self.research['records']
        self.assertEqual({(r['family'], r['version']) for r in records},
                         {('505', '9.3.6'), ('705', '9.3.5'), ('705', '7.5.2')})
        self.assertEqual({r['sys_product'] for r in records}, {'3IROBOTDM2'})
        for record in records:
            family = record['family']
            matching = [row for row in self.catalog['firmwares']
                        if row['family'] == family and row['version'] == record['version']
                        and row.get('archive', {}).get('sha256') == record['sha256']]
            self.assertEqual(len(matching), 1, record)
            self.assertEqual(matching[0]['archive']['asset_url'], record['archive_url'])
            self.assertEqual(record['metadata_length'], 976)
            self.assertEqual(len(record['gzip_member_md5']), 32)
            self.assertEqual(record['rootfs_format'], 'ext4')
            self.assertGreater(record['ext4_start'], 0)
            self.assertGreater(record['ext4_length'], 0)
            self.assertEqual(record['rootfs_sku'], record['metadata_sku'])
            self.assertIn(record['known_sku'], self.platforms['platforms'][family]['known_skus'])
            self.assertTrue(record['known_sku'].startswith(record['metadata_sku'][:5]))
            evidence = [item for item in self.platforms['platforms'][family]['evidence']
                        if item.get('kind') == 'unblob-extracted-firmware-sku'
                        and item.get('firmware_sha256') == record['sha256']]
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]['metadata_sku'], record['metadata_sku'])
            self.assertEqual(self.platforms['platforms'][family]['confidence'],
                             'confirmed-backend+firmware')

    def test_unblob_verifier_covers_all_seven_real_signed_images(self):
        path = ROOT / 'scripts/verify_sigmastar_sku_evidence.py'
        spec = importlib.util.spec_from_file_location('sigmastar_unblob_verifier', path)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        records = module.examples()
        self.assertEqual(len(records), 7)
        self.assertEqual({r['family'] for r in records},
                         {'105', '105v', '205', '405', '505', '705'})
        self.assertEqual({r['sku'] for r in records if r['family'] == '705'},
                         {'X1850PPKEY', 'K1550PP'})

    def test_platform_gap_reduction_does_not_erase_missing_ota_evidence(self):
        ledger = build_completeness_ledger(self.catalog, self.platforms,
                                           ROOT / 'data/research')
        self.assertEqual(ledger['summary']['platform_mapping_gap_count'], 6)
        self.assertEqual(ledger['summary']['official_release_evidence_gap_count'], 48)
        self.assertEqual(ledger['summary']['official_release_unresolved_family_count'], 3)
        self.assertNotIn('505', [r['family'] for r in ledger['platform_mapping_gaps']])
        self.assertNotIn('705', [r['family'] for r in ledger['platform_mapping_gaps']])


if __name__ == '__main__':
    unittest.main()
