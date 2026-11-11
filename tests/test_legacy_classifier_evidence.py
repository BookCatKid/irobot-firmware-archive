"""Regression checks for historical app-native SKU mapping evidence."""
import json
import unittest
from pathlib import Path

from irobot_firmware.completeness import build_completeness_ledger

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "data/research/legacy-2017-native-sku-evidence-2026-11-10.json"


class LegacyClassifierEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text())
        cls.config = json.loads((ROOT / "config/platforms.json").read_text())
        cls.catalog = json.loads((ROOT / "data/catalog.json").read_text())
        cls.legacy = json.loads((ROOT / "data/legacy-v1-firmware-catalog.json").read_text())

    def test_native_classifiers_match_recorded_elf_offsets_and_prefixes(self):
        self.assertEqual(
            {row["function"]: (row["prefix"], row["literal_va"]) for row in self.evidence["native_classifiers"]},
            {
                "core::SkuUtils::isMarconiSku": ("R69", 0x586cf8),
                "core::SkuUtils::isHertzSku": ("R89", 0x586cfc),
                "core::SkuUtils::is900SeriesSku": ("R9", 0x586d00),
            },
        )
        self.assertEqual(len(self.evidence["source"]["apk_sha256"]), 64)
        self.assertEqual(len(self.evidence["source"]["native_library_sha256"]), 64)

    def test_legacy_v1_deployment_and_official_sku_links(self):
        items = self.legacy["items"]
        by_sku = {x["sku"]: x["model"] for x in self.evidence["official_retail_identity"]}
        expected = {
            "R690020": ("marconi", "R890R690/"),
            "R890020": ("marconi", "R890R690/"),
            "R980020": ("roomba9xx", "R980R960/"),
        }
        for row in self.evidence["deployment_corroboration"]:
            sku = row["sku"]
            family, prefix = expected[sku]
            self.assertEqual(row["catalog_family"], family)
            self.assertTrue(row["deploymentMpkg"].startswith(prefix))
            self.assertTrue(any(
                x.get("sku") == sku and x.get("deploymentMpkg") == row["deploymentMpkg"]
                for x in items
            ))
            self.assertIn(sku, by_sku)

        platforms = self.config["platforms"]
        self.assertIn("R690020", platforms["marconi"]["known_skus"])
        self.assertIn("R890020", platforms["marconi"]["known_skus"])
        self.assertIn("R980020", platforms["roomba9xx"]["known_skus"])
        for sku in ("R671020", "R675020", "R677020"):
            self.assertIn(sku, platforms["ningbo"]["known_skus"])
            self.assertIn(sku, by_sku)
        self.assertEqual(platforms["marconi"]["confidence"], "confirmed-app-binary+backend+retail")
        self.assertEqual(platforms["ningbo"]["confidence"], "confirmed-app+backend+cdn+retail")

    def test_embedded_altadena_firmware_is_not_a_new_artifact(self):
        altadena = [
            row for row in self.catalog["firmwares"]
            if row["family"] == "altadena" and row["version"] == "4.60.0"
        ]
        self.assertEqual(len(altadena), 1)
        self.assertEqual(
            altadena[0]["archive"]["sha256"],
            self.evidence["embedded_firmware"]["sha256"],
        )
        self.assertEqual(
            altadena[0]["archive"]["size"],
            self.evidence["embedded_firmware"]["size"],
        )

    def test_only_platform_mapping_gaps_were_closed(self):
        ledger = build_completeness_ledger(
            self.catalog,
            self.config,
            ROOT / "data/research",
        )
        self.assertEqual(ledger["summary"]["platform_mapping_gap_count"], 8)
        self.assertEqual(ledger["summary"]["official_release_evidence_gap_count"], 48)
        self.assertEqual(ledger["summary"]["official_release_unresolved_family_count"], 3)
        remaining = {entry["family"] for entry in ledger["platform_mapping_gaps"]}
        self.assertFalse({"marconi", "roomba9xx", "ningbo"} & remaining)


if __name__ == "__main__":
    unittest.main()
