import hashlib
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from irobot_firmware.analyze import analyze
from irobot_firmware.backfill import classic_versions
from irobot_firmware.discover import api_probe, api_probe_response
from irobot_firmware.catalog import empty_catalog, merge_records
from irobot_firmware.release_notes import render_release_notes


class CatalogTests(unittest.TestCase):
    def test_repository_catalog_json_is_valid(self):
        # This specifically guards the machine-readable catalog against an accidental
        # unresolved Git merge being committed by either a human or an Action run.
        path = Path("data/catalog.json")
        text = path.read_text()
        self.assertNotIn("<<<<<<<", text)
        self.assertNotIn(">>>>>>>", text)
        parsed = json.loads(text)
        self.assertIsInstance(parsed.get("firmwares"), list)

    def test_merge_preserves_archive(self):
        catalog = empty_catalog()
        old = {"family": "sapphire", "version": "1", "url": "u", "archive": {"sha256": "abc"}}
        catalog["firmwares"] = [old]
        merged, added = merge_records(catalog, [{"family": "sapphire", "version": "1", "url": "u", "size": 12}])
        self.assertEqual(added, 0)
        self.assertEqual(merged["firmwares"][0]["archive"]["sha256"], "abc")
        self.assertEqual(merged["firmwares"][0]["size"], 12)

    def test_classic_versions_has_padded_form(self):
        values = set(classic_versions(24, 24, 0))
        self.assertIn("24.1.0", values)
        self.assertIn("24.01.00", values)

    def test_release_notes_include_provenance(self):
        record = {
            "family": "sapphire", "version": "24.29.03",
            "url": "https://example.invalid/sapphire-24.29.03.signed",
            "source": "direct-probe", "source_sku": "j715020", "track": "prod",
        }
        analysis = {
            "filename": "sapphire-24.29.03.signed", "format": "irobot-otps",
            "components": [{
                "name": "SYSTEM", "kind": "squashfs", "size": 42,
                "sha256": "a" * 64, "metadata_hash_verified": True,
            }],
        }
        notes = render_release_notes(record, analysis, "b" * 64, 123, Path("data"))
        self.assertIn("Original OTA source", notes)
        self.assertIn("Raw discovery metadata", notes)
        self.assertIn("Roomba j7", notes)
        self.assertIn("SYSTEM", notes)
        self.assertIn("https://example.invalid/sapphire-24.29.03.signed", notes)


    def test_api_probe_matches_prime_310_dock_query_shape(self):
        seen = {}

        def fake_request(url):
            seen["url"] = url
            return {"firmware": [], "dock": {"version": "1.2.3", "track": "prod"}}

        with patch("irobot_firmware.discover._request_json", side_effect=fake_request):
            raw = api_probe_response(
                "X186020", "7.3.1", None,
                dock_fw_ver="4.5.6", dock_fw_ver_sec="7.8.9", dock_hw_rev="2",
            )
        self.assertEqual(raw["dock"]["version"], "1.2.3")
        self.assertIn("sku=X186020", seen["url"])
        self.assertIn("softwareVer=7.3.1", seen["url"])
        self.assertIn("dockFwVer=4.5.6", seen["url"])
        self.assertIn("dockFwVerSec=7.8.9", seen["url"])
        self.assertIn("dockHwRev=2", seen["url"])
        self.assertNotIn("track=", seen["url"])

    def test_api_probe_preserves_dock_recommendation_metadata(self):
        response = {
            "firmware": [{
                "version": "9.3.6",
                "sku": "X186020",
                "downloadUrl": "https://example.invalid/fw.signed",
                "deploymentMpkg": "705/fw.signed",
                "track": "prod",
            }],
            "dock": {
                "version": "2.0.1",
                "provisioningPriority": 1,
                "otaPriority": 2,
                "track": "prod",
                "expectedInstallationTime": 5,
            },
        }
        with patch("irobot_firmware.discover.api_probe_response", return_value=response):
            records = api_probe("X186020", "7.3.1", "prod", dock_fw_ver="1.0.0")
        self.assertEqual(records[0]["dock_firmware_recommendation"]["version"], "2.0.1")
        self.assertEqual(records[0]["source_dock_state"], {"dockFwVer": "1.0.0"})

    def test_synthetic_otps_component(self):
        payload = b"hello firmware"
        digest = hashlib.sha256(payload).digest()
        meta = b"Otps" + b"Otim" + b"key type D" + b"hash" + struct.pack("<I", 32) + digest
        frame = b"Otie" + struct.pack("<I", len(payload) + 17) + b"indx" + struct.pack("<I", 1) + b"\x04" + b"data" + struct.pack("<I", len(payload)) + payload
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "test.signed"
            out = root / "manifest.json"
            src.write_bytes(meta + frame)
            result = analyze(src, out, root / "work", deep=False)
            self.assertEqual(result["format"], "irobot-otps")
            self.assertEqual(result["components"][0]["name"], "SYSTEM")
            self.assertTrue(result["components"][0]["metadata_hash_verified"])


if __name__ == "__main__":
    unittest.main()
