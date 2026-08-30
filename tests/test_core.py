import hashlib
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from irobot_firmware.analyze import analyze, _extract_reported_identity
from irobot_firmware.backfill import classic_versions, numeric_versions
from irobot_firmware.discover import api_probe, api_probe_response, direct_probe, extract_metapackage_urls
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

    def test_merge_same_url_keeps_one_artifact_and_tracks_version_alias(self):
        catalog = empty_catalog()
        catalog["firmwares"] = [{
            "family": "lewis", "version": "22.7.2",
            "url": "https://example.invalid/lewis220702.signed",
            "archive": {"sha256": "abc"},
        }]
        merged, added = merge_records(catalog, [{
            "family": "lewis", "version": "22.07.02",
            "url": "https://example.invalid/lewis220702.signed",
            "source": "release-notes-probe",
        }])
        self.assertEqual(added, 0)
        self.assertEqual(len(merged["firmwares"]), 1)
        self.assertEqual(merged["firmwares"][0]["version"], "22.7.2")
        self.assertEqual(merged["firmwares"][0]["version_aliases"], ["22.07.02"])
        self.assertEqual(merged["firmwares"][0]["archive"]["sha256"], "abc")

    def test_merge_refresh_is_stable_and_only_enriches_missing_fields(self):
        catalog = empty_catalog()
        catalog["updated_at"] = "original-update"
        catalog["firmwares"] = [{
            "family": "705", "version": "8.6.2", "url": "u",
            "source": "content-api", "source_software_ver": "3.1.23",
            "discovered_at": "first-seen", "release_date": None,
            "archive": {"sha256": "abc"},
        }]
        merged, added = merge_records(catalog, [{
            "family": "705", "version": "8.6.2", "url": "u",
            "source": "release-notes-api", "source_software_ver": "6.4.3",
            "discovered_at": "later", "release_date": "2025-08-28",
        }])
        item = merged["firmwares"][0]
        self.assertEqual(added, 0)
        self.assertEqual(item["source"], "content-api")
        self.assertEqual(item["source_software_ver"], "3.1.23")
        self.assertEqual(item["discovered_at"], "first-seen")
        self.assertEqual(item["release_date"], "2025-08-28")
        self.assertEqual(item["archive"]["sha256"], "abc")
        self.assertNotEqual(merged["updated_at"], "original-update")

        stable_stamp = merged["updated_at"]
        merged, added = merge_records(merged, [{
            "family": "705", "version": "8.6.2", "url": "u",
            "source": "other", "discovered_at": "even-later",
        }])
        self.assertEqual(added, 0)
        self.assertEqual(merged["updated_at"], stable_stamp)

    def test_classic_versions_has_padded_form(self):
        values = set(classic_versions(24, 24, 0))
        self.assertIn("24.1.0", values)
        self.assertIn("24.01.00", values)

    def test_numeric_versions_supports_legacy_tokens(self):
        self.assertEqual(list(numeric_versions(326, 328)), ["326", "327", "328"])
        self.assertEqual(list(numeric_versions(7, 9, 4)), ["0007", "0008", "0009"])

    def test_reported_identity_resolves_compact_filename_ambiguity(self):
        components = [
            {"name": "SYSTEM", "filesystem_analysis": {"text_snapshots": {
                "build.prop": "ro.build.version.release=lewis+3.12.6+lewis-release-420+7\n",
                "opt/irobot/version.env": "OS_VERSION=linux+3.8.0+lewis-release-420+7\nPRODUCT_VERSION=3.12.6+lewis-release-420+7\n",
            }}},
            {"name": "CMNLIB", "filesystem_analysis": {"text_snapshots": {
                "opt/irobot/identity.env": "MODEL=lewis\nPRODUCT_VERSION=3.12.6+lewis-release-420+7\n",
            }}},
        ]
        identity = _extract_reported_identity(components)
        self.assertEqual(identity["model"], "lewis")
        self.assertEqual(identity["version"], "3.12.6")
        self.assertEqual(identity["product_version"], "3.12.6+lewis-release-420+7")
        self.assertEqual(identity["evidence"]["opt/irobot/identity.env"], "CMNLIB")

    def test_direct_probe_supports_padded_compact_versions(self):
        with patch("irobot_firmware.discover._exists", return_value=(False, {})) as exists:
            direct_probe("sanmarino", "22.29.6", "https://example.invalid/{family}{padded_compact}.signed")
        self.assertEqual(exists.call_args.args[0], "https://example.invalid/sanmarino222906.signed")

    def test_release_note_two_part_version_expands_patches(self):
        from irobot_firmware.discover import version_filename_candidates
        values = version_filename_candidates("22.52", 2)
        self.assertIn("22.52.0", values)
        self.assertIn("22.52.00", values)
        self.assertIn("22.52.2", values)
        self.assertIn("22.52.02", values)
        self.assertNotIn("22.52.3", values)

    def test_release_note_legacy_catalog_token_uses_vcompact(self):
        from unittest.mock import patch
        from irobot_firmware.discover import discover_from_config
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / "discovery.json"
            cfg.write_text(json.dumps({
                "release_note_probes": [{
                    "url": "https://example.invalid/notes",
                    "families": [{
                        "family": "marconi",
                        "template": "https://example.invalid/marconiv{compact}.signed",
                        "catalog_version": "vcompact"
                    }]
                }]
            }))
            with patch("irobot_firmware.discover.release_note_versions", return_value=["3.2.7"]), \
                 patch("irobot_firmware.discover.direct_probe", return_value={
                     "family": "marconi", "version": "3.2.7",
                     "url": "https://example.invalid/marconiv327.signed", "source": "direct-probe"
                 }):
                rows, errors = discover_from_config(cfg)
            self.assertFalse(errors)
            self.assertEqual(rows[0]["version"], "v327")
            self.assertEqual(rows[0]["filename_token"], "v327")
            self.assertEqual(rows[0]["release_notes_version"], "3.2.7")

    def test_swupdate_cpio_identity(self):
        def entry(name: str, payload: bytes, mode: int = 0o100644, magic: bytes = b"070702") -> bytes:
            names = name.encode() + b"\0"
            fields = [1, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(names), sum(payload) & 0xFFFFFFFF]
            header = magic + b"".join(f"{v:08X}".encode() for v in fields)
            out = header + names
            out += b"\0" * ((-len(out)) % 4)
            out += payload
            out += b"\0" * ((-len(out)) % 4)
            return out

        body = entry("sw-description", b'software : { version = "daredevil+2.4.7+daredevil-release+150"; };')
        body += entry("TRAILER!!!", b"")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "daredevil247.signed"
            src.write_bytes(body)
            result = analyze(src, root / "manifest.json", root / "work", deep=False)
        self.assertEqual(result["format"], "swupdate-cpio")
        self.assertTrue(result["cpio"]["trailer_found"])
        self.assertEqual(result["cpio"]["entries"][0]["path"], "sw-description")
        self.assertEqual(result["reported_identity"]["model"], "daredevil")
        self.assertEqual(result["reported_identity"]["version"], "2.4.7")

    def test_swupdate_identity_prefers_explicit_robot_field(self):
        from irobot_firmware.analyze import _swupdate_identity
        cpio = {"text_snapshots": {"sw-description": (
            'software : { version = "23.53.04+2024-02-21-deadbeef+Firmware-Production+197"; '
            'osversion = "linux+flint-1.23.0_release+Firmware-Production+197"; robot = "ruby"; };'
        )}}
        identity = _swupdate_identity(cpio)
        self.assertEqual(identity["model"], "ruby")
        self.assertEqual(identity["version"], "23.53.04")
        self.assertEqual(identity["os_version"], "linux+flint-1.23.0_release+Firmware-Production+197")

    def test_release_notes_include_provenance(self):
        record = {
            "family": "sapphire", "version": "24.29.03",
            "url": "https://example.invalid/sapphire-24.29.03.signed",
            "source": "direct-probe", "source_sku": "j715020", "track": "prod",
        }
        analysis = {
            "filename": "sapphire-24.29.03.signed", "format": "irobot-otps",
            "reported_identity": {"model": "sapphire", "version": "24.29.3", "product_version": "24.29.3+build"},
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
        self.assertIn("Package-reported version", notes)
        self.assertIn("24.29.3+build", notes)
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

    def test_metapackage_url_extraction_is_deduplicated_and_binary_safe(self):
        body = (
            b"aPKG\x01\x00\x00\x00"
            b"https://prod-ota-firmware.iot.irobotapi.com/lewis-22.52.08.signed\x00"
            b"junk\xff\x00"
            b"https://prod-ota-firmware.iot.irobotapi.com/lewis-22.52.08.signed\x00"
            b"https://example.invalid/other.bin\x00"
        )
        self.assertEqual(extract_metapackage_urls(body), [
            "https://prod-ota-firmware.iot.irobotapi.com/lewis-22.52.08.signed",
            "https://example.invalid/other.bin",
        ])

    def test_api_probe_preserves_metapackage_embedded_urls(self):
        response = {
            "firmware": [{
                "version": "22.52.08",
                "downloadUrl": "https://content.example/fw.signed",
                "metapackageUrl": "https://content.example/meta.signed",
                "deploymentMpkg": "lewis/fw.signed",
                "track": "prod",
            }]
        }
        with patch("irobot_firmware.discover.api_probe_response", return_value=response), \
             patch("irobot_firmware.discover.metapackage_embedded_urls", return_value=["https://legacy.example/fw.signed"]):
            records = api_probe("i800000", "22.29.3")
        self.assertEqual(records[0]["metapackage_embedded_urls"], ["https://legacy.example/fw.signed"])

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


    def test_legacy_apkg_header_is_recognized_without_guessing_fields(self):
        name = b"marconiv327.bin"
        payload = bytearray(400)
        payload[:4] = b"aPKG"
        struct.pack_into("<I", payload, 4, 1)
        struct.pack_into("<I", payload, 8, 96)
        struct.pack_into("<I", payload, 12, 256)
        payload[16:16 + len(name)] = name
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "legacy.signed"
            out = root / "manifest.json"
            src.write_bytes(payload)
            result = analyze(src, out, root / "work", deep=False)
            self.assertEqual(result["format"], "irobot-apkg")
            self.assertEqual(result["legacy_container"]["container_version"], 1)
            self.assertEqual(result["legacy_container"]["name_hint"], "marconiv327.bin")
            self.assertEqual(result["legacy_container"]["header_u32_08"], 96)
            self.assertEqual(result["legacy_container"]["header_u32_0c"], 256)

    def test_legacy_apkg_entries_are_exposed_when_bounds_validate(self):
        payload = bytearray(0x500)
        payload[:4] = b"aPKG"
        struct.pack_into("<I", payload, 4, 1)
        struct.pack_into("<I", payload, 8, 0x480)
        struct.pack_into("<I", payload, 12, 0x100)
        payload[16:16 + len(b"marconiv327.bin")] = b"marconiv327.bin"
        struct.pack_into("<I", payload, 0x30, 1)
        struct.pack_into("<III", payload, 0x34, 7, 0x400, 16)
        payload[0x40:0x40 + len(b"version1")] = b"version1"
        payload[0x400:0x410] = b"0123456789abcdef"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "legacy.signed"
            out = root / "manifest.json"
            src.write_bytes(payload)
            result = analyze(src, out, root / "work", deep=False)
            legacy = result["legacy_container"]
            self.assertEqual(legacy["entry_count"], 1)
            self.assertEqual(legacy["entries"][0]["id"], 7)
            self.assertEqual(legacy["entries"][0]["label"], "version1")
            self.assertTrue(legacy["entries"][0]["bounds_valid"])
            self.assertEqual(legacy["entries"][0]["sha256"], hashlib.sha256(b"0123456789abcdef").hexdigest())
            self.assertEqual(legacy["trailing_bytes_after_header_u32_08"], 0x80)

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
