#!/usr/bin/env python3
"""Verify preserved SigmaStar firmware with unblob and unblob-extra.

No custom gzip, SquashFS or ext4 decompression is performed here. Metadata
checks need only the outer aPKG extraction. --full additionally checks the
filesystem extracted by unblob (requires debugfs or sasquatch, as appropriate).
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ROOT / 'data/research/sigmastar-embedded-sku-evidence-2026-11-10.json',
    ROOT / 'data/research/unblob-sigmastar-sku-evidence-2026-11-10.json',
)


def examples() -> list[dict]:
    old, new = (json.loads(path.read_text()) for path in SOURCES)
    return [
        {
            'family': r['family'], 'version': r['firmware_version'],
            'sha256': r['firmware_sha256'], 'url': r['source'],
            'sku': r['embedded_product_sku_template'],
            'sys_version': r['embedded_sys_version'],
            'sys_product': r['embedded_sys_product'],
            'sdk_version': r['embedded_sdk_version'],
        } for r in old['verified_images']
    ] + [
        {
            'family': r['family'], 'version': r['version'],
            'sha256': r['sha256'], 'url': r['archive_url'],
            'sku': r['metadata_sku'], 'sys_version': r['sys_version'],
            'sys_product': r['sys_product'], 'sdk_version': r['sdk_version'],
        } for r in new['records']
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def md5_file(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def only(root: Path, pattern: str) -> Path:
    matches = list(root.rglob(pattern))
    if len(matches) != 1:
        raise ValueError(f'Expected exactly one {pattern!r} in unblob output; found {len(matches)}')
    return matches[0]


def ini_value(path: Path, section: str, field: str) -> str:
    data = configparser.ConfigParser()
    data.read(path)
    return data[section][field]


def verify(record: dict, local_file: Path | None = None, *, full=False, no_sandbox=False, plugin_path: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix='irobot-unblob-verify-') as tmp:
        work = Path(tmp)
        package = local_file or work / 'firmware.signed'
        if local_file is None:
            subprocess.run([
                'curl', '--fail', '--location', '--silent', '--show-error',
                '--retry', '2', '--max-time', '180', '--output', str(package), record['url'],
            ], check=True)
        sha = sha256_file(package)
        if sha != record['sha256']:
            raise ValueError(f"{record['family']}: archive SHA-256 mismatch: {sha}")
        result_dir = work / 'unblob-output'
        cmd = ['unblob', '-p', '1', '-n', '0', '-d', '3' if full else '1',
               '--report', str(work / 'report.json'), '--log', str(work / 'unblob.log'),
               '--extract-dir', str(result_dir)]
        if no_sandbox:
            cmd.append('--no-sandbox')
        if plugin_path:
            cmd.extend(['--plugins-path', str(plugin_path)])
        subprocess.run(cmd + [str(package)], check=True, capture_output=True, text=True)
        report = json.loads((work / 'report.json').read_text())
        for task in report:
            for item in task.get('reports', []):
                for problem in item.get('extraction_reports', []):
                    if problem.get('severity') == 'ERROR':
                        raise ValueError(f"{record['family']}: unblob extraction problem: {problem}")
        metadata = json.loads(only(result_dir, 'SStarOta.bin.metadata.json').read_text())
        raw_metadata = only(result_dir, 'SStarOta.bin.metadata.bin')
        member = only(result_dir, 'SStarOta.bin.gz')
        if metadata.get('raw_metadata_size') != 976 or raw_metadata.stat().st_size != 976:
            raise ValueError('Unexpected SigmaStar metadata size')
        if metadata.get('sku_template') != record['sku']:
            raise ValueError(f"SKU mismatch: {metadata.get('sku_template')} != {record['sku']}")
        if metadata.get('gzip_member_md5') != md5_file(member):
            raise ValueError('Compressed gzip member MD5 mismatch')
        observed = {'family': record['family'], 'version': record['version'],
                    'sha256': sha, 'metadata_sku': metadata['sku_template'],
                    'gzip_member_md5': metadata['gzip_member_md5']}
        if full:
            sysver = only(result_dir, 'sysVersion.ini')
            sku = only(result_dir, 'product_sku.ini')
            sdk = only(result_dir, 'sdk_version.ini')
            embedded = {
                'sysProduct': ini_value(sysver, 'sysversion_Config', 'sysProduct'),
                'sysVersion': ini_value(sysver, 'sysversion_Config', 'sysVersion'),
                'sku': ini_value(sku, 'SKU_CONFIG', 'product_sku'),
                'sdk_version': sdk.read_text().strip(),
            }
            expected = {'sysProduct': record['sys_product'],
                        'sysVersion': record['sys_version'],
                        'sku': record['sku'], 'sdk_version': record['sdk_version']}
            if embedded != expected:
                raise ValueError(f'Extracted rootfs does not match evidence: {embedded} != {expected}')
            observed.update(embedded)
        return observed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', help='Limit to OTA family')
    parser.add_argument('--version', help='Limit to public firmware version')
    parser.add_argument('--local-file', type=Path, help='Use already downloaded signed firmware (one selection only)')
    parser.add_argument('--plugin-path', type=Path, help='Local unblob-extra checkout if not installed as entry point')
    parser.add_argument('--no-sandbox', action='store_true', help='Disable unblob sandbox only if unsupported by the host')
    parser.add_argument('--full', action='store_true', help='Also verify extracted ext4/SquashFS files (needs debugfs/sasquatch)')
    parser.add_argument('--list', action='store_true', help='Show recorded images without downloading')
    args = parser.parse_args()
    selected = [r for r in examples() if (not args.family or r['family'] == args.family)
                and (not args.version or r['version'] == args.version)]
    if not selected:
        parser.error('No recorded firmware matches those filters')
    if args.list:
        for record in selected:
            print(record['family'], record['version'], record['sku'], record['sha256'])
        return
    if args.local_file and len(selected) != 1:
        parser.error('--local-file needs a single --family/--version selection')
    for tool in ('curl', 'unblob'):
        if shutil.which(tool) is None:
            parser.error(f'Required executable not on PATH: {tool}')
    for record in selected:
        print(json.dumps(verify(record, args.local_file, full=args.full,
                                no_sandbox=args.no_sandbox, plugin_path=args.plugin_path), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
