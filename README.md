# iRobot Firmware Archive

**Website:** [smrff.dev/irobot-firmware-archive](https://smrff.dev/irobot-firmware-archive/)

An unofficial, reproducible archive/index for publicly reachable iRobot firmware. It discovers firmware, preserves the original signed package, fingerprints and inspects it, maps internal firmware platforms to observed retail hardware, and publishes a static site that can diff any two analyzed builds.

## Why it is split this way

A single modern Roomba OTA can be **~250 MiB**. Putting those blobs directly in Git would make the repository unusable and hit GitHub's normal file/repository limits quickly.

So the project uses:

- **Git:** discovery catalog, hashes, package/component metadata, filesystem manifests, site code.
- **GitHub Releases:** the original unmodified `.signed` firmware blobs.
- **GitHub Pages:** searchable firmware catalog and build-to-build diff UI.
- **Actions:** daily discovery plus optional automatic archive/upload.

The Pages diff does not need to download two 250 MiB packages. The archive action extracts a compact file manifest (path/type/size/SHA-256) from SquashFS components once, and the browser compares those manifests client-side.

## Firmware platform names vs retail models

Names such as `sapphire`, `lewis`, `sanmarino`, `soho`, `ruby`, and `stingray` are **internal firmware/platform identifiers observed in iRobot software strings and OTA packages**. They are not retail model names. Newer API results can also expose deployment identifiers such as `405`, `505`, and `705`; those are treated as backend/OTA family identifiers rather than consumer models.

The archive keeps these concepts separate:

- **Retail model / SKU:** e.g. Roomba j7, SKU `j715020`.
- **Firmware platform:** e.g. `sapphire`.
- **Firmware version:** e.g. `24.29.03`.
- **Evidence:** public or directly observed reports tying a SKU/model to a platform.

`config/platforms.json` records known associations and their confidence. The site intentionally says when a mapping is incomplete instead of guessing.

## Android app intelligence

The archive also statically analyzes official iRobot Android apps to recover product/SKU intelligence that is not exposed as a public model list. The derived, provenance-labelled data lives in `data/app-product-intelligence.json` and is used to expand recurring API probes without pretending internal codenames are retail model names. App-bundled firmware payloads can be archived with `irobot-fw import-file` and are stored in Releases just like cloud OTA images.

## Current discovery sources

The tool supports two complementary mechanisms:

1. iRobot's content firmware API (`content-prod.iot.irobotapi.com/v2/firmware`) using known/synthetic SKU probes.
2. Direct 1-byte probes of known OTA naming schemes such as `prod-ota-firmware.iot.irobotapi.com/sapphire-24.29.03.signed`.

There does not appear to be a public "list every object/version" endpoint, so **exhaustive historical coverage is a backfill/search problem rather than a single API call**. `irobot-fw backfill` exists specifically for that. The classic scanner generates padded and unpadded `YY.WW.patch` variants and can be chunked in Actions.

## Local setup

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
irobot-fw discover
irobot-fw archive --dry-run
python scripts/build_site.py
python -m http.server -d _dist 8000
```

`archive --dry-run` is intentionally the safe first step. Actual archive mode downloads large files.

## Automatic updates

`.github/workflows/check-firmware.yml` runs daily. It always refreshes discovery metadata. Binary archiving is gated by the repository variable:

`IROBOT_ARCHIVE_ENABLED=true`

Until that variable is set, scheduled checks **do not bulk-download firmware**. A manual workflow dispatch can also archive a run immediately.

When archiving is enabled, each pending build is:

1. downloaded from the original iRobot URL;
2. SHA-256 hashed;
3. parsed for signed `Otps`/`Otie` components;
4. checked against component hashes embedded in the package where available;
5. SquashFS components are extracted and file-hashed;
6. the original package **and its machine-readable analysis manifest** are uploaded as GitHub Release assets;
7. the compact manifest is committed to `data/firmware/`.

Every GitHub Release body is generated from the catalog + parsed package and includes the firmware platform, associated retail models/SKUs and mapping confidence, version/release date, original package URL, metapackage URL, discovery method and probe SKU, track/signing/fused fields, ETag/Last-Modified, archive SHA-256/size/format, a complete top-level signed-component table with integrity results, SquashFS file counts and key identity/version files, platform↔hardware evidence, and the raw discovery JSON.

The daily job processes at most six pending builds per run to keep Actions/runtime/storage bursts under control.

## Historical backfill

The **Historical firmware backfill** workflow is manual on purpose. It lets you scan one family/range at a time before deciding how much storage to consume. The default safety cap is 5,000 object probes per invocation, and `archive_found` defaults to false.

Example local dry discovery of the classic `sapphire` naming space:

```sh
irobot-fw backfill \
  --family sapphire \
  --template 'https://prod-ota-firmware.iot.irobotapi.com/{family}-{version}.signed' \
  --scheme classic \
  --year-start 23 --year-end 24 \
  --patch-max 10 --max-probes 5000
```

## Repository layout

```text
config/discovery.json       recurring API/direct probes
data/catalog.json           canonical firmware catalog
data/firmware/...           analyzed build manifests
src/irobot_firmware/        discovery/downloader/analyzer CLI
site/                       static comparison site
.github/workflows/          daily check, backfill, Pages deployment
```

## Firmware ownership / preservation note

This repository's MIT license applies to the **tooling**, not to iRobot firmware. iRobot firmware, certificates, trademarks, and other proprietary material remain the property of their respective owners. The archive records source URLs and hashes so packages can be verified as unmodified.
