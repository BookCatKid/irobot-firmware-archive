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

Deep filesystem analysis also exposes firmware that iRobot ships *inside* the robot OTA for subordinate hardware. `data/auxiliary-firmware.json` is a generated index of those aux-board bundles, including mobility, safety, power, confinement, and dock firmware packages where present. At the current archive snapshot it identifies **200 distinct auxiliary bundle SHA-256s across 8 firmware families**. The analyzer recursively inventories nested tarballs without extracting their paths, hashes leaf firmware images, and preserves explicit image versions from iRobot `download-manifest.cfg` files and dock descriptors where available. Their bytes are already preserved inside the corresponding parent firmware Release; the auxiliary index makes that embedded firmware searchable without pretending it came from an independent public download URL.

Robot audio is indexed the same way. `data/audio-assets.json` summarizes embedded songs and multilingual voice prompts without duplicating the media files into Git. At the current snapshot it covers **137,447 unique audio SHA-256s**, **9,148 semantic sound/language combinations**, **52 locale directories**, and **22 robot-song names** across **200 unique parent firmware packages**. Exact paths, hashes, and bytes remain traceable through the parent firmware manifests/Releases. The Pages search exposes one directly extractable representative for every semantic result, including its parent firmware, internal path, SHA-256, and a copyable local extraction command. `scripts/extract_audio_from_firmware.py` range-downloads only the containing SquashFS component, verifies the component/audio hashes, and writes the selected file locally.

## Completeness is evidence-based, not a fake percentage

`data/completeness.json` is the machine-readable completeness ledger. It deliberately separates:

- preserved byte-identical firmware artifacts;
- catalog aliases that point at the same SHA-256 payload;
- historical software states seen in official apps but not independently proven to have been separate OTA downloads;
- explicit software releases listed on official iRobot support pages whose exact package bytes have not yet been recovered;
- factory-only/no-OTA software states;
- SKU/platform mapping gaps; and
- already-run negative public-object probes.

At the current snapshot the 283 catalog rows represent **278 unique preserved firmware payload SHA-256s** plus **5 byte-identical aliases**. All 283 catalog rows have archived bytes. Separately, official release-note reconciliation currently leaves **51 rollout-version evidence gaps** (48 with a candidate firmware family and 3 whose family mapping is still unresolved) and **6 explicitly factory-only states**. All 51 current gaps have an explicit evidence-backed disposition, while remaining visibly unrecovered. These gap entries are *not* claimed to be 51 distinct missing blobs: some support pages cover multiple internal hardware branches, and an official version heading proves that a rollout existed without revealing its exact package filename or byte identity.

The archive therefore does not claim a literal historical “100%” unless the surviving public evidence can actually justify it. The goal is instead to drive every evidence-backed recoverable gap to zero while keeping uncertainty explicit.

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

The tool supports three complementary mechanisms:

1. iRobot's content firmware API (`content-prod.iot.irobotapi.com/v2/firmware`) using known/synthetic SKU probes.
2. Direct 1-byte probes of known OTA naming schemes such as `prod-ota-firmware.iot.irobotapi.com/sapphire-24.29.03.signed`.
3. Official iRobot software-release pages as an independent version-evidence feed. These are parsed conservatively: dates and app-version prose are excluded, and entries explicitly marked factory-only/no-OTA are not treated as missing OTA packages.

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
7. the compact manifest is committed to `data/firmware/`;
8. `data/auxiliary-firmware.json` is regenerated from deep filesystem manifests so newly preserved embedded aux-board firmware is indexed automatically.
9. `data/audio-assets.json` is regenerated so embedded robot songs and voice-prompt variants stay searchable.
10. official release-note evidence and `data/completeness.json` are refreshed so newly published versions become explicit research/backfill leads even when the firmware API does not yet return them.
11. a Release-integrity audit checks the published firmware and distinct metapackage assets against catalog byte counts and GitHub's SHA-256 digests before the metadata commit is pushed.

Every GitHub Release body is generated from the catalog + parsed package and includes the firmware platform, associated retail models/SKUs and mapping confidence, version/release date, original package URL, metapackage URL, discovery method and probe SKU, track/signing/fused fields, ETag/Last-Modified, archive SHA-256/size/format, a complete top-level signed-component table with integrity results, SquashFS file counts and key identity/version files, platform↔hardware evidence, and the raw discovery JSON.

The archive workflow does **not** impose a package-count cap. It processes every pending catalog record in the run; GitHub's own hosted-run/storage/network constraints are the only external limits.

## Historical backfill

The **Historical firmware backfill** workflow is manual on purpose so different naming families can be searched deliberately. `max_probes=0` means the requested search space is not truncated, and `archive_found` can immediately preserve every object found by the scan.

The **Enrich embedded auxiliary firmware** workflow reanalyzes already-preserved parent Release assets whose aux-board bundles predate recursive nested analysis. Jobs verify the parent archive SHA-256 before analysis and the finalize step merges only nested aux metadata back into the existing manifest, so catalog/discovery provenance is not rewritten.

Example local dry discovery of the classic `sapphire` naming space:

```sh
irobot-fw backfill \
  --family sapphire \
  --template 'https://prod-ota-firmware.iot.irobotapi.com/{family}-{version}.signed' \
  --scheme classic \
  --year-start 23 --year-end 24 \
  --patch-max 15
```

## Repository layout

```text
config/discovery.json       recurring API/direct probes
data/catalog.json           canonical firmware catalog
data/firmware/...           analyzed build manifests
data/auxiliary-firmware.json generated embedded aux-board firmware index
data/audio-assets.json      generated embedded robot-audio metadata index
data/completeness.json      evidence-based archive/research completeness ledger
data/research/...           provenance-heavy completeness/reconciliation evidence
src/irobot_firmware/        discovery/downloader/analyzer CLI
site/                       static comparison site
.github/workflows/          daily check, backfill, Pages deployment
```

## Firmware ownership / preservation note

This repository's MIT license applies to the **tooling**, not to iRobot firmware. iRobot firmware, certificates, trademarks, and other proprietary material remain the property of their respective owners. The archive records source URLs and hashes so packages can be verified as unmodified.
