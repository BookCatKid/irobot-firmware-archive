#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from irobot_firmware.discover import LEGACY_CONTENT_V1, legacy_v1_response

cfg=json.load(open(ROOT/'config/discovery.json'))
rows=[]; errors=[]
for sku in cfg.get('legacy_v1_skus',[]):
    try:
        body=legacy_v1_response(str(sku))
        for item in body.get('firmwareUpdateItems',[]):
            rows.append({'sku':sku, **item})
    except Exception as exc:
        errors.append({'sku':sku,'error':repr(exc)})
# endpoint repeats identical releases across regional/color SKUs; preserve SKU association
# while removing exact duplicate objects for the same SKU.
seen=set(); unique=[]
for row in rows:
    key=json.dumps(row,sort_keys=True,separators=(',',':'))
    if key not in seen:
        seen.add(key); unique.append(row)
out={
    'schema':1,
    'source':LEGACY_CONTENT_V1+'firmware/{sku}',
    'retrieved_at':datetime.now(timezone.utc).isoformat(),
    'sku_count':len(cfg.get('legacy_v1_skus',[])),
    'item_count':len(unique),
    'items':unique,
    'errors':errors,
}
path=ROOT/'data/legacy-v1-firmware-catalog.json'
path.write_text(json.dumps(out,indent=2)+"\n")
print(path,'items',len(unique),'errors',len(errors))
