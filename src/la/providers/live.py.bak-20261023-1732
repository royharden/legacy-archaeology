"""Guarded OpenAI Responses REST source adapter. Activation/version verification deferred.

No request is made at import. Never retry an ambiguous billed attempt automatically.
"""
from __future__ import annotations
import json
import os
import sqlite3
import time
import urllib.request
from decimal import Decimal
from pathlib import Path
from la.contracts import canonical, digest

def generate_once(prompt: str, config: dict, ledger_path, *, run: str, method: str) -> dict:
    required = ('authorized','model','price_version','price_evidence_date','input_usd_per_million',
                'output_usd_per_million','total_cap_usd','max_output_tokens','activation_verified')
    if any(key not in config for key in required) or config['authorized'] is not True or config['activation_verified'] is not True:
        raise ValueError('live activation requires explicit authority, verified model/API/token bounds and dated price evidence')
    if method not in ('B1','rank'): raise ValueError('unknown provider method')
    if not config['model'] or not config['price_version'] or not config['price_evidence_date']:
        raise ValueError('model and dated price pins required')
    if not 1 <= config['max_output_tokens'] <= 2000 or len(prompt.encode('utf-8')) > 8000:
        raise ValueError('request token/byte budget exceeded')
    input_price=Decimal(config['input_usd_per_million']); output_price=Decimal(config['output_usd_per_million'])
    cap=Decimal(config['total_cap_usd'])
    if any(not n.is_finite() or n < 0 for n in (input_price,output_price,cap)) or cap == 0:
        raise ValueError('invalid price/cap')
    reserve=(8000*input_price+config['max_output_tokens']*output_price)/1000000
    path=Path(ledger_path); path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path)
    try:
        db.execute('CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY, run TEXT, method TEXT, reserve TEXT, status TEXT, receipt TEXT)')
        db.execute('BEGIN IMMEDIATE')
        prior=db.execute('SELECT reserve,status FROM calls').fetchall()
        attempts=db.execute('SELECT count(*) FROM calls WHERE run=? AND method=?',(run,method)).fetchone()[0]
        if attempts >= (1 if method=='B1' else 3): raise ValueError('attempt budget exhausted')
        if any(status in ('reserved','unknown_liability') for _,status in prior):
            raise ValueError('unreconciled liability blocks further calls')
        if sum((Decimal(amount) for amount,_ in prior),Decimal(0))+reserve > cap:
            raise ValueError('conservative total budget exhausted')
        receipt={'schema_version':1,'run':run,'method':method,'mode':'live','model':config['model'],
            'price_version':config['price_version'],'prompt_sha256':digest(prompt),'attempt':attempts+1,
            'reserved_usd':str(reserve),'cost_known':False,'cost_usd':None,'status':'reserved'}
        cursor=db.execute('INSERT INTO calls(run,method,reserve,status,receipt) VALUES(?,?,?,?,?)',
            (run,method,str(reserve),'reserved',canonical(receipt).decode()))
        call_id=cursor.lastrowid; db.commit()
        # Credential access occurs only in an explicitly activated invocation, never construction/import.
        key=os.environ.get('OPENAI_API_KEY')
        if not key:
            receipt.update(status='not_sent',cost_known=True,cost_usd='0')
            db.execute('UPDATE calls SET reserve=?,status=?,receipt=? WHERE id=?',('0','not_sent',canonical(receipt).decode(),call_id)); db.commit()
            raise ValueError('OPENAI_API_KEY missing; live does not fall back to mock')
        payload={'model':config['model'],'input':prompt,'max_output_tokens':config['max_output_tokens'],'store':False}
        request=urllib.request.Request('https://api.openai.com/v1/responses',data=canonical(payload),
            headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method='POST')
        start=time.monotonic()
        try:
            with urllib.request.urlopen(request,timeout=60) as response:
                raw=response.read(2*1024*1024+1)
            if len(raw)>2*1024*1024: raise ValueError('provider response limit')
            value=json.loads(raw)
            usage=value.get('usage',{})
            inputs=usage.get('input_tokens'); outputs=usage.get('output_tokens')
            known=type(inputs) is int and type(outputs) is int and inputs>=0 and outputs>=0
            cost=(inputs*input_price+outputs*output_price)/1000000 if known else None
            receipt.update(status='completed' if known else 'unknown_liability',cost_known=known,
                cost_usd=str(cost) if cost is not None else None,usage=usage,latency_seconds=str(time.monotonic()-start),response_sha256=digest(value))
            db.execute('UPDATE calls SET reserve=?,status=?,receipt=? WHERE id=?',
                (str(cost) if cost is not None else str(reserve),receipt['status'],canonical(receipt).decode(),call_id)); db.commit()
            texts=[part['text'] for item in value.get('output',[]) for part in item.get('content',[]) if part.get('type')=='output_text']
            return {'text':''.join(texts),'receipt':receipt}
        except Exception:
            receipt.update(status='unknown_liability',cost_known=False,cost_usd=None,latency_seconds=str(time.monotonic()-start))
            db.execute('UPDATE calls SET status=?,receipt=? WHERE id=?',('unknown_liability',canonical(receipt).decode(),call_id)); db.commit()
            raise ValueError('live attempt failed; liability unknown; no automatic retry') from None
    finally:
        db.close()

def single_pass_mapping(prompt: str, config: dict, ledger_path, *, run: str) -> dict:
    """B1 exactly one attempt. Caller validates mapping; malformed output stays failed."""
    result=generate_once(prompt,config,ledger_path,run=run,method='B1')
    try:
        mapping=json.loads(result['text'])
        if type(mapping) is not dict: raise ValueError('mapping must be object')
    except (ValueError,TypeError):
        return {'status':'failed','reason':'malformed_single_pass_output','receipt':result['receipt']}
    return {'status':'proposed','mapping':mapping,'origin':'model','receipt':result['receipt']}
