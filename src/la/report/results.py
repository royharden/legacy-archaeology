"""Closed local result projections. No evaluator, oracle, provider or DB imports."""
from __future__ import annotations

import math
import re
from decimal import Decimal,InvalidOperation

from la.contracts import canonical,digest

METHODS=('B0','B1','C0','R0','R1')
SPLITS=('development','validation','heldout')
METRICS=('semantic_rows','semantic_fields','all_record_outcomes')
STATES={'mapping_status':{'incomplete','complete'},
        'transformation_status':{'not_run','partial','complete','failed'},
        'row_parity':{'not_run','exact','mismatch','incomplete'},
        'target_validation':{'not_run','failed','indeterminate','passed'},
        'benchmark_status':{'not_run','reported_below_target','target_met'},
        'product_acceptance':{'pending'}}
ROW_KEYS={'schema_version','edition','variant_id','split','method','mode','original_mode','status',
    *STATES,'semantic_rows','semantic_fields','all_record_outcomes','questions_asked','questions_answered',
    'request_attempts','failed_attempts','known_cost_subtotal','known_total_cost','cost_known',
    'unknown_liability_count','usage','budget_violation','latency_seconds','input_sha256','release_sha256','config_sha256',
    'prompt_sha256','model_sha256','price_sha256','source_receipt_sha256','replay_receipt_sha256',
    'original_target_validation','original_transformation_status','cost_scope'}
LIMITATION='Recorded immutable receipts or explicit not_run template; no new measurements or product acceptance'


def label(value):
    if type(value) is not str or re.fullmatch('[A-Za-z0-9._-]{1,128}',value) is None:
        raise ValueError('result labels must be bounded identifiers, never paths or free text')
    return value


def count(value,*,nullable=False):
    if value is None and nullable: return None
    if type(value) is not int or not 0<=value<=1000000000: raise ValueError('invalid recorded count')
    return value


def money(value,*,nullable=False):
    if value is None and nullable: return None
    if type(value) is not str or len(value)>64: raise ValueError('exact bounded cost string required')
    try: amount=Decimal(value)
    except InvalidOperation: raise ValueError('invalid recorded cost') from None
    if not amount.is_finite() or amount<0: raise ValueError('invalid recorded cost')
    return value


def metric(value):
    if type(value) is not dict or set(value)!={'numerator','denominator','rate'}:
        raise ValueError('full recorded metric denominator required')
    n,d=value['numerator'],value['denominator']
    if n is None or d is None:
        if value!={'numerator':None,'denominator':None,'rate':None}: raise ValueError('partial not_run metric')
        return dict(value)
    count(n); count(d)
    if n>d: raise ValueError('metric numerator exceeds denominator')
    rate=value['rate']
    if (d==0 and rate is not None) or (d>0 and
        (type(rate) not in (int,float) or not math.isfinite(rate) or rate!=n/d)):
        raise ValueError('recorded rate differs from full denominator')
    return dict(value)


def validate_row(row):
    if type(row) is not dict or set(row)!=ROW_KEYS or type(row['schema_version']) is not int or row['schema_version']!=1:
        raise ValueError('closed result projection row required; raw values/paths/extra fields forbidden')
    for key in ('edition','variant_id'): label(row[key])
    if row['method'] not in METHODS or row['split'] not in SPLITS or row['mode'] not in ('rules','mock','live','replay','not_run'):
        raise ValueError('unknown recorded method/split/mode')
    if row['original_mode'] not in ('rules','mock','live',None) or row['status'] not in ('completed','partial','failed','abstained','not_run'):
        raise ValueError('unknown execution status/mode')
    for key,allowed in STATES.items():
        if row[key] not in allowed: raise ValueError('unsupported independent result state: '+key)
    if row['original_target_validation'] not in STATES['target_validation'] or row['original_transformation_status'] not in STATES['transformation_status']:
        raise ValueError('invalid recorded original state')
    if row['cost_scope'] not in ('recorded_attempts','not_run'): raise ValueError('explicit cost scope required')
    for key in METRICS: metric(row[key])
    for key in ('questions_asked','questions_answered','request_attempts','failed_attempts','unknown_liability_count'):
        count(row[key],nullable=row['status']=='not_run')
    money(row['known_cost_subtotal'],nullable=True); money(row['known_total_cost'],nullable=True)
    if type(row['cost_known']) is not bool or row['cost_known']!=(row['known_total_cost'] is not None):
        raise ValueError('known cost state cannot be fabricated')
    if row['unknown_liability_count'] and row['known_total_cost'] is not None:
        raise ValueError('unknown liability cannot become known zero/total')
    if row['known_total_cost'] is not None and (row['known_cost_subtotal'] is None
            or Decimal(row['known_total_cost'])!=Decimal(row['known_cost_subtotal'])):
        raise ValueError('known total differs from actual known attempt subtotal')
    if row['budget_violation'] is not None and type(row['budget_violation']) is not bool:
        raise ValueError('budget projection must be a typed diagnostic')
    latency=row['latency_seconds']
    if latency is not None and (type(latency) not in (int,float) or not math.isfinite(latency) or latency<0):
        raise ValueError('invalid recorded latency')
    if row['status']=='not_run' and (any(row[k]['numerator'] is not None for k in METRICS)
            or any(row[k] is not None for k in ('known_cost_subtotal','known_total_cost','request_attempts',
                'questions_asked','questions_answered','failed_attempts','unknown_liability_count','latency_seconds','budget_violation'))):
        raise ValueError('not_run template cannot contain measurements')
    for key in ROW_KEYS:
        if key.endswith('_sha256') and row[key] is not None:
            if type(row[key]) is not str or re.fullmatch('[0-9a-f]{64}',row[key]) is None: raise ValueError('invalid result identity pin')
    if type(row['usage']) is not dict or set(row['usage'])!={'input_tokens','output_tokens','cached_tokens','reasoning_tokens'}:
        raise ValueError('only numeric usage projection is permitted')
    for value in row['usage'].values(): count(value,nullable=True)
    return row


def usage_totals(attempts):
    paths={'input_tokens':('input_tokens',),'output_tokens':('output_tokens',),
           'cached_tokens':('input_tokens_details','cached_tokens'),
           'reasoning_tokens':('output_tokens_details','reasoning_tokens')}
    result={}
    for name,path in paths.items():
        values=[]
        for attempt in attempts:
            value=attempt.get('usage')
            for part in path: value=value.get(part) if type(value) is dict else None
            if type(value) is not int or value<0: break
            values.append(value)
        result[name]=sum(values) if len(values)==len(attempts) else None
    return result


def arm_row(manifest,arm,raw,*,benchmark_status,receipt_sha256,replay=None):
    score=(replay or {}).get('score',arm['score'])
    attempts=raw['attempts']
    if type(attempts) is not list or len(attempts)!=arm['request_attempts']:
        raise ValueError('attempts omitted from recorded arm')
    unknown=[a['attempt'] for a in attempts if a['cost_status']!='known']
    if unknown!=arm['unknown_liabilities'] or [a.get('usage') for a in attempts]!=arm['usage']:
        raise ValueError('usage/liability receipt disagrees with raw committed arm')
    known=sum((Decimal(money(a['known_cost'])) for a in attempts if a.get('known_cost') is not None),Decimal(0))
    if known!=Decimal(money(arm['known_cost_subtotal'])):
        raise ValueError('known cost subtotal omitted attempts')
    mapping=raw.get('mapping') or {}
    outcomes=raw['outcomes']
    if type(outcomes) is not list: raise ValueError('recorded outcomes required')
    transformed=('complete' if outcomes and all(o['outcome']=='converted' for o in outcomes)
                 and score['aggregates']['cardinality_reconciled'] and len(outcomes)==score['all_record_outcomes']['denominator']
                 else 'partial' if outcomes else 'failed' if arm['status']=='failed' else 'not_run')
    pins=manifest['pins']
    row=dict(schema_version=1,edition=label(manifest['edition']),variant_id=label(manifest['variant_id']),
        split=manifest['split'],method=arm['method'],mode='replay' if replay else arm['mode'],original_mode=arm['mode'],
        status=arm['status'],mapping_status=mapping.get('mapping_status',mapping.get('status','incomplete')),
        transformation_status='not_run' if replay else transformed,row_parity=score['row_parity'],
        target_validation='not_run' if replay else arm['target_validation'],
        original_target_validation=arm['target_validation'],original_transformation_status=transformed,cost_scope='recorded_attempts',
        benchmark_status='not_run' if replay else benchmark_status,product_acceptance='pending',
        **{key:metric(score[key]) for key in METRICS},questions_asked=arm['questions_asked'],questions_answered=arm['questions_answered'],
        request_attempts=arm['request_attempts'],failed_attempts=arm['failed_attempts'],
        known_cost_subtotal=arm['known_cost_subtotal'],known_total_cost=arm['known_total_cost'],
        cost_known=arm['known_total_cost'] is not None,unknown_liability_count=len(unknown),usage=usage_totals(attempts),
        budget_violation=((arm['request_attempts']!=(1 if arm['method']=='B1' else 0)) if arm['method'] in ('B0','B1') else arm['request_attempts']>3)
            or arm['questions_asked']>12 or arm['questions_answered']>arm['questions_asked'],
        latency_seconds=arm['latency_seconds'],
        input_sha256=manifest['input_sha256'],release_sha256=pins.get('release_sha256'),config_sha256=pins.get('config_sha256'),
        prompt_sha256=pins.get('prompt_sha256'),model_sha256=pins.get('model_sha256'),price_sha256=pins.get('price_sha256'),
        source_receipt_sha256=receipt_sha256,replay_receipt_sha256=(replay or {}).get('receipt_sha256'))
    return validate_row(row)


def not_run_rows():
    result=[]
    for split in SPLITS:
        for method in METHODS:
            row=dict(schema_version=1,edition='uninitialized',variant_id='not-recorded',split=split,method=method,
                mode='not_run',original_mode=None,status='not_run',mapping_status='incomplete',transformation_status='not_run',
                row_parity='not_run',target_validation='not_run',benchmark_status='not_run',product_acceptance='pending',
                original_target_validation='not_run',original_transformation_status='not_run',cost_scope='not_run',
                **{key:{'numerator':None,'denominator':None,'rate':None} for key in METRICS},
                questions_asked=None,questions_answered=None,request_attempts=None,failed_attempts=None,
                known_cost_subtotal=None,known_total_cost=None,cost_known=False,unknown_liability_count=None,
                usage=dict(input_tokens=None,output_tokens=None,cached_tokens=None,reasoning_tokens=None),budget_violation=None,latency_seconds=None,
                **{key:None for key in ROW_KEYS if key.endswith('_sha256')})
            result.append(validate_row(row))
    return result


def projection(rows,*,visibility,source_suite_sha256,edition_state,supersedes=None):
    if visibility not in ('not_run','public','active-hidden','retired-replay'): raise ValueError('explicit result visibility required')
    rows=[dict(validate_row(row)) for row in rows]
    if edition_state not in ('uninitialized','public','active','exposed','retired'): raise ValueError('explicit edition disposition required')
    for pin in (source_suite_sha256,supersedes):
        if pin is not None and (type(pin) is not str or re.fullmatch('[0-9a-f]{64}',pin) is None): raise ValueError('invalid report source/supersession pin')
    identities=[(r['edition'],r['split'],r['variant_id'],r['method']) for r in rows]
    if len(identities)!=len(set(identities)) or not rows or len(rows)>1024: raise ValueError('duplicate/oversize result projection')
    for edition,split,variant in {(r['edition'],r['split'],r['variant_id']) for r in rows}:
        methods={r['method'] for r in rows if r['edition']==edition and r['split']==split and r['variant_id']==variant}
        if methods!=set(METHODS): raise ValueError('all five arms must remain visible, including failed/no-output arms')
    if visibility=='public' and any(r['split']=='heldout' for r in rows): raise ValueError('hidden results cannot enter public-data route')
    if visibility=='not_run' and (source_suite_sha256 is not None or edition_state!='uninitialized' or any(r['status']!='not_run' for r in rows)):
        raise ValueError('not_run route cannot relabel recorded measurements')
    if visibility!='not_run' and source_suite_sha256 is None: raise ValueError('actual suite capture pin required')
    if visibility=='retired-replay' and edition_state!='retired': raise ValueError('actual retired edition disposition required')
    if visibility=='active-hidden':
        for row in rows: row['variant_id']='variant-'+digest(row['variant_id'])[:16]
    if visibility=='retired-replay' and any(r['mode']!='replay' for r in rows):
        raise ValueError('retired replay requires actual replay receipts; never relabel original execution')
    value=dict(schema_version=1,kind='local_result_projection',visibility=visibility,edition_state=edition_state,
        source_suite_sha256=source_suite_sha256,supersedes=supersedes,fresh_holdout=False,
        stochastic_model_rerun=False,rows=rows,
        limitation=LIMITATION)
    return dict(value,projection_sha256=digest(value))


def jsonl(value):
    return b''.join(canonical(row)+b'\n' for row in value['rows'])


def _cell(value):
    if value is None: return 'unknown'
    text=str(value)
    for old,new in (('&','&amp;'),('<','&lt;'),('>','&gt;'),('|','\\|'),('`','\\`'),('[','\\['),(']','\\]'),('\n',' '),('\r',' ')):
        text=text.replace(old,new)
    return text


def markdown(value):
    headers=['Method','Variant','Split','Mode','Original mode','Status','Exact rows n/d','Exact fields n/d','All outcomes n/d',
             'Mapping','Transform','Parity','Target','Benchmark','Product','Recorded transform','Recorded target',
             'Attempts','Cost scope','Known USD','Unknown liabilities']
    lines=['# Recorded legacy archaeology results','',
        'Projection: '+value['projection_sha256'],'',value['limitation'],'',
        'Visibility: '+value['visibility']+'; fresh holdout: false; stochastic model rerun: false.','',
        '| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']
    for r in value['rows']:
        rate=lambda name: 'not_run' if r[name]['denominator'] is None else str(r[name]['numerator'])+'/'+str(r[name]['denominator'])
        cells=[r['method'],r['variant_id'],r['split'],r['mode'],r['original_mode'],r['status'],rate('semantic_rows'),rate('semantic_fields'),rate('all_record_outcomes'),
               r['mapping_status'],r['transformation_status'],r['row_parity'],r['target_validation'],r['benchmark_status'],r['product_acceptance'],
               r['original_transformation_status'],r['original_target_validation'],
               r['request_attempts'],r['cost_scope'],r['known_total_cost'],r['unknown_liability_count']]
        lines.append('| '+' | '.join(_cell(cell) for cell in cells)+' |')
    return ('\n'.join(lines)+'\n').encode()


def publish(value,out,*,approval_sha256=None):
    """Immutable local files. Caller validates capture/approval provenance first."""
    from pathlib import Path
    import uuid
    from la.app.artifacts import within,read
    from la.app.storage import publish_bytes,bounded_bytes,atomic_directory
    from la.contracts import sha256
    expected_keys={'schema_version','kind','visibility','edition_state','source_suite_sha256','supersedes','fresh_holdout',
                   'stochastic_model_rerun','rows','limitation','projection_sha256'}
    if (set(value)!=expected_keys or value['kind']!='local_result_projection' or value['schema_version']!=1
            or value['limitation']!=LIMITATION or value['fresh_holdout'] is not False or value['stochastic_model_rerun'] is not False):
        raise ValueError('closed result projection metadata required')
    for row in value['rows']: validate_row(row)
    if value.get('projection_sha256')!=digest({k:v for k,v in value.items() if k!='projection_sha256'}):
        raise ValueError('projection content identity mismatch')
    if value['visibility']=='active-hidden' and (type(approval_sha256) is not str or re.fullmatch('[0-9a-f]{64}',approval_sha256) is None):
        raise ValueError('verified signed active-hidden projection approval required')
    out=Path(out).resolve(); out.mkdir(parents=True,exist_ok=True)
    prior=value['supersedes']
    if prior:
        previous=read(within(out,prior+'/manifest.json',exists=True),canonical_required=True)
        if previous['report_sha256']!=prior or previous['manifest_sha256']!=digest({k:v for k,v in previous.items() if k!='manifest_sha256'}):
            raise ValueError('superseded report identity mismatch')
    code=sha256(bounded_bytes(Path(__file__),limit=512*1024))
    report_id=digest({'projection_sha256':value['projection_sha256'],'publisher_code_sha256':code,'approval_sha256':approval_sha256})
    if report_id==prior: raise ValueError('report cannot supersede itself')
    files={'results.jsonl':jsonl(value),'results.md':markdown(value),'projection.json':canonical(value)+b'\n'}
    manifest=dict(schema_version=1,kind='local_result_report',report_sha256=report_id,projection_sha256=value['projection_sha256'],
        publisher_code_sha256=code,approval_sha256=approval_sha256,source_suite_sha256=value['source_suite_sha256'],
        supersedes=prior,visibility=value['visibility'],files={name:sha256(data) for name,data in files.items()})
    manifest['manifest_sha256']=digest(manifest)
    files['manifest.json']=canonical(manifest)+b'\n'
    final=within(out,report_id)
    if final.exists():
        if {p.name for p in final.iterdir()}!=set(files): raise ValueError('unexpected immutable report member')
        if any(bounded_bytes(within(final,name,exists=True))!=data for name,data in files.items()):
            raise ValueError('immutable result report collision')
    else:
        stage=within(out,'.'+report_id+'.la-tmp-'+uuid.uuid4().hex); stage.mkdir()
        for name,data in files.items(): publish_bytes(within(stage,name),data)
        atomic_directory(stage,final)
    return {'report_sha256':report_id,'projection_sha256':value['projection_sha256'],'directory':str(final),
            'markdown':str(final/'results.md'),'jsonl':str(final/'results.jsonl'),'measurements_created':False}
