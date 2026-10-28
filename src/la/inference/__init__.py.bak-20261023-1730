"""Finite evidence-bound proposals. Ambiguity is retained for explicit review."""
import re
from la.contracts import REQUIRED_FIELDS, digest, sha256, validate_batch, validate_generation

POLICY = {'max_fields': 32, 'max_alternatives': 3, 'scales': [0, 2, 3]}

def hypothesize(batch: dict, brief: str, mode: str = 'rules') -> dict:
    batch = validate_batch(batch)
    if mode not in ('rules', 'mock'): raise ValueError('live mode requires separately authorized provider')
    if sha256(brief.encode()) != batch['brief_sha256']: raise ValueError('brief identity mismatch')
    candidates = []
    unknowns = []
    rows = [bytes.fromhex(r['raw_hex']) for r in batch['records'] if r['disposition'] == 'eligible']
    width = batch['width']
    if batch['status'] != 'accepted' or not rows or width is None:
        unknowns.append('input_not_eligible')
    else:
        # A transition supported by every row is evidence, never a proven business boundary.
        boundaries = {0, width}
        for index in range(1, width):
            if all((raw[index-1:index] == b' ') != (raw[index:index+1] == b' ') for raw in rows):
                boundaries.add(index)
            if all((48 <= raw[index-1] <= 57) != (48 <= raw[index] <= 57) for raw in rows):
                boundaries.add(index)
        # A shared explicit sign belongs to the numeric token that follows it.
        for index in list(boundaries):
            if 0 < index < width and all(raw[index-1] in b'+-' and 48 <= raw[index] <= 57 for raw in rows):
                boundaries.discard(index); boundaries.add(index-1)
        # Finite suffix-date proposals allow adjacent numeric amount/date fields.
        for end in list(boundaries):
            for size in (8,6):
                start=end-size
                if start > 0 and all(raw[start:end].isdigit() and
                    (raw[start:end] in (b'0'*size,b'9'*size) or
                     1 <= int(raw[end-4:end-2]) <= 12 and 1 <= int(raw[end-2:end]) <= 31) for raw in rows):
                    boundaries.add(start)
                    break
        points = sorted(boundaries)
        spans = []
        for index, (start,end) in enumerate(zip(points,points[1:])):
            if not any(raw[start:end].strip(b' ') for raw in rows): continue
            # Offer a full padded field as well as its token; selection declares trimming.
            padded_end = points[index+2] if index+2 < len(points) and all(not raw[end:points[index+2]].strip(b' ') for raw in rows) else end
            spans.append((start,padded_end))
            if padded_end != end: spans.append((start,end))
        spans = list(dict.fromkeys(spans))[:32]
        for start, end in spans:
            lexemes = [raw[start:end].decode('ascii').strip(' ') for raw in rows]
            kind = 'date' if all(re.fullmatch(r'(?:\d{8}|\d{6})', x) for x in lexemes) else 'decimal' if all(re.fullmatch(r'[+-]?\d+[+-]?', x) for x in lexemes) else 'text'
            targets = [name for name in REQUIRED_FIELDS if name in brief]
            if kind == 'decimal': targets = [n for n in targets if n in ('account_ref','balance')]
            elif kind == 'date': targets = [n for n in targets if n in ('effective_date','account_ref','balance')]
            else: targets = [n for n in targets if n in ('description','status','account_ref')]
            for target in targets:
                dtype = 'decimal' if target == 'balance' else 'date' if target == 'effective_date' else 'text'
                date_sentinels = [x for x in ('0'*(end-start),'9'*(end-start),' '*(end-start)) if x in lexemes]
                alternatives = [0,2,3] if dtype == 'decimal' else [None,'null_sentinels'] if dtype == 'date' and date_sentinels else [None]
                for scale in alternatives:
                    policy = {'padding_byte':' ', 'padding_side':'right', 'trim':True, 'nullable':False}
                    if dtype == 'decimal':
                        sign = 'leading' if all(x.startswith(('+','-')) for x in lexemes) else 'trailing' if all(x.endswith(('+','-')) for x in lexemes) else 'unsigned'
                        policy.update(scale=scale,precision=18,sign=sign)
                    if dtype == 'date':
                        policy.update(format='YYMMDD' if all(len(x)==6 for x in lexemes) else 'YYYYMMDD',sentinels={})
                        if policy['format']=='YYMMDD': policy['century_window']=[1970,2069]
                        if scale=='null_sentinels': policy.update(nullable=True,sentinels={x:'null' for x in date_sentinels})
                    evidence = [{'ordinal': r['ordinal'], 'start':start, 'end':end,
                        'source_sha256':batch['source_sha256'],'framing_sha256':batch['framing_sha256'],
                        'byte_start':r['byte_start']+start,'raw_hex':bytes.fromhex(r['raw_hex'])[start:end].hex(),
                        'raw_sha256':sha256(bytes.fromhex(r['raw_hex'])[start:end])} for r in batch['samples']['records'][:3]]
                    value = dict(start=start,end=end,semantic_target=target,data_type=dtype,policy=policy,evidence=evidence,origin=mode,uncertainty='unconfirmed_interpretation')
                    candidates.append(dict(id=digest(value),**value))
        unknowns.extend(['boundaries_require_confirmation','padding_requires_confirmation','unoffered_policy_requires_unknown'])
        if not spans: unknowns.append('no_supported_boundary_candidates')
    value = dict(schema_version=1,source_sha256=batch['source_sha256'],framing_sha256=batch['framing_sha256'],
        brief_sha256=batch['brief_sha256'],policy_sha256=digest(POLICY),candidates=candidates,unknowns=unknowns,mode=mode)
    return validate_generation(dict(value,generation_sha256=digest(value)))
