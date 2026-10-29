"""Shape-only validators for shared dictionaries, preserving supplied bytes/keys.

Business policy legality and source/target authority stay in owner validators.
These functions return the supplied object unchanged: no defaults or stripping.
"""
import re


def closed(value,required,optional=()):
    if type(value) is not dict or not set(required)<=set(value) or set(value)-set(required)-set(optional):
        raise ValueError('closed protocol dictionary required')
    return value


def integer(value,low=0,high=1000000000):
    if type(value) is not int or not low<=value<=high: raise ValueError('bounded exact integer required')


def text(value,limit=4096):
    if type(value) is not str or len(value)>limit: raise ValueError('bounded protocol string required')


def identity(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None: raise ValueError('SHA256 identity required')


def policy_wire(value):
    closed(value,(),{'padding_byte','padding_side','trim','nullable','allowed_codes','scale','precision',
                     'sign','format','century_window','sentinels'})
    for key,item in value.items():
        if key in ('trim','nullable'):
            if type(item) is not bool: raise ValueError('exact policy boolean required')
        elif key in ('scale','precision'): integer(item,0,1000)
        elif key=='allowed_codes':
            if type(item) is not list or not 1<=len(item)<=10000: raise ValueError('bounded disclosed vocabulary required')
            for code in item: text(code,256)
        elif key=='century_window':
            if type(item) is not list or len(item)!=2: raise ValueError('two exact century endpoints required')
            for year in item: integer(year,1,9999)
        elif key=='sentinels':
            if type(item) is not dict or len(item)>2: raise ValueError('bounded explicit sentinel dictionary required')
            for lexeme,action in item.items(): text(lexeme,256); text(action,32)
        else: text(item,256)
    return value


def filler_wire(value):
    if type(value) is not list or len(value)>256: raise ValueError('bounded explicit filler spans required')
    for span in value:
        closed(span,{'start','end'}); integer(span['start'],0,255); integer(span['end'],1,256)
        if span['end']<=span['start']: raise ValueError('nonempty filler span required')
    return value


def options_wire(value):
    if type(value) is not list or not 1<=len(value)<=481: raise ValueError('bounded finite question options required')
    seen=set()
    for option in value:
        if type(option) is not dict: raise ValueError('question option must be dictionary')
        if option.get('id')=='unknown': closed(option,{'id'})
        else:
            closed(option,{'id','start','end','data_type','policy'}); identity(option['id'])
            integer(option['start'],0,255); integer(option['end'],1,256)
            if option['start']>=option['end'] or option['data_type'] not in ('text','date','decimal'):
                raise ValueError('invalid offered interpretation span/type')
            policy_wire(option['policy'])
        if option['id'] in seen: raise ValueError('duplicate offered option')
        seen.add(option['id'])
    if 'unknown' not in seen: raise ValueError('explicit unknown option required')
    return value


def outcome_evidence_wire(value):
    closed(value,{'raw_hex'},{'failure_span','proposal','template_proposal_sha256'})
    raw=value['raw_hex']; text(raw,10*1024*1024)
    if len(raw)%2 or re.fullmatch('[0-9a-f]*',raw) is None: raise ValueError('canonical raw hex required')
    for key in ('template_proposal_sha256',):
        if key in value: identity(value[key])
    if 'proposal' in value:
        proposal=closed(value['proposal'],{'proposal_sha256','method','origin','loadable','product_approval'})
        identity(proposal['proposal_sha256'])
        if (proposal['method'] not in ('B0','B1','C0','R0','R1') or proposal['origin'] not in ('rules','model','finite_candidates','agent_provisional')
                or proposal['loadable'] is not False or proposal['product_approval']!='absent'):
            raise ValueError('explicit non-loadable proposal evidence required')
    if 'failure_span' in value:
        span=closed(value['failure_span'],{'start','end','semantic_target'})
        integer(span['start'],0,255); integer(span['end'],1,256)
        if span['start']>=span['end']: raise ValueError('nonempty failed span required')
        if span['semantic_target'] not in ('account_ref','description','balance','effective_date','status'):
            raise ValueError('unknown failed semantic target')
    return value


def opaque_json(value,*,max_nodes=4096,max_depth=8,max_string=4096):
    """Bound external raw usage as data, including unsupported categories; never normalize."""
    import math
    pending=[(value,0)]; count=0
    while pending:
        item,depth=pending.pop(); count+=1
        if count>max_nodes or depth>max_depth: raise ValueError('raw JSON data exceeds bound')
        if type(item) is dict:
            for key,child in item.items(): text(key,256); pending.append((child,depth+1))
        elif type(item) is list: pending.extend((child,depth+1) for child in item)
        elif type(item) is str: text(item,max_string)
        elif item is None or type(item) is bool: pass
        elif type(item) is int:
            if item.bit_length()>256: raise ValueError('raw integer magnitude exceeds JSON bound')
        elif type(item) is float and math.isfinite(item): pass
        else: raise ValueError('raw data must remain finite JSON primitives')
    return value
