"""Inert static HTML. Imported content is always escaped, never executable."""
import html
import json
from pathlib import Path


def renderer_pin():
    from la.app.storage import bounded_bytes
    from la.contracts import sha256
    return sha256(bounded_bytes(Path(__file__),limit=512*1024))


def esc(value):
    return html.escape(str(value), quote=True)


def table(headers, rows):
    return '<div class="scroll"><table><thead><tr>'+''.join('<th>'+esc(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join(
        '<tr>'+''.join('<td>'+esc(cell)+'</td>' for cell in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def block(name, value):
    return '<details><summary>'+esc(name)+'</summary><pre>'+esc(json.dumps(value, indent=2, ensure_ascii=False))+'</pre></details>'


def render_report(artifacts):
    defaults = dict(mapping_status='incomplete', transformation_status='not_run', row_parity='not_run',
                    target_validation='not_run', benchmark_status='not_run', product_acceptance='pending')
    states = dict(defaults, **artifacts.get('states', {}))
    body = '<h1>Legacy archaeology</h1><p>Evidence-bound migration candidate</p>'
    body += '<p class="notice">Mapping, transformation, parity, target, benchmark and product acceptance are separate states. Source construction does not verify runtime behavior.</p>'
    body += '<h2>Readiness</h2>'+table(['Dimension', 'State'], states.items())
    batch = artifacts.get('source_batch', {})
    if batch:
        intake = batch.get('intake', batch.get('samples', {}).get('intake', {}))
        body += '<h2>Source and framing</h2>'+table(['Item', 'Value'], [
            ['Source SHA256', batch.get('source_sha256')], ['Framing', batch.get('framing')],
            ['Width', batch.get('width')], ['Batch status', batch.get('status')],
            ['Refusal reasons', ', '.join(batch.get('reasons', []))],
            ['Observed records', intake.get('observed_record_count', len(batch.get('records', [])))],
            ['Materialized records', intake.get('materialized_record_count', len(batch.get('records', [])))],
            ['Unmaterialized records', intake.get('unmaterialized_record_count', 0)]])
        outcomes = artifacts.get('preview_outcomes', artifacts.get('outcomes', []))
        by_ordinal = {}
        for outcome in outcomes:
            by_ordinal.setdefault(outcome['record_ref']['ordinal'], []).append(outcome)
        grid = []
        for record in ([] if artifacts.get('inspection') else batch.get('records', [])):
            matching = by_ordinal.get(record['ordinal'], [])
            outcome = matching[0] if len(matching) == 1 else None
            raw = bytes.fromhex(record['raw_hex'])
            # High bytes/control characters use escaped display, no replacement decode.
            display = raw.decode('ascii', errors='backslashreplace')
            grid.append([record['ordinal'], record['byte_start'], record['length'], display,
                         record['raw_hex'], outcome['outcome'] if outcome else record['disposition'],
                         json.dumps(outcome.get('values', {}) if outcome else {}, ensure_ascii=False),
                         ', '.join(outcome.get('reasons', []) if outcome else record['reasons'])])
        if not artifacts.get('inspection'):
            body += '<h2>Row evidence and partial preview</h2><p>Preview values are diagnostic. Load rows require the current complete mapping and explicit approval; unresolved raw bytes are never load values.</p>'
            body += table(['Ordinal', 'Byte offset', 'Length', 'Raw text', 'Raw hex', 'Outcome', 'Typed preview', 'Reasons'], grid)
    page=artifacts.get('inspection')
    if page:
        body+='<h2>Bounded byte inspection</h2><p>'+esc(page['access_mode'])+' · '+esc(page['state'])+' · diagnostic bytes, not converted values</p>'
        rows=[]
        for row in page['rows']:
            rows.append([row['ordinal'], ' '.join(str(c['position']) for c in row['cells']),
                ' '.join(c['hex'] if c['hex'] is not None else '..' for c in row['cells']),
                ''.join(c['ascii'] if c['ascii'] is not None else '•' for c in row['cells']),
                json.dumps(row['window']), ', '.join(row['reasons']) or row['disposition'],
                json.dumps(row['overlays'],ensure_ascii=False)])
        body+=table(['Ordinal','Byte ruler','Hex','Diagnostic ASCII','Window','State/reasons','Candidate/selected spans'],rows)
        body+='<p>Next ordinal: '+esc(page['next_offset'])+' · unmaterialized in this page: '+esc(page['unmaterialized_in_page'])+'</p>'
        body+=block('Inspection counts and provenance',dict(counts=page['counts'],provenance=page['provenance'],inspection_sha256=page['inspection_sha256']))
        if 'preview_outcomes' in artifacts:
            ordinals={row['ordinal'] for row in page['rows']}
            body+='<h2>Partial typed preview</h2><p>Diagnostic preview is separate from approved load rows.</p>'
            body+=table(['Ordinal','Outcome','Typed values','Reasons'],[
                [row['record_ref']['ordinal'],row['outcome'],json.dumps(row.get('values',{}),ensure_ascii=False),', '.join(row.get('reasons',[]))]
                for row in artifacts['preview_outcomes'] if row['record_ref']['ordinal'] in ordinals])
    mapping = artifacts.get('mapping')
    explanations=artifacts.get('explanations')
    if explanations:
        body+='<h2>Interpretation decisions</h2><p>Offered interpretations remain unapproved. Byte patterns do not establish a business policy; choose unknown when the correct interpretation is absent.</p>'
        for field in explanations.get('fields',[]):
            candidate=field.get('candidate') or {}
            body+='<h3>'+esc(candidate.get('semantic_target','Unknown'))+' · bytes ['+esc(candidate.get('start','?'))+','+esc(candidate.get('end','?'))+')</h3>'
            body+=''.join('<p>'+esc(reason)+'</p>' for reason in field.get('decision_reasons',[]))
            body+=table(['Offered candidate','Name','Type','Policy summary'],[
                [option['candidate_id'],option['semantic_target'],option['data_type'],json.dumps(option['policy_summary'],ensure_ascii=False)]
                for option in field.get('alternatives',[])])
            body+=table(['Source ordinal','Diagnostic ASCII','Visible proof slices','Typed value'],[
                [example['record_ref']['ordinal'],''.join(cell['ascii'] if cell['ascii'] is not None else '•' for cell in example['cells']),
                 json.dumps(example['visible_evidence'],ensure_ascii=False),example['typed_value']]
                for example in field.get('examples',[])])
            body+=block('Underdetermination and provenance',dict(explanation_sha256=field['explanation_sha256'],
                examples_state=field['examples_state'],unoffered_combination_count=field.get('unoffered_combination_count'),
                dependent_row_impact=field.get('dependent_row_impact'),correct_policy_available=field['correct_policy_available']))
        body+='<p>Next physical-field index: '+esc(explanations.get('next_offset'))+'</p>'
    if mapping:
        body += '<h2>Mapping and approval</h2>'+table(['Item', 'Value'], [
            ['Mapping SHA256', mapping.get('mapping_sha256')], ['Mapping', mapping.get('mapping_status')],
            ['Unresolved', ', '.join(mapping.get('unresolved', []))],
            ['Current approval', (artifacts.get('approval') or {}).get('approval_sha256', 'absent')],
            ['Load rows available', artifacts.get('load_rows_available', False)]])
    for question in artifacts.get('questions', []):
        body += '<h2>'+esc(question.get('kind', question.get('semantic_target', 'Interpretation question')))+'</h2>'
        body += '<p>'+esc(question.get('prompt', ''))+'</p>'
        body += table(['Option', 'Interpretation'], [[o.get('id'), json.dumps(o, ensure_ascii=False)] for o in question.get('options', [])])
        body += block('Permitted byte evidence', question.get('evidence', []))
    body += '<h2>Receipts and provenance</h2><p>Migration bundles remain immutable. Execution and evaluation receipts are separate artifacts; supplied evidence does not appoint an independent product reviewer.</p>'
    for name, value in artifacts.items():
        if name not in ('source_batch', 'questions', 'preview_outcomes', 'outcomes', 'states','inspection','explanations'):
            body += block(name.replace('_', ' '), value)
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Legacy archaeology</title>'
            '<style>body{font:16px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#183044}'
            'h1{font-size:2rem}h2{margin-top:2rem}.notice{padding:1rem;background:#fff4d6}'
            'table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;vertical-align:top;padding:.6rem;border:1px solid #d3dce3;white-space:pre-wrap;overflow-wrap:anywhere}'
            'th{background:#eaf0f4}.scroll{overflow-x:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}'
            'details{margin:1rem 0}summary{cursor:pointer;font-weight:600}</style></head><body>'+body+'</body></html>')
