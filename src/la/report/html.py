"""Inert static HTML. Imported content is always escaped, never executable."""
import html
import json


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
        for record in batch.get('records', []):
            matching = by_ordinal.get(record['ordinal'], [])
            outcome = matching[0] if len(matching) == 1 else None
            raw = bytes.fromhex(record['raw_hex'])
            # High bytes/control characters use escaped display, no replacement decode.
            display = raw.decode('ascii', errors='backslashreplace')
            grid.append([record['ordinal'], record['byte_start'], record['length'], display,
                         record['raw_hex'], outcome['outcome'] if outcome else record['disposition'],
                         json.dumps(outcome.get('values', {}) if outcome else {}, ensure_ascii=False),
                         ', '.join(outcome.get('reasons', []) if outcome else record['reasons'])])
        body += '<h2>Row evidence and partial preview</h2><p>Preview values are diagnostic. Load rows require the current complete mapping and explicit approval; unresolved raw bytes are never load values.</p>'
        body += table(['Ordinal', 'Byte offset', 'Length', 'Raw text', 'Raw hex', 'Outcome', 'Typed preview', 'Reasons'], grid)
    mapping = artifacts.get('mapping')
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
        if name not in ('source_batch', 'questions', 'preview_outcomes', 'outcomes', 'states'):
            body += block(name.replace('_', ' '), value)
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Legacy archaeology</title>'
            '<style>body{font:16px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#183044}'
            'h1{font-size:2rem}h2{margin-top:2rem}.notice{padding:1rem;background:#fff4d6}'
            'table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;vertical-align:top;padding:.6rem;border:1px solid #d3dce3;white-space:pre-wrap;overflow-wrap:anywhere}'
            'th{background:#eaf0f4}.scroll{overflow-x:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}'
            'details{margin:1rem 0}summary{cursor:pointer;font-weight:600}</style></head><body>'+body+'</body></html>')
