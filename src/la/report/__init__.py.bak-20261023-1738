"""Inert, escaped HTML report with distinct readiness dimensions."""
import html
import json

def render_report(artifacts: dict) -> str:
    body = ''.join('<section><h2>'+html.escape(name)+'</h2><pre>'+html.escape(json.dumps(value,indent=2,ensure_ascii=False))+'</pre></section>' for name,value in artifacts.items())
    return '<!doctype html><html><head><meta charset="utf-8"><title>Legacy archaeology</title><style>body{font:16px system-ui;max-width:1100px;margin:3rem auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}h1{color:#173a54}</style></head><body><h1>Legacy archaeology</h1><p>Migration candidate · target validation not run · product acceptance pending</p>'+body+'</body></html>'
