# modules/report.py
import os
from datetime import datetime
from jinja2 import Template


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attack Surface Report</title>
    <style>
        body { font-family: Arial, sans-serif; background:#f7f7f7; padding:20px; }
        h1, h2 { color:#2c3e50; }
        .host { background:#fff; padding:15px; margin-bottom:20px; border-radius:6px; }
        .risk-high { color:#c0392b; }
        .risk-medium { color:#f39c12; }
        .risk-low { color:#27ae60; }
        ul { margin-left:20px; }
        .box { background:#ecf0f1; padding:10px; border-radius:4px; margin-top:10px; }
        code { background:#eee; padding:2px 6px; border-radius:3px; }
    </style>
</head>
<body>

<h1>Attack Surface Report</h1>
<p>
<b>Target:</b> {{ target }}<br>
<b>Scan Date:</b> {{ date }}<br>
<b>Version:</b> {{ version }}
</p>

{% for host in alive_hosts %}
<div class="host">
    <h2>{{ host }}</h2>

    {% set risk = risk_scores.get(host, {}) %}
    <p>
        <b>Risk Level:</b>
        <span class="risk-{{ risk.get('level','unknown') }}">
            {{ risk.get('level','unknown') }}
        </span>
        ({{ risk.get('score',0) }})
    </p>

    {% if ports.get(host) %}
    <div class="box">
        <b>Open Ports</b>
        <ul>
        {% for p in ports.get(host, []) %}
            <li>{{ p.port }}/{{ p.proto }} – {{ p.service }} {{ p.version }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}

    {% if technologies.get(host) %}
    <div class="box">
        <b>Technologies</b>
        <ul>
        {% for t in technologies.get(host, []) %}
            <li>{{ t }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}

    {% if misconfigurations.get(host) %}
    <div class="box">
        <b>Misconfigurations</b>
        <ul>
        {% for k,v in misconfigurations.get(host,{}).items() %}
            {% for item in v %}
            <li><b>{{ k }}:</b> {{ item }}</li>
            {% endfor %}
        {% endfor %}
        </ul>
    </div>
    {% endif %}

    {% if findings.get(host) %}
    <div class="box">
        <b>Findings</b>
        <ul>
        {% for f in findings.get(host, []) %}
            <li>{{ f }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}

</div>
{% endfor %}

</body>
</html>
"""


def export_html(data: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(
        target=data.get("metadata", {}).get("target"),
        date=data.get("metadata", {}).get("scan_date"),
        version=data.get("metadata", {}).get("version"),
        **data
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

