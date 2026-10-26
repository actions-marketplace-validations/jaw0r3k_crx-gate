use crate::report::table::ScanFinding;
use crate::scorer::BlastRadiusScore;
use crate::taint::TaintLeakPath;

pub fn render_html_report(
    target_path: &str,
    package_type: &str,
    extension_id: Option<&str>,
    extension_name: &str,
    extension_version: &str,
    manifest_version: u32,
    score: &BlastRadiusScore,
    findings: &[ScanFinding],
    taint_paths: &[TaintLeakPath],
    duration_ms: u128,
) -> String {
    let grade_color = match score.grade.as_str() {
        "A+" | "A" => "#10b981", // green
        "B" => "#3b82f6",        // blue
        "C" => "#f59e0b",        // amber
        "D" => "#ef4444",        // red
        _ => "#dc2626",          // dark red
    };

    let ext_id_html = extension_id
        .map(|id| format!("<span class=\"badge id-badge\">ID: {}</span>", id))
        .unwrap_or_default();

    let mut findings_rows = String::new();
    for (i, f) in findings.iter().enumerate() {
        let sev_class = f.severity.to_lowercase();
        let snippet_html = if let Some(snip) = &f.snippet {
            format!("<pre class=\"code-snippet\"><code>{}</code></pre>", html_escape(snip))
        } else {
            String::new()
        };

        let loc_str = match (&f.file_path, f.line) {
            (Some(p), Some(l)) => format!("{}:{}", p, l),
            (Some(p), None) => p.clone(),
            _ => "manifest.json".into(),
        };

        findings_rows.push_str(&format!(
            r#"<div class="finding-card sev-{sev_class}" data-severity="{sev_class}">
                <div class="finding-header" onclick="toggleDetails({i})">
                    <span class="sev-pill sev-{sev_class}">{sev_upper}</span>
                    <span class="rule-id">{rule_id}</span>
                    <span class="finding-title">{title}</span>
                    <span class="finding-loc">{loc}</span>
                </div>
                <div class="finding-body" id="details-{i}">
                    <p class="finding-desc">{desc}</p>
                    {snippet_html}
                    <div class="remediation-box">
                        <strong>💡 Remediation:</strong> {fix}
                    </div>
                </div>
            </div>"#,
            sev_class = sev_class,
            sev_upper = f.severity.to_uppercase(),
            rule_id = html_escape(&f.rule_id),
            title = html_escape(&f.title),
            loc = html_escape(&loc_str),
            i = i,
            desc = html_escape(&f.description),
            snippet_html = snippet_html,
            fix = html_escape(&f.remediation)
        ));
    }

    let mut taint_cards = String::new();
    for (idx, leak) in taint_paths.iter().enumerate() {
        let mut steps_html = String::new();
        for step in &leak.flow_trace {
            steps_html.push_str(&format!(r#"<div class="trace-step"><span>➔</span> {}</div>"#, html_escape(step)));
        }

        let target_url_html = leak.sink_target_url.as_ref().map(|url| {
            format!(r#"<div class="exfil-target"><strong>Exfiltration Target:</strong> <code>{}</code></div>"#, html_escape(url))
        }).unwrap_or_default();

        taint_cards.push_str(&format!(
            r#"<div class="taint-card">
                <div class="taint-header">
                    <span class="sev-pill sev-critical">CRITICAL TAINT LEAK</span>
                    <span class="taint-summary">Flow #{idx}: <code>{src}</code> ➔ <code>{sink}</code></span>
                </div>
                <div class="taint-trace">
                    {steps_html}
                </div>
                {target_url_html}
            </div>"#,
            idx = idx + 1,
            src = html_escape(&leak.source_api),
            sink = html_escape(&leak.sink_api),
            steps_html = steps_html,
            target_url_html = target_url_html
        ));
    }

    let taint_section = if !taint_paths.is_empty() {
        format!(
            r#"<section class="section">
                <h2>🚨 Confirmed Data Exfiltration Paths (Static Taint Engine)</h2>
                {}
            </section>"#,
            taint_cards
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>crx-gate Security Audit — {ext_name}</title>
<style>
  :root {{
    --bg: #0f172a;
    --card-bg: #1e293b;
    --card-border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --primary: #38bdf8;
    --crit: #ef4444;
    --high: #f97316;
    --med: #f59e0b;
    --low: #3b82f6;
    --success: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  body {{ background: var(--bg); color: var(--text); padding: 2rem 1rem; line-height: 1.5; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--card-border); padding-bottom: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem; }}
  .logo {{ display: flex; align-items: center; gap: 0.75rem; font-size: 1.5rem; font-weight: 700; color: var(--primary); }}
  .meta {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }}
  .badge {{ background: var(--card-bg); border: 1px solid var(--card-border); padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.8rem; color: var(--text-muted); }}
  .id-badge {{ color: var(--primary); font-family: monospace; }}
  
  .dashboard-grid {{ display: grid; grid-template-columns: 280px 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
  @media (max-width: 768px) {{ .dashboard-grid {{ grid-template-columns: 1fr; }} }}
  
  .score-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }}
  .score-gauge {{ width: 140px; height: 140px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; border: 8px solid {grade_color}; margin-bottom: 1rem; box-shadow: 0 0 20px {grade_color}33; }}
  .score-grade {{ font-size: 3rem; font-weight: 900; line-height: 1; color: {grade_color}; }}
  .score-points {{ font-size: 0.9rem; color: var(--text-muted); font-weight: 600; }}
  .risk-title {{ font-size: 1.1rem; font-weight: 700; text-transform: uppercase; margin-bottom: 0.5rem; }}
  .cws-verdict {{ font-size: 0.8rem; padding: 0.25rem 0.5rem; border-radius: 6px; font-weight: 700; background: #00000044; }}

  .breakdown-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; display: flex; flex-direction: column; justify-content: space-around; gap: 1rem; }}
  .bar-item {{ display: flex; flex-direction: column; gap: 0.35rem; }}
  .bar-meta {{ display: flex; justify-content: space-between; font-size: 0.85rem; font-weight: 600; }}
  .progress-bg {{ background: #334155; border-radius: 9999px; height: 10px; overflow: hidden; }}
  .progress-fill {{ height: 100%; border-radius: 9999px; transition: width 0.3s ease; }}

  .section {{ margin-bottom: 2.5rem; }}
  .section h2 {{ font-size: 1.3rem; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }}

  .taint-card {{ background: #450a0a; border: 1px solid #dc2626; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }}
  .taint-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }}
  .taint-trace {{ background: #1c0505; border-radius: 6px; padding: 0.75rem 1rem; font-family: monospace; font-size: 0.85rem; margin-bottom: 0.5rem; }}
  .trace-step {{ color: #fecaca; margin: 0.25rem 0; }}
  .exfil-target {{ font-size: 0.85rem; color: #fca5a5; }}

  .filter-bar {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }}
  .filter-btn {{ background: var(--card-bg); border: 1px solid var(--card-border); color: var(--text); padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }}
  .filter-btn.active {{ background: var(--primary); color: #0f172a; font-weight: 700; }}

  .finding-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; margin-bottom: 0.75rem; overflow: hidden; }}
  .finding-header {{ padding: 0.9rem 1.25rem; display: flex; align-items: center; gap: 0.75rem; cursor: pointer; user-select: none; flex-wrap: wrap; }}
  .finding-header:hover {{ background: #33415544; }}
  .sev-pill {{ font-size: 0.7rem; font-weight: 800; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; }}
  .sev-critical {{ background: var(--crit); color: white; }}
  .sev-high {{ background: var(--high); color: white; }}
  .sev-medium {{ background: var(--med); color: #000; }}
  .sev-low {{ background: var(--low); color: white; }}
  .rule-id {{ font-family: monospace; color: var(--primary); font-weight: 700; font-size: 0.85rem; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-loc {{ font-family: monospace; font-size: 0.8rem; color: var(--text-muted); }}

  .finding-body {{ padding: 1rem 1.25rem; border-top: 1px solid var(--card-border); display: none; background: #0f172a88; }}
  .finding-desc {{ margin-bottom: 0.75rem; font-size: 0.9rem; }}
  .code-snippet {{ background: #00000066; padding: 0.75rem; border-radius: 6px; font-family: monospace; font-size: 0.85rem; color: #cbd5e1; margin-bottom: 0.75rem; overflow-x: auto; }}
  .remediation-box {{ background: #064e3b44; border-left: 4px solid var(--success); padding: 0.6rem 0.8rem; font-size: 0.85rem; color: #a7f3d0; border-radius: 0 4px 4px 0; }}

  footer {{ text-align: center; margin-top: 3rem; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--card-border); padding-top: 1rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">
      <span>🛡️</span> crx-gate Security Audit
    </div>
    <div class="meta">
      <span class="badge">Target: <code>{target_path}</code></span>
      <span class="badge">Type: {package_type}</span>
      <span class="badge">Extension: <strong>{ext_name}</strong> (v{ext_ver})</span>
      <span class="badge">MV{mv}</span>
      <span class="badge">Scanned in {duration_ms}ms</span>
      {ext_id_html}
    </div>
  </header>

  <div class="dashboard-grid">
    <div class="score-card">
      <div class="score-gauge">
        <span class="score-grade">{grade}</span>
        <span class="score-points">{score_total}/100</span>
      </div>
      <div class="risk-title" style="color: {grade_color};">{risk_name} RISK</div>
      <div class="cws-verdict">CWS: {cws_verdict}</div>
    </div>

    <div class="breakdown-card">
      <div class="bar-item">
        <div class="bar-meta"><span>Manifest Permissions Blast</span><span>{p_score}/30</span></div>
        <div class="progress-bg"><div class="progress-fill" style="width: {p_pct}%; background: {p_color};"></div></div>
      </div>
      <div class="bar-item">
        <div class="bar-meta"><span>Host Permissions Scope</span><span>{h_score}/25</span></div>
        <div class="progress-bg"><div class="progress-fill" style="width: {h_pct}%; background: {h_color};"></div></div>
      </div>
      <div class="bar-item">
        <div class="bar-meta"><span>Static Taint Exfiltration</span><span>{t_score}/25</span></div>
        <div class="progress-bg"><div class="progress-fill" style="width: {t_pct}%; background: {t_color};"></div></div>
      </div>
      <div class="bar-item">
        <div class="bar-meta"><span>Policy & Vulnerabilities</span><span>{v_score}/20</span></div>
        <div class="progress-bg"><div class="progress-fill" style="width: {v_pct}%; background: {v_color};"></div></div>
      </div>
    </div>
  </div>

  {taint_section}

  <section class="section">
    <h2>Detailed Findings ({findings_count})</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('all')">All ({findings_count})</button>
      <button class="filter-btn" onclick="filterFindings('critical')">Critical ({crit_cnt})</button>
      <button class="filter-btn" onclick="filterFindings('high')">High ({high_cnt})</button>
      <button class="filter-btn" onclick="filterFindings('medium')">Medium ({med_cnt})</button>
      <button class="filter-btn" onclick="filterFindings('low')">Low ({low_cnt})</button>
    </div>
    <div id="findings-container">
      {findings_rows}
    </div>
  </section>

  <footer>
    Generated deterministically by <strong>crx-gate v{pkg_ver}</strong> in {duration_ms}ms • Pre-Commit Extension Security Engine
  </footer>
</div>

<script>
function toggleDetails(id) {{
  var el = document.getElementById('details-' + id);
  el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}}

function filterFindings(sev) {{
  var cards = document.querySelectorAll('.finding-card');
  var btns = document.querySelectorAll('.filter-btn');
  btns.forEach(function(b) {{ b.classList.remove('active'); }});
  event.target.classList.add('active');

  cards.forEach(function(card) {{
    if (sev === 'all' || card.getAttribute('data-severity') === sev) {{
      card.style.display = 'block';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"#,
        ext_name = html_escape(extension_name),
        ext_ver = html_escape(extension_version),
        target_path = html_escape(target_path),
        package_type = html_escape(package_type),
        mv = manifest_version,
        duration_ms = duration_ms,
        ext_id_html = ext_id_html,
        grade_color = grade_color,
        grade = score.grade,
        score_total = score.total_score,
        risk_name = score.risk_level.as_str().to_uppercase(),
        cws_verdict = score.predicted_cws_verdict,
        p_score = score.breakdown.permissions_score,
        p_pct = (score.breakdown.permissions_score as f64 / 30.0 * 100.0).min(100.0),
        p_color = if score.breakdown.permissions_score <= 10 { "#10b981" } else { "#ef4444" },
        h_score = score.breakdown.host_scope_score,
        h_pct = (score.breakdown.host_scope_score as f64 / 25.0 * 100.0).min(100.0),
        h_color = if score.breakdown.host_scope_score <= 10 { "#3b82f6" } else { "#f97316" },
        t_score = score.breakdown.taint_exfiltration_score,
        t_pct = (score.breakdown.taint_exfiltration_score as f64 / 25.0 * 100.0).min(100.0),
        t_color = if score.breakdown.taint_exfiltration_score == 0 { "#10b981" } else { "#ef4444" },
        v_score = score.breakdown.vulnerability_score,
        v_pct = (score.breakdown.vulnerability_score as f64 / 20.0 * 100.0).min(100.0),
        v_color = if score.breakdown.vulnerability_score <= 5 { "#10b981" } else { "#ef4444" },
        taint_section = taint_section,
        findings_count = findings.len(),
        crit_cnt = score.critical_count,
        high_cnt = score.high_count,
        med_cnt = score.medium_count,
        low_cnt = score.low_count,
        findings_rows = findings_rows,
        pkg_ver = env!("CARGO_PKG_VERSION")
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
