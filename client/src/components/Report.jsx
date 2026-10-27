import { useMemo, useState } from 'react';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function CopyButton({ text, label = 'Copy' }) {
  const [done, setDone] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch { /* clipboard blocked — nothing to do */ }
  }
  return (
    <button type="button" className="btn btn-ghost btn-sm" onClick={copy}>
      {done ? 'Copied ✓' : label}
    </button>
  );
}

function ScoreCard({ scan }) {
  const { score, grade, counts, total, stats, durationMs } = scan;
  return (
    <div className={`scorecard grade-${grade}`}>
      <div className="score-main">
        <div className="score-grade">{grade}</div>
        <div>
          <div className="score-number">{score}<span>/100</span></div>
          <div className="score-label">hygiene score</div>
        </div>
      </div>
      <div className="score-counts">
        {SEVERITIES.map((s) => (
          <div key={s} className={`count count-${s}`}>
            <span className="count-n">{counts?.[s] ?? 0}</span>
            <span className="count-l">{s}</span>
          </div>
        ))}
      </div>
      <div className="score-meta">
        <span><strong>{total}</strong> finding{total === 1 ? '' : 's'}</span>
        <span><strong>{stats?.filesScanned ?? 0}</strong> files scanned</span>
        <span><strong>{fmtBytes(stats?.bytesScanned ?? 0)}</strong> read</span>
        <span><strong>{((durationMs ?? 0) / 1000).toFixed(1)}s</strong></span>
      </div>
    </div>
  );
}

function Findings({ findings, webUrl, commit }) {
  const [filter, setFilter] = useState(new Set(SEVERITIES));
  const [hidePlaceholders, setHidePlaceholders] = useState(false);
  const [query, setQuery] = useState('');

  const visible = useMemo(() => findings
    .map((f, index) => ({ ...f, index }))
    .filter((f) =>
      filter.has(f.severity)
      && (!hidePlaceholders || !f.placeholder)
      && (!query || `${f.file} ${f.name} ${f.ruleId}`.toLowerCase().includes(query.toLowerCase()))),
  [findings, filter, hidePlaceholders, query]);

  function toggle(s) {
    const next = new Set(filter);
    next.has(s) ? next.delete(s) : next.add(s);
    setFilter(next);
  }

  const lineUrl = (f) => (webUrl && commit && f.line > 0 ? `${webUrl}/blob/${commit}/${f.file}#L${f.line}` : null);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Findings</h2>
        <div className="filters">
          {SEVERITIES.map((s) => (
            <button key={s} type="button" className={`chip chip-${s} ${filter.has(s) ? 'on' : ''}`} onClick={() => toggle(s)}>
              {s}
            </button>
          ))}
          <label className="check">
            <input type="checkbox" checked={hidePlaceholders} onChange={(e) => setHidePlaceholders(e.target.checked)} />
            hide placeholders
          </label>
          <input className="search" placeholder="filter by file or rule" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="clean">
          <strong>Clean.</strong> No secrets, keys, or sensitive files found. Nice.
        </div>
      ) : visible.length === 0 ? (
        <div className="empty-inline">Nothing matches the current filters.</div>
      ) : (
        <ul className="findings">
          {visible.map((f) => (
            <li key={f.index} className={`finding sev-${f.severity}`}>
              <div className="finding-top">
                <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                <span className="finding-name">{f.name}</span>
                <span className="finding-tags">
                  {f.placeholder && <span className="tag">placeholder</span>}
                  {f.testOrDocs && <span className="tag">test / docs</span>}
                  {f.detector === 'entropy' && <span className="tag">entropy {f.entropy}</span>}
                  {f.occurrences?.length > 0 && <span className="tag">+{f.occurrences.length} more</span>}
                </span>
              </div>
              <div className="finding-loc">
                {lineUrl(f) ? (
                  <a href={lineUrl(f)} target="_blank" rel="noreferrer">{f.file}{f.line > 0 && `:${f.line}`}</a>
                ) : (
                  <span>{f.file}{f.line > 0 && `:${f.line}`}</span>
                )}
                {f.masked && <code className="masked">{f.masked}</code>}
              </div>
              {f.line > 0 && <pre className="context"><code>{f.context}</code></pre>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Gitignore({ text }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Suggested .gitignore additions</h2>
        <CopyButton text={text} />
      </div>
      <pre className="codeblock"><code>{text}</code></pre>
      <p className="muted">
        Adding these stops <em>future</em> commits. Files already committed stay in history until you remove them
        (see the Git history step below).
      </p>
    </section>
  );
}

function Rotation({ items }) {
  const [done, setDone] = useState({});
  if (!items || items.length === 0) return null;
  const total = items.reduce((n, c) => n + c.steps.length, 0);
  const completed = Object.values(done).filter(Boolean).length;

  const asText = items.map((c) => `## ${c.label}\n${c.steps.map((s) => `- [ ] ${s}`).join('\n')}\n${c.docs}`).join('\n\n');

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Rotation checklist <span className="muted">{completed}/{total}</span></h2>
        <CopyButton text={asText} label="Copy as Markdown" />
      </div>
      <ol className="rotation">
        {items.map((c) => (
          <li key={c.provider} className="rotation-item">
            <div className="rotation-head">
              <strong>{c.label}</strong>
              {c.findings.length > 0 && (
                <span className="muted">
                  {c.findings.length} finding{c.findings.length === 1 ? '' : 's'} · {[...new Set(c.findings.map((f) => f.file))].slice(0, 3).join(', ')}
                </span>
              )}
              <a href={c.docs} target="_blank" rel="noreferrer" className="docs-link">docs ↗</a>
            </div>
            <ul className="steps">
              {c.steps.map((s, i) => {
                const k = `${c.provider}-${i}`;
                return (
                  <li key={k} className={done[k] ? 'done' : ''}>
                    <label>
                      <input type="checkbox" checked={!!done[k]} onChange={(e) => setDone({ ...done, [k]: e.target.checked })} />
                      <span>{s}</span>
                    </label>
                  </li>
                );
              })}
            </ul>
          </li>
        ))}
      </ol>
    </section>
  );
}

export default function Report({ scan }) {
  const when = scan.createdAt ? new Date(scan.createdAt).toLocaleString() : '';
  return (
    <div className="report">
      <div className="report-title">
        <h2>
          {scan.webUrl ? <a href={scan.webUrl} target="_blank" rel="noreferrer">{scan.repo}</a> : scan.repo}
          <span className="muted"> · {scan.branch}{scan.commit ? ` @ ${scan.commit}` : ''}</span>
        </h2>
        {when && <span className="muted">{when}</span>}
      </div>
      <ScoreCard scan={scan} />
      <Findings findings={scan.findings || []} webUrl={scan.webUrl} commit={scan.commit} />
      {scan.findings?.length > 0 && <Gitignore text={scan.gitignore} />}
      <Rotation items={scan.rotation} />
    </div>
  );
}
