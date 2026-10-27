import { useEffect, useState } from 'react';
import { api } from '../api.js';

export default function Rules({ onClose }) {
  const [rules, setRules] = useState(null);

  useEffect(() => {
    api.rules().then(setRules).catch(() => setRules({ patterns: [], files: [] }));
    const onKey = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Detection rules" onClick={(e) => e.stopPropagation()}>
        <div className="panel-head">
          <h2>What the sweeper looks for</h2>
          <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>Close</button>
        </div>
        {!rules ? (
          <p className="muted">Loading…</p>
        ) : (
          <>
            <h3>Pattern rules</h3>
            <ul className="rules-list">
              {rules.patterns.map((r) => (
                <li key={r.id}>
                  <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                  <span>{r.name}</span>
                  <code className="muted">{r.id}</code>
                </li>
              ))}
            </ul>
            <h3>Sensitive file names</h3>
            <ul className="rules-list">
              {rules.files.map((r, i) => (
                <li key={i}>
                  <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                  <span>{r.name}</span>
                </li>
              ))}
            </ul>
            <h3>Plus</h3>
            <ul className="rules-list plain">
              <li>A Shannon-entropy detector for random-looking values assigned to credential-ish variable names.</li>
              <li>Placeholder detection (<code>your_key_here</code>, <code>${'{'}VAR{'}'}</code>, <code>process.env.X</code>, vendor doc examples) → downgraded to <em>low</em>.</li>
              <li>Findings inside <code>tests/</code>, <code>docs/</code>, fixtures and README files are downgraded one level.</li>
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
