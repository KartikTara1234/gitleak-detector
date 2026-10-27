import { useState } from 'react';

export default function ScanForm({ loading, onScan, onDemo }) {
  const [url, setUrl] = useState('');

  function submit(e) {
    e.preventDefault();
    if (!url.trim() || loading) return;
    onScan(url.trim());
  }

  return (
    <form className="scanform" onSubmit={submit}>
      <label htmlFor="repo" className="visually-hidden">GitHub repository URL</label>
      <div className="scanform-row">
        <input
          id="repo"
          type="text"
          placeholder="https://github.com/owner/repo  (or owner/repo)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading}
          autoComplete="off"
          spellCheck="false"
        />
        <button type="submit" className="btn btn-primary" disabled={loading || !url.trim()}>
          {loading ? 'Scanning…' : 'Scan repo'}
        </button>
      </div>
      <div className="scanform-hint">
        Public repositories only · add <code>/tree/branch</code> to scan a specific branch ·{' '}
        <button type="button" className="link" onClick={onDemo} disabled={loading}>
          scan the demo leaky repo
        </button>
      </div>
    </form>
  );
}
