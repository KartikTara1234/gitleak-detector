import { useEffect, useState } from 'react';
import { api } from './api.js';
import ScanForm from './components/ScanForm.jsx';
import Report from './components/Report.jsx';
import History from './components/History.jsx';
import Rules from './components/Rules.jsx';

export default function App() {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(null);
  const [showRules, setShowRules] = useState(false);

  const refreshHistory = () => api.history().then(setHistory).catch(() => {});

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ ok: false }));
    refreshHistory();
  }, []);

  async function run(fn) {
    setLoading(true);
    setError(null);
    try {
      const result = await fn();
      setScan(result);
      refreshHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function openHistory(id) {
    setError(null);
    try {
      setScan(await api.getScan(id));
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32" width="26" height="26"><path d="M16 5l9 3.5v7c0 5.3-3.8 9.8-9 11.5-5.2-1.7-9-6.2-9-11.5v-7L16 5z" fill="none" stroke="currentColor" strokeWidth="2.2"/><path d="M11.5 16.5l3 3 6-6.5" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </span>
          <span className="brand-name">Repo Secret Sweeper</span>
        </div>
        <nav className="topnav">
          <button className="link" onClick={() => setShowRules(true)}>
            {health?.rules ? `${health.rules} detection rules` : 'Detection rules'}
          </button>
          <span className={`pill ${health?.ok ? 'pill-ok' : 'pill-bad'}`}>
            {health == null ? 'connecting…' : health.ok ? `API online · history: ${health.store}` : 'API offline'}
          </span>
        </nav>
      </header>

      <main className="layout">
        <section className="main-col">
          <div className="hero">
            <h1>Find leaked secrets <em>before</em> someone else does.</h1>
            <p>
              Paste a public GitHub repository. The sweeper shallow-clones it, scans every text file for API keys,
              tokens, passwords and committed <code>.env</code> files, then tells you exactly what to rotate and
              what to add to <code>.gitignore</code>. Secrets are shown masked and never stored in full.
            </p>
          </div>

          <ScanForm
            loading={loading}
            onScan={(url) => run(() => api.scan(url))}
            onDemo={() => run(() => api.scanDemo())}
          />

          {error && <div className="alert" role="alert">{error}</div>}

          {loading && (
            <div className="scanning">
              <div className="scanning-bar"><span /></div>
              <p>Cloning and scanning… large repositories can take up to a minute.</p>
            </div>
          )}

          {scan && !loading && <Report scan={scan} />}

          {!scan && !loading && !error && (
            <div className="empty">
              <p>No scan yet. Try the demo repository to see what a bad day looks like.</p>
            </div>
          )}
        </section>

        <aside className="side-col">
          <History items={history} activeId={scan?._id} onOpen={openHistory} />
        </aside>
      </main>

      {showRules && <Rules onClose={() => setShowRules(false)} />}

      <footer className="footer">
        Built for the MERN end-term project · Node + Express + React + MongoDB · Scans are read-only and clones are deleted after each run.
      </footer>
    </div>
  );
}
