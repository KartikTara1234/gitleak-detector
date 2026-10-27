export default function History({ items, activeId, onOpen }) {
  return (
    <section className="panel history">
      <div className="panel-head">
        <h2>Recent scans</h2>
      </div>
      {items.length === 0 ? (
        <p className="muted">Scans you run will show up here.</p>
      ) : (
        <ul className="history-list">
          {items.map((s) => (
            <li key={s._id}>
              <button type="button" className={`history-item ${s._id === activeId ? 'active' : ''}`} onClick={() => onOpen(s._id)}>
                <span className={`grade-dot grade-${s.grade}`}>{s.grade}</span>
                <span className="history-repo">{s.repo}</span>
                <span className="history-meta">
                  {s.total} finding{s.total === 1 ? '' : 's'} · {s.createdAt ? new Date(s.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
