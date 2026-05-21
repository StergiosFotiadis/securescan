import { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  ShieldCheck, Search, Box, FileCode2, Bot,
  CheckCircle2, XCircle, Loader2, AlertTriangle,
  Code, Terminal, Key, History, ChevronDown, ChevronRight,
  ExternalLink, User, Lock, LogOut, Trash2,
  ArrowUpDown, SlidersHorizontal, Package,
  TrendingUp, TrendingDown, Minus,
} from 'lucide-react';

import './index.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatTimestamp(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function vulnKey(v) {
  return v.cve_id || `${v.package_name}@${v.version}`;
}

function computeDelta(prevScan, currScan) {
  const prevKeys = new Set((prevScan?.vulnerabilities || []).map(vulnKey));
  const currKeys = new Set((currScan?.vulnerabilities || []).map(vulnKey));
  return {
    newVulns: currScan.vulnerabilities.filter(v => !prevKeys.has(vulnKey(v))),
    fixedVulns: (prevScan?.vulnerabilities || []).filter(v => !currKeys.has(vulnKey(v))),
  };
}

function getSeverityCounts(vulns) {
  return {
    critical: vulns.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high:     vulns.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium:   vulns.filter(v => v.severity?.toLowerCase() === 'medium').length,
    low:      vulns.filter(v => v.severity?.toLowerCase() === 'low').length,
  };
}

// ─── Shared UI ────────────────────────────────────────────────────────────────

function AIMarkdown({ children }) {
  return (
    <div className="ai-content">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>
    </div>
  );
}

function VulnCard({ vuln, isNew = false }) {
  const sev = vuln.severity?.toLowerCase() || 'high';
  return (
    <div className={`vuln-card vuln-${sev}${isNew ? ' vuln-card-new' : ''}`}>
      {isNew && <span className="vuln-new-badge">NEW</span>}
      <div className="vuln-header">
        <div>
          <div className="vuln-pkg">{vuln.package_name}</div>
          <div className="vuln-version">v{vuln.version}</div>
        </div>
        <span className={`severity-badge badge-${sev}`}>{vuln.severity}</span>
      </div>
      <p className="vuln-desc">{vuln.description}</p>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem' }}>
        {vuln.cve_id ? (
          <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`} target="_blank" rel="noopener noreferrer" className="vuln-cve">
            {vuln.cve_id}
          </a>
        ) : (
          <span className="vuln-cve" style={{ opacity: 0.5 }}>No CVE</span>
        )}
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>
          {vuln.scanner_type || 'Unknown'}
        </span>
      </div>
    </div>
  );
}

function SeverityChips({ vulnerabilities }) {
  const c = getSeverityCounts(vulnerabilities);
  if (vulnerabilities.length === 0) {
    return <span className="sev-chip sev-clean">✓ Clean</span>;
  }
  return (
    <div className="severity-chips">
      {c.critical > 0 && <span className="sev-chip sev-critical">{c.critical}C</span>}
      {c.high     > 0 && <span className="sev-chip sev-high">{c.high}H</span>}
      {c.medium   > 0 && <span className="sev-chip sev-medium">{c.medium}M</span>}
      {c.low      > 0 && <span className="sev-chip sev-low">{c.low}L</span>}
    </div>
  );
}

function TrendBadge({ scans }) {
  if (scans.length < 2) return <span className="trend-badge trend-baseline">First scan</span>;
  const { newVulns, fixedVulns } = computeDelta(scans[scans.length - 2], scans[scans.length - 1]);
  const net = newVulns.length - fixedVulns.length;
  if (net > 0)  return <span className="trend-badge trend-worse"><TrendingUp size={12} /> +{newVulns.length} new</span>;
  if (net < 0)  return <span className="trend-badge trend-better"><TrendingDown size={12} /> {fixedVulns.length} fixed</span>;
  if (newVulns.length > 0) return <span className="trend-badge trend-mixed"><Minus size={12} /> {newVulns.length} changed</span>;
  return <span className="trend-badge trend-same"><Minus size={12} /> No change</span>;
}

function VulnFilterBar({ allVulns, filterSeverity, setFilterSeverity, sortBy, setSortBy }) {
  const counts = {
    all:      allVulns.length,
    critical: allVulns.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high:     allVulns.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium:   allVulns.filter(v => v.severity?.toLowerCase() === 'medium').length,
    low:      allVulns.filter(v => v.severity?.toLowerCase() === 'low').length,
  };
  const pills = [
    { key: 'all', label: 'All' },
    { key: 'critical', label: 'Critical' },
    { key: 'high', label: 'High' },
    { key: 'medium', label: 'Medium' },
    { key: 'low', label: 'Low' },
  ];
  return (
    <div className="vuln-filter-bar">
      <div className="vuln-filter-left">
        <span className="vuln-filter-label"><SlidersHorizontal size={14} /> Filter</span>
        {pills.map(({ key, label }) =>
          (counts[key] > 0 || key === 'all') ? (
            <button
              key={key}
              className={`vuln-pill vuln-pill-${key} ${filterSeverity === key ? 'active' : ''}`}
              onClick={() => setFilterSeverity(key)}
            >
              {label}
              <span className="vuln-pill-count">{counts[key]}</span>
            </button>
          ) : null
        )}
      </div>
      <div className="vuln-filter-right">
        <span className="vuln-filter-label"><ArrowUpDown size={14} /> Sort</span>
        <button className={`vuln-sort-btn ${sortBy === 'severity' ? 'active' : ''}`} onClick={() => setSortBy('severity')}>Severity</button>
        <button className={`vuln-sort-btn ${sortBy === 'name' ? 'active' : ''}`} onClick={() => setSortBy('name')}>Package A–Z</button>
      </div>
    </div>
  );
}

// ─── Login Page ───────────────────────────────────────────────────────────────

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const credentials = btoa(`${username}:${password}`);
    try {
      const res = await fetch(`${API_URL}/history`, {
        headers: { 'Authorization': `Basic ${credentials}` },
      });
      if (res.status === 401) {
        setError('Invalid username or password. Please try again.');
      } else {
        onLogin(credentials);
      }
    } catch {
      setError('Connection failed. Check your network and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-glow" />
        <div className="login-header">
          <div className="login-icon"><ShieldCheck size={36} color="#58a6ff" /></div>
          <h1 className="logo login-title">SecureScan</h1>
          <p className="subtitle" style={{ fontSize: '1rem' }}>Sign in to access the security scanner</p>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <div className="input-wrapper">
            <User className="input-icon" size={20} />
            <input type="text" className="repo-input" placeholder="Username" value={username}
              onChange={e => setUsername(e.target.value)} disabled={loading} required autoComplete="username" autoFocus />
          </div>
          <div className="input-wrapper">
            <Lock className="input-icon" size={20} />
            <input type={showPassword ? 'text' : 'password'} className="repo-input" placeholder="Password"
              value={password} onChange={e => setPassword(e.target.value)} disabled={loading} required
              autoComplete="current-password" style={{ paddingRight: '3.5rem' }} />
            <button type="button" className="show-password-btn" onClick={() => setShowPassword(v => !v)} tabIndex={-1}>
              {showPassword ? '🙈' : '👁'}
            </button>
          </div>
          {error && (
            <div className="login-error"><AlertTriangle size={15} />{error}</div>
          )}
          <button type="submit" className={`scan-btn login-btn ${loading ? 'scanning' : ''}`}
            disabled={loading || !username || !password}>
            {loading ? <><Loader2 size={20} className="loader" /> Signing in…</> : <><ShieldCheck size={20} /> Sign In</>}
          </button>
        </form>
        <p className="login-footer">Protected by SecureScan Basic Auth</p>
      </div>
    </div>
  );
}

// ─── AI Review History ────────────────────────────────────────────────────────

function PreviousReviewItem({ review, index, total }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="ai-review-card" style={{ marginBottom: '0.75rem', borderColor: 'rgba(210,168,255,0.2)' }}>
      <button onClick={() => setOpen(o => !o)} style={{
        display: 'flex', alignItems: 'center', gap: '0.5rem',
        background: 'none', border: 'none', cursor: 'pointer',
        color: '#d2a8ff', width: '100%', padding: '0.75rem 1rem',
        fontSize: '0.9rem', fontWeight: 600,
      }}>
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        Scan {index + 1} of {total} — {formatTimestamp(review.timestamp)}
      </button>
      {open && (
        <div style={{ padding: '0 1rem 1rem', borderTop: '1px solid rgba(210,168,255,0.15)' }}>
          <AIMarkdown>{review.ai_output}</AIMarkdown>
        </div>
      )}
    </div>
  );
}

function RepoHistoryBlock({ repoUrl, reviews, onDelete }) {
  const [collapsed, setCollapsed] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    setDeleting(true);
    try { await onDelete(repoUrl); }
    finally { setDeleting(false); setConfirmDelete(false); }
  };

  return (
    <div className="repo-history-block">
      <div className="repo-history-header-row">
        <button className="repo-history-header" onClick={() => setCollapsed(c => !c)}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            {collapsed ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            <span className="repo-history-url">{repoUrl}</span>
          </span>
          <span className="repo-history-count">{reviews.length} scan{reviews.length !== 1 ? 's' : ''}</span>
        </button>
        <div className="repo-delete-area">
          {confirmDelete ? (
            <>
              <span className="repo-delete-confirm-text">Delete all scans?</span>
              <button className="repo-delete-btn repo-delete-confirm" onClick={handleDelete} disabled={deleting}>
                {deleting ? <Loader2 size={13} className="loader" /> : 'Yes, delete'}
              </button>
              <button className="repo-delete-btn repo-delete-cancel" onClick={() => setConfirmDelete(false)} disabled={deleting}>Cancel</button>
            </>
          ) : (
            <button className="repo-delete-btn repo-delete-idle" onClick={() => setConfirmDelete(true)} title="Delete history">
              <Trash2 size={15} />
            </button>
          )}
        </div>
      </div>
      {!collapsed && (
        <div style={{ padding: '0 1.5rem 1.5rem' }}>
          {reviews.map((review, i) => (
            <PreviousReviewItem key={i} review={review} index={i} total={reviews.length} />
          ))}
        </div>
      )}
    </div>
  );
}

function HistoryView({ apiFetch, onLogout }) {
  const [repos, setRepos] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);

  useEffect(() => {
    apiFetch('/history')
      .then(r => { if (!r.ok) throw new Error('Failed to load history'); return r.json(); })
      .then(data => { setRepos(data.repos); setLoading(false); })
      .catch(e => { setErr(e.message); setLoading(false); });
  }, []);

  const handleDelete = async (repoUrl) => {
    await apiFetch(`/history?repo_url=${encodeURIComponent(repoUrl)}`, { method: 'DELETE' });
    setRepos(prev => prev.filter(r => r.repo_url !== repoUrl));
  };

  return (
    <div className="app-container">
      <header>
        <h1 className="logo"><History size={40} color="#d2a8ff" />AI Review History</h1>
        <p className="subtitle">All stored AI security reviews across every scanned repository</p>
        <button className="logout-btn" onClick={onLogout}><LogOut size={15} /> Sign Out</button>
      </header>
      {loading && <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '4rem' }}>
        <Loader2 size={36} className="loader" style={{ margin: '0 auto 1rem' }} /><p>Loading history…</p>
      </div>}
      {err && <div className="dashboard"><div className="status-card" style={{ borderColor: 'rgba(255,123,114,0.3)' }}>
        <div className="status-icon-wrapper" style={{ color: '#ff7b72', background: 'rgba(255,123,114,0.1)' }}><AlertTriangle size={24} /></div>
        <div className="status-info"><h3>Error</h3><p style={{ color: '#ff7b72' }}>{err}</p></div>
      </div></div>}
      {repos && repos.length === 0 && <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '6rem' }}>
        <Bot size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} />
        <p style={{ fontSize: '1.2rem' }}>No AI reviews saved yet.</p>
        <p style={{ marginTop: '0.5rem', fontSize: '0.95rem' }}>Run a scan first to build up your history.</p>
      </div>}
      {repos && repos.length > 0 && (
        <div className="history-list">
          {repos.map(item => (
            <RepoHistoryBlock key={item.repo_url} repoUrl={item.repo_url} reviews={item.reviews} onDelete={handleDelete} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Package Vulnerability History ───────────────────────────────────────────

function FixedVulnRow({ vuln }) {
  const sev = vuln.severity?.toLowerCase() || 'high';
  return (
    <div className="fixed-vuln-row">
      <span className="fixed-badge">FIXED</span>
      <span className="vuln-pkg" style={{ fontSize: '0.95rem' }}>{vuln.package_name}</span>
      <span className="vuln-version">v{vuln.version}</span>
      {vuln.cve_id && <span className={`vuln-cve`} style={{ fontSize: '0.78rem' }}>{vuln.cve_id}</span>}
      <span className={`severity-badge badge-${sev}`} style={{ fontSize: '0.7rem', padding: '0.25rem 0.6rem' }}>{vuln.severity}</span>
    </div>
  );
}

function ScanEntry({ scan, delta, isLatest }) {
  const [open, setOpen] = useState(isLatest);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [sortBy, setSortBy] = useState('severity');

  const newVulnKeys = delta ? new Set(delta.newVulns.map(vulnKey)) : new Set();

  const filteredVulns = scan.vulnerabilities
    .filter(v => filterSeverity === 'all' || v.severity?.toLowerCase() === filterSeverity)
    .sort((a, b) => {
      if (sortBy === 'severity') {
        return (SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 4) - (SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 4);
      }
      return (a.package_name || '').localeCompare(b.package_name || '');
    });

  return (
    <div className={`scan-entry${isLatest ? ' scan-entry-latest' : ''}`}>
      <div className="scan-entry-timeline-dot" />

      <button className="scan-entry-header" onClick={() => setOpen(o => !o)}>
        <div className="scan-entry-left">
          <span className="scan-entry-date">{formatTimestamp(scan.timestamp)}</span>
          {isLatest && <span className="scan-entry-latest-tag">Latest</span>}
          <div className="scan-entry-types">
            {(scan.project_types || []).map(t => (
              <span key={t} className="project-type-chip">{t}</span>
            ))}
          </div>
        </div>
        <div className="scan-entry-right">
          <SeverityChips vulnerabilities={scan.vulnerabilities} />
          {delta ? (
            (delta.newVulns.length === 0 && delta.fixedVulns.length === 0) ? (
              <span className="delta-badge delta-same">No changes</span>
            ) : (
              <span className="delta-badge delta-mixed">
                {delta.newVulns.length > 0 && <span className="delta-part delta-part-new">+{delta.newVulns.length} new</span>}
                {delta.fixedVulns.length > 0 && <span className="delta-part delta-part-fixed">−{delta.fixedVulns.length} fixed</span>}
              </span>
            )
          ) : (
            <span className="delta-badge delta-baseline">Baseline</span>
          )}
          {open ? <ChevronDown size={15} style={{ flexShrink: 0, opacity: 0.5 }} /> : <ChevronRight size={15} style={{ flexShrink: 0, opacity: 0.5 }} />}
        </div>
      </button>

      {open && (
        <div className="scan-entry-body">
          {delta && (delta.newVulns.length > 0 || delta.fixedVulns.length > 0) && (
            <div className="scan-changes">
              {delta.newVulns.length > 0 && (
                <div className="delta-section delta-section-new">
                  <div className="delta-section-title delta-section-title-new">
                    <AlertTriangle size={14} />
                    {delta.newVulns.length} new vulnerability{delta.newVulns.length !== 1 ? 'ies' : ''} introduced
                  </div>
                  <div className="vuln-grid">
                    {delta.newVulns.map((v, i) => <VulnCard key={i} vuln={v} isNew={true} />)}
                  </div>
                </div>
              )}
              {delta.fixedVulns.length > 0 && (
                <div className="delta-section delta-section-fixed">
                  <div className="delta-section-title delta-section-title-fixed">
                    <CheckCircle2 size={14} />
                    {delta.fixedVulns.length} vulnerability{delta.fixedVulns.length !== 1 ? 'ies' : ''} resolved
                  </div>
                  <div className="fixed-vuln-list">
                    {delta.fixedVulns.map((v, i) => <FixedVulnRow key={i} vuln={v} />)}
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="scan-all-vulns">
            <div className="scan-all-header">
              All vulnerabilities
              <span className="scan-all-count">{scan.vulnerabilities.length}</span>
            </div>
            {scan.vulnerabilities.length > 0 ? (
              <>
                <VulnFilterBar
                  allVulns={scan.vulnerabilities}
                  filterSeverity={filterSeverity}
                  setFilterSeverity={setFilterSeverity}
                  sortBy={sortBy}
                  setSortBy={setSortBy}
                />
                {filteredVulns.length === 0 ? (
                  <div className="vuln-empty">No {filterSeverity} vulnerabilities in this scan.</div>
                ) : (
                  <div className="vuln-grid">
                    {filteredVulns.map((v, i) => (
                      <VulnCard key={i} vuln={v} isNew={newVulnKeys.has(vulnKey(v))} />
                    ))}
                  </div>
                )}
              </>
            ) : (
              <div className="vuln-empty">No vulnerabilities found in this scan — clean!</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function RepoVulnBlock({ repoUrl, scans, onDelete }) {
  const [collapsed, setCollapsed] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // Display newest first; delta for each scan compares against the scan before it
  const sortedScans = [...scans].reverse();

  const handleDelete = async () => {
    setDeleting(true);
    try { await onDelete(repoUrl); }
    finally { setDeleting(false); setConfirmDelete(false); }
  };

  return (
    <div className="repo-history-block">
      <div className="repo-history-header-row">
        <button className="repo-history-header" onClick={() => setCollapsed(c => !c)}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', minWidth: 0 }}>
            {collapsed ? <ChevronRight size={18} /> : <ChevronDown size={18} />}
            <span className="repo-history-url">{repoUrl}</span>
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
            <span className="repo-history-count">{scans.length} scan{scans.length !== 1 ? 's' : ''}</span>
            <TrendBadge scans={scans} />
          </span>
        </button>
        <div className="repo-delete-area">
          {confirmDelete ? (
            <>
              <span className="repo-delete-confirm-text">Delete all scans?</span>
              <button className="repo-delete-btn repo-delete-confirm" onClick={handleDelete} disabled={deleting}>
                {deleting ? <Loader2 size={13} className="loader" /> : 'Yes, delete'}
              </button>
              <button className="repo-delete-btn repo-delete-cancel" onClick={() => setConfirmDelete(false)} disabled={deleting}>Cancel</button>
            </>
          ) : (
            <button className="repo-delete-btn repo-delete-idle" onClick={() => setConfirmDelete(true)} title="Delete history">
              <Trash2 size={15} />
            </button>
          )}
        </div>
      </div>

      {!collapsed && (
        <div className="scan-timeline">
          {sortedScans.map((scan, i) => {
            // prevScan is the chronologically older scan (i+1 in the newest-first array)
            const prevScan = sortedScans[i + 1] ?? null;
            const delta = prevScan ? computeDelta(prevScan, scan) : null;
            return (
              <ScanEntry
                key={scan.timestamp}
                scan={scan}
                delta={delta}
                isLatest={i === 0}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

function PackageHistoryView({ apiFetch, onLogout }) {
  const [repos, setRepos] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);

  useEffect(() => {
    apiFetch('/vuln-history')
      .then(r => { if (!r.ok) throw new Error('Failed to load vulnerability history'); return r.json(); })
      .then(data => { setRepos(data.repos); setLoading(false); })
      .catch(e => { setErr(e.message); setLoading(false); });
  }, []);

  const handleDelete = async (repoUrl) => {
    await apiFetch(`/vuln-history?repo_url=${encodeURIComponent(repoUrl)}`, { method: 'DELETE' });
    setRepos(prev => prev.filter(r => r.repo_url !== repoUrl));
  };

  return (
    <div className="app-container">
      <header>
        <h1 className="logo"><Package size={40} color="#58a6ff" />Package History</h1>
        <p className="subtitle">Vulnerability trend across all scanned repositories — track what's introduced and what's fixed</p>
        <button className="logout-btn" onClick={onLogout}><LogOut size={15} /> Sign Out</button>
      </header>

      {loading && <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '4rem' }}>
        <Loader2 size={36} className="loader" style={{ margin: '0 auto 1rem' }} /><p>Loading history…</p>
      </div>}

      {err && <div className="dashboard"><div className="status-card" style={{ borderColor: 'rgba(255,123,114,0.3)' }}>
        <div className="status-icon-wrapper" style={{ color: '#ff7b72', background: 'rgba(255,123,114,0.1)' }}><AlertTriangle size={24} /></div>
        <div className="status-info"><h3>Error</h3><p style={{ color: '#ff7b72' }}>{err}</p></div>
      </div></div>}

      {repos && repos.length === 0 && <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '6rem' }}>
        <Package size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} />
        <p style={{ fontSize: '1.2rem' }}>No vulnerability history yet.</p>
        <p style={{ marginTop: '0.5rem', fontSize: '0.95rem' }}>Run a scan to start tracking your vulnerability trends.</p>
      </div>}

      {repos && repos.length > 0 && (
        <div className="history-list">
          {repos.map(item => (
            <RepoVulnBlock
              key={item.repo_url}
              repoUrl={item.repo_url}
              scans={item.scans}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Scanner App ─────────────────────────────────────────────────────────

function ScannerApp({ apiFetch, onLogout }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [sortBy, setSortBy] = useState('severity');

  const [scanStatus, setScanStatus] = useState({ detect: 'idle', scanners: 'idle', ai: 'idle' });

  const openTab = (view) => {
    const url = new URL(window.location.href);
    url.searchParams.set('view', view);
    window.open(url.toString(), '_blank');
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!repoUrl) return;
    setIsScanning(true);
    setResults(null);
    setError(null);
    setFilterSeverity('all');
    setSortBy('severity');
    setScanStatus({ detect: 'scanning', scanners: 'idle', ai: 'idle' });
    try {
      const response = await apiFetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl, github_token: githubToken }),
      });
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Scan failed');
      }
      setScanStatus({ detect: 'done', scanners: 'scanning', ai: 'scanning' });
      const data = await response.json();
      setResults(data);
      setScanStatus({ detect: 'done', scanners: 'done', ai: 'done' });
    } catch (err) {
      setError(err.message);
      setScanStatus({ detect: 'error', scanners: 'error', ai: 'error' });
    } finally {
      setIsScanning(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'idle':     return <Box />;
      case 'scanning': return <Loader2 className="loader" />;
      case 'done':     return <CheckCircle2 />;
      case 'error':    return <XCircle />;
      default:         return <Box />;
    }
  };

  const getAllVulnerabilities = () => {
    if (!results?.results) return [];
    const vulns = [];
    Object.keys(results.results).forEach(key => {
      if (key === 'ai_review') return;
      const r = results.results[key];
      if (r?.vulnerabilities) vulns.push(...r.vulnerabilities);
    });
    return vulns;
  };

  const allVulns = getAllVulnerabilities();
  const filteredAndSorted = allVulns
    .filter(v => filterSeverity === 'all' || v.severity?.toLowerCase() === filterSeverity)
    .sort((a, b) => {
      if (sortBy === 'severity') {
        return (SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 4) - (SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 4);
      }
      return (a.package_name || '').localeCompare(b.package_name || '');
    });

  const metrics = {
    total:    allVulns.length,
    critical: allVulns.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high:     allVulns.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium:   allVulns.filter(v => v.severity?.toLowerCase() === 'medium').length,
  };

  return (
    <div className="app-container">
      <header style={{ position: 'relative' }}>
        <h1 className="logo"><ShieldCheck size={40} color="#58a6ff" />SecureScan</h1>
        <p className="subtitle">Universal Security Scanner for GitHub Repositories</p>
        <div className="header-nav">
          <button className="history-tab-btn" onClick={() => openTab('history')}>
            <History size={18} /> AI Review History <ExternalLink size={14} style={{ opacity: 0.6 }} />
          </button>
          <button className="history-tab-btn packages-tab-btn" onClick={() => openTab('packages')}>
            <Package size={18} /> Package History <ExternalLink size={14} style={{ opacity: 0.6 }} />
          </button>
        </div>
        <button className="logout-btn" onClick={onLogout}><LogOut size={15} /> Sign Out</button>
      </header>

      <form className="search-container" onSubmit={handleScan}>
        <div className="input-wrapper">
          <Code className="input-icon" size={20} />
          <input type="url" className="repo-input" placeholder="GitHub Repository URL"
            value={repoUrl} onChange={e => setRepoUrl(e.target.value)} disabled={isScanning} required />
        </div>
        <div className="input-wrapper" style={{ maxWidth: '200px' }}>
          <Key className="input-icon" size={20} />
          <input type="password" className="repo-input" placeholder="Token (Optional)"
            value={githubToken} onChange={e => setGithubToken(e.target.value)} disabled={isScanning} />
        </div>
        <button type="submit" className={`scan-btn ${isScanning ? 'scanning' : ''}`} disabled={isScanning || !repoUrl}>
          {isScanning ? <><Loader2 size={20} className="loader" /> Scanning...</> : <><Search size={20} /> Scan Repo</>}
        </button>
      </form>

      {error && (
        <div className="dashboard" style={{ marginBottom: '2rem' }}>
          <div className="status-card" style={{ borderColor: 'rgba(255,123,114,0.3)' }}>
            <div className="status-icon-wrapper" style={{ color: '#ff7b72', background: 'rgba(255,123,114,0.1)' }}><AlertTriangle size={24} /></div>
            <div className="status-info"><h3>Error Occurred</h3><p style={{ color: '#ff7b72' }}>{error}</p></div>
          </div>
        </div>
      )}

      {(isScanning || results) && !error && (
        <div className="dashboard">
          <div className="status-grid">
            <div className="status-card">
              <div className={`status-icon-wrapper status-${scanStatus.detect}`}>{getStatusIcon(scanStatus.detect)}</div>
              <div className="status-info">
                <h3>Project Detection</h3>
                <p>{scanStatus.detect === 'done' ? `Detected: ${results?.project_types?.join(', ') || 'None'}` : 'Analyzing...'}</p>
              </div>
            </div>

            {results?.project_types?.map(type => {
              if (type === 'docker') return null;
              const scannerResult = results.results?.[type];
              return (
                <div key={type} className="status-card">
                  <div className="status-icon-wrapper status-done"><Terminal /></div>
                  <div className="status-info">
                    <h3 style={{ textTransform: 'capitalize' }}>{type} Scanner</h3>
                    <p>{scannerResult?.vulnerabilities?.length || 0} Issues Found</p>
                  </div>
                </div>
              );
            })}

            {isScanning && scanStatus.detect === 'done' && (
              <div className="status-card">
                <div className="status-icon-wrapper status-scanning"><Loader2 className="loader" /></div>
                <div className="status-info"><h3>Deep Scan</h3><p>Auditing dependencies...</p></div>
              </div>
            )}

            <div className="status-card">
              <div className={`status-icon-wrapper status-${scanStatus.ai}`}>{getStatusIcon(scanStatus.ai)}</div>
              <div className="status-info">
                <h3>AI Code Review</h3>
                <p>{scanStatus.ai === 'done'
                  ? (results?.results?.ai_review?.status === 'error'
                    ? `Failed (${results?.results?.ai_review?.error || 'No API Key'})`
                    : 'Completed')
                  : (scanStatus.ai === 'scanning' ? 'Analyzing...' : 'Pending')}
                </p>
              </div>
            </div>
          </div>

          {results && (
            <>
              <div className="metrics-bar">
                {[
                  { val: metrics.total,    label: 'Total Issues', cls: 'value-total' },
                  { val: metrics.critical, label: 'Critical',     cls: 'value-critical' },
                  { val: metrics.high,     label: 'High',         cls: 'value-high' },
                  { val: metrics.medium,   label: 'Medium',       cls: 'value-medium' },
                ].map(({ val, label, cls }) => (
                  <div key={label} className="metric-card">
                    <div className={`metric-value ${cls}`}>{val}</div>
                    <div className="metric-label">{label}</div>
                  </div>
                ))}
              </div>

              {allVulns.length > 0 && (
                <div className="results-section">
                  <h2 className="section-title"><FileCode2 size={24} color="#58a6ff" />Dependency Vulnerabilities</h2>
                  <VulnFilterBar allVulns={allVulns} filterSeverity={filterSeverity}
                    setFilterSeverity={setFilterSeverity} sortBy={sortBy} setSortBy={setSortBy} />
                  {filteredAndSorted.length === 0 ? (
                    <div className="vuln-empty">No {filterSeverity} vulnerabilities found.</div>
                  ) : (
                    <div className="vuln-grid">
                      {filteredAndSorted.map((vuln, i) => <VulnCard key={i} vuln={vuln} />)}
                    </div>
                  )}
                </div>
              )}

              {results.previous_reviews?.length > 0 && (
                <div className="results-section">
                  <h2 className="section-title"><History size={24} color="#d2a8ff" />Previous AI Reviews ({results.previous_reviews.length})</h2>
                  {results.previous_reviews.map((review, i) => (
                    <PreviousReviewItem key={i} review={review} index={i} total={results.previous_reviews.length} />
                  ))}
                </div>
              )}

              {results.results?.ai_review?.ai_output && (
                <div className="results-section">
                  <h2 className="section-title"><Bot size={24} color="#d2a8ff" />Claude AI Review — Latest</h2>
                  <div className="ai-review-card">
                    <AIMarkdown>{results.results.ai_review.ai_output}</AIMarkdown>
                  </div>
                </div>
              )}

              {results.results?.ai_review?.status === 'error' && (
                <div className="results-section">
                  <h2 className="section-title"><Bot size={24} color="#ff7b72" />Claude AI Review Failed</h2>
                  <div className="ai-review-card" style={{ borderColor: 'rgba(255,123,114,0.3)' }}>
                    <div className="ai-content" style={{ color: '#ff7b72' }}>
                      Error: {results.results.ai_review.error || 'Unknown error occurred during AI review.'}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Root ─────────────────────────────────────────────────────────────────────

function App() {
  const [credentials, setCredentials] = useState(() => sessionStorage.getItem('auth') || null);

  const handleLogin  = (creds) => { sessionStorage.setItem('auth', creds); setCredentials(creds); };
  const handleLogout = ()      => { sessionStorage.removeItem('auth');       setCredentials(null); };

  const apiFetch = (path, options = {}) =>
    fetch(`${API_URL}${path}`, {
      ...options,
      headers: { ...(options.headers || {}), 'Authorization': `Basic ${credentials}` },
    }).then(res => {
      if (res.status === 401) { handleLogout(); throw new Error('Session expired. Please sign in again.'); }
      return res;
    });

  if (!credentials) return <LoginPage onLogin={handleLogin} />;

  const params = new URLSearchParams(window.location.search);
  const view = params.get('view');

  if (view === 'history')  return <HistoryView       apiFetch={apiFetch} onLogout={handleLogout} />;
  if (view === 'packages') return <PackageHistoryView apiFetch={apiFetch} onLogout={handleLogout} />;
  return <ScannerApp apiFetch={apiFetch} onLogout={handleLogout} />;
}

export default App;
