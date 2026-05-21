import { useState, useRef } from 'react';
import {
  ShieldCheck,
  Search,
  Box,
  FileCode2,
  Bot,
  CheckCircle2,
  XCircle,
  Loader2,
  AlertTriangle,
  Code,
  Terminal,
  Key,
  History,
  ChevronDown,
  ChevronRight
} from 'lucide-react';

import './index.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function formatTimestamp(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch {
    return iso;
  }
}

function PreviousReviewItem({ review, index, total }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="ai-review-card" style={{ marginBottom: '0.75rem', borderColor: 'rgba(210,168,255,0.2)' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          background: 'none', border: 'none', cursor: 'pointer',
          color: '#d2a8ff', width: '100%', padding: '0.75rem 1rem',
          fontSize: '0.9rem', fontWeight: 600
        }}
      >
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        Scan {index + 1} of {total} — {formatTimestamp(review.timestamp)}
      </button>
      {open && (
        <div className="ai-content" style={{ padding: '0 1rem 1rem', borderTop: '1px solid rgba(210,168,255,0.15)' }}>
          {review.ai_output}
        </div>
      )}
    </div>
  );
}

function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  
  // Track status of various scan stages
  const [scanStatus, setScanStatus] = useState({
    detect: 'idle',
    scanners: 'idle', // overall scanners state
    ai: 'idle'
  });

  const handleScan = async (e) => {
    e.preventDefault();
    if (!repoUrl) return;

    setIsScanning(true);
    setResults(null);
    setError(null);
    
    setScanStatus({
      detect: 'scanning',
      scanners: 'idle',
      ai: 'idle'
    });

    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          repo_url: repoUrl,
          github_token: githubToken 
        })
      });
      
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Scan failed');
      }

      setScanStatus({ detect: 'done', scanners: 'scanning', ai: 'scanning' });
      
      const data = await response.json();
      setResults(data);
      
      setScanStatus({
        detect: 'done',
        scanners: 'done',
        ai: 'done'
      });
      
    } catch (err) {
      setError(err.message);
      setScanStatus({ detect: 'error', scanners: 'error', ai: 'error' });
    } finally {
      setIsScanning(false);
    }
  };

  const getStatusIcon = (status) => {
    switch(status) {
      case 'idle': return <Box className="w-6 h-6" />;
      case 'scanning': return <Loader2 className="w-6 h-6 loader" />;
      case 'done': return <CheckCircle2 className="w-6 h-6" />;
      case 'error': return <XCircle className="w-6 h-6" />;
      default: return <Box className="w-6 h-6" />;
    }
  };

  // Dynamically calculate metrics from ALL scanners in the results
  const getAllVulnerabilities = () => {
    if (!results || !results.results) return [];
    const vulns = [];
    
    // Iterate through all keys in results (node, python, ruby, etc.)
    Object.keys(results.results).forEach(key => {
        // Skip ai_review as it's handled separately
        if (key === 'ai_review') return;
        
        const moduleResult = results.results[key];
        if (moduleResult && moduleResult.vulnerabilities) {
            vulns.push(...moduleResult.vulnerabilities);
        }
    });
    
    return vulns;
  };

  const allVulns = getAllVulnerabilities();
    
  const metrics = {
    total: allVulns.length,
    critical: allVulns.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high: allVulns.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium: allVulns.filter(v => v.severity?.toLowerCase() === 'medium').length,
  };

  return (
    <div className="app-container">
      <header>
        <h1 className="logo">
          <ShieldCheck size={40} color="#58a6ff" />
          SecureScan
        </h1>
        <p className="subtitle">Universal Security Scanner for GitHub Repositories</p>
      </header>

      <form className="search-container" onSubmit={handleScan}>
        <div className="input-wrapper">
          <Code className="input-icon" size={20} />
          <input 
            type="url" 
            className="repo-input"
            placeholder="GitHub Repository URL"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            disabled={isScanning}
            required
          />
        </div>
        <div className="input-wrapper" style={{ maxWidth: '200px' }}>
          <Key className="input-icon" size={20} />
          <input 
            type="password" 
            className="repo-input"
            placeholder="Token (Optional)"
            value={githubToken}
            onChange={(e) => setGithubToken(e.target.value)}
            disabled={isScanning}
          />
        </div>
        <button type="submit" className={`scan-btn ${isScanning ? 'scanning' : ''}`} disabled={isScanning || !repoUrl}>
          {isScanning ? (
            <><Loader2 size={20} className="loader" /> Scanning...</>
          ) : (
            <><Search size={20} /> Scan Repo</>
          )}
        </button>
      </form>

      {error && (
        <div className="dashboard" style={{marginBottom: '2rem'}}>
          <div className="status-card" style={{borderColor: 'rgba(255,123,114,0.3)'}}>
             <div className="status-icon-wrapper" style={{color: '#ff7b72', background: 'rgba(255,123,114,0.1)'}}>
               <AlertTriangle size={24} />
             </div>
             <div className="status-info">
               <h3>Error Occurred</h3>
               <p style={{color: '#ff7b72'}}>{error}</p>
             </div>
          </div>
        </div>
      )}

      {(isScanning || results) && !error && (
        <div className="dashboard">
          <div className="status-grid">
            <div className="status-card">
              <div className={`status-icon-wrapper status-${scanStatus.detect}`}>
                {getStatusIcon(scanStatus.detect)}
              </div>
              <div className="status-info">
                <h3>Project Detection</h3>
                <p>{scanStatus.detect === 'done' ? `Detected: ${results?.project_types?.join(', ') || 'None'}` : 'Analyzing...'}</p>
              </div>
            </div>
            
            {/* Dynamically render cards for each detected language */}
            {results && results.project_types && results.project_types.map(type => {
              if (type === 'docker') return null; // Skip generic types if preferred
              const scannerResult = results.results?.[type];
              return (
                <div key={type} className="status-card">
                  <div className={`status-icon-wrapper status-done`}>
                    <Terminal className="w-6 h-6" />
                  </div>
                  <div className="status-info">
                    <h3 style={{textTransform: 'capitalize'}}>{type} Scanner</h3>
                    <p>{scannerResult?.vulnerabilities?.length || 0} Issues Found</p>
                  </div>
                </div>
              );
            })}

            {/* If scanning, show a generic scanner placeholder */}
            {isScanning && scanStatus.detect === 'done' && (
               <div className="status-card">
                  <div className={`status-icon-wrapper status-scanning`}>
                    <Loader2 className="w-6 h-6 loader" />
                  </div>
                  <div className="status-info">
                    <h3>Deep Scan</h3>
                    <p>Auditing dependencies...</p>
                  </div>
                </div>
            )}
            
            <div className="status-card">
              <div className={`status-icon-wrapper status-${scanStatus.ai}`}>
                {getStatusIcon(scanStatus.ai)}
              </div>
              <div className="status-info">
                <h3>AI Code Review</h3>
                <p>
                  {scanStatus.ai === 'done' ? (
                    results?.results?.ai_review?.status === 'error' 
                      ? `Failed (${results?.results?.ai_review?.error || 'No API Key'})` 
                      : 'Completed'
                  ) : (
                    scanStatus.ai === 'scanning' ? 'Analyzing...' : 'Pending'
                  )}
                </p>
              </div>
            </div>
          </div>

          {results && (
            <>
              <div className="metrics-bar">
                <div className="metric-card">
                  <div className="metric-value value-total">{metrics.total}</div>
                  <div className="metric-label">Total Issues</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value value-critical">{metrics.critical}</div>
                  <div className="metric-label">Critical</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value value-high">{metrics.high}</div>
                  <div className="metric-label">High</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value value-medium">{metrics.medium}</div>
                  <div className="metric-label">Medium</div>
                </div>
              </div>

              {allVulns.length > 0 && (
                <div className="results-section">
                  <h2 className="section-title">
                    <FileCode2 size={24} color="#58a6ff" />
                    Dependency Vulnerabilities
                  </h2>
                  <div className="vuln-grid">
                    {allVulns.map((vuln, i) => (
                      <div key={i} className={`vuln-card vuln-${vuln.severity?.toLowerCase() || 'high'}`}>
                        <div className="vuln-header">
                          <div>
                            <div className="vuln-pkg">{vuln.package_name}</div>
                            <div className="vuln-version">v{vuln.version}</div>
                          </div>
                          <span className={`severity-badge badge-${vuln.severity?.toLowerCase() || 'high'}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="vuln-desc">{vuln.description}</p>
                        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem'}}>
                          {vuln.cve_id ? (
                            <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`} target="_blank" rel="noopener noreferrer" className="vuln-cve">
                              {vuln.cve_id}
                            </a>
                          ) : <span className="vuln-cve" style={{opacity: 0.5}}>No CVE</span>}
                          
                          <span style={{fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px'}}>
                             Source: {vuln.scanner_type || 'Unknown'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {results.previous_reviews?.length > 0 && (
                <div className="results-section">
                  <h2 className="section-title">
                    <History size={24} color="#d2a8ff" />
                    Previous AI Reviews ({results.previous_reviews.length})
                  </h2>
                  {results.previous_reviews.map((review, i) => (
                    <PreviousReviewItem
                      key={i}
                      review={review}
                      index={i}
                      total={results.previous_reviews.length}
                    />
                  ))}
                </div>
              )}

              {results.results?.ai_review?.ai_output && (
                <div className="results-section">
                  <h2 className="section-title">
                    <Bot size={24} color="#d2a8ff" />
                    Claude AI Review — Latest
                  </h2>
                  <div className="ai-review-card">
                    <div className="ai-content">
                      {results.results.ai_review.ai_output}
                    </div>
                  </div>
                </div>
              )}

              {results.results?.ai_review?.status === 'error' && (
                <div className="results-section">
                  <h2 className="section-title">
                    <Bot size={24} color="#ff7b72" />
                    Claude AI Review Failed
                  </h2>
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

export default App;
