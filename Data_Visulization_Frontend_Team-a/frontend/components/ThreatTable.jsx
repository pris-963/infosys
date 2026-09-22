import React, { useState, useMemo } from 'react';
import { Search, ChevronDown, ChevronUp, AlertCircle, Eye, Download, Filter, RefreshCw, Layers } from 'lucide-react';

/**
 * ThreatTable Component
 * Displays the threat events logs with columns:
 * - Event ID
 * - Event Type
 * - Prediction (AI Model Classification)
 * - Confidence (AI Confidence level)
 * - Severity
 * - Timestamp
 * 
 * Props:
 * - events: Array of event objects
 * - onSelectEvent: Callback function (eventId) when event is clicked
 */
export default function ThreatTable({ events = [], onSelectEvent }) {
  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [predictionFilter, setPredictionFilter] = useState('ALL');

  // Sorting State
  const [sortColumn, setSortColumn] = useState('time');
  const [sortDirection, setSortDirection] = useState('desc'); // 'asc' | 'desc'

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // 1. Filter Logic
  const filteredEvents = useMemo(() => {
    return events.filter(evt => {
      const idStr = String(evt.id || evt.event_id || '').toLowerCase();
      const typeStr = String(evt.name || evt.event_type || '').toLowerCase();
      const sourceStr = String(evt.source || evt.source_ip || '').toLowerCase();
      const searchLower = searchQuery.toLowerCase();

      const matchesSearch = idStr.includes(searchLower) || 
                            typeStr.includes(searchLower) ||
                            sourceStr.includes(searchLower);

      const matchesSeverity = severityFilter === 'ALL' || (evt.severity || '').toUpperCase() === severityFilter;
      const matchesPrediction = predictionFilter === 'ALL' || (evt.prediction || '').toUpperCase() === predictionFilter;

      return matchesSearch && matchesSeverity && matchesPrediction;
    });
  }, [events, searchQuery, severityFilter, predictionFilter]);

  // 2. Sort Logic
  const sortedEvents = useMemo(() => {
    if (!sortColumn) return filteredEvents;

    return [...filteredEvents].sort((a, b) => {
      let valA = a[sortColumn];
      let valB = b[sortColumn];

      if (sortColumn === 'confidence') {
        valA = Number(valA) || 0;
        valB = Number(valB) || 0;
      } else {
        valA = String(valA || '').toLowerCase();
        valB = String(valB || '').toLowerCase();
      }

      if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
      if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [filteredEvents, sortColumn, sortDirection]);

  // 3. Pagination Logic
  const totalRecords = sortedEvents.length;
  const totalPages = Math.max(1, Math.ceil(totalRecords / pageSize));
  const activePage = Math.min(currentPage, totalPages);
  const startIndex = (activePage - 1) * pageSize;
  const paginatedEvents = useMemo(() => {
    return sortedEvents.slice(startIndex, startIndex + pageSize);
  }, [sortedEvents, startIndex, pageSize]);

  // Handle Sort Change
  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
    setCurrentPage(1);
  };

  // Helper for Severity Badges
  const getSeverityBadgeClass = (severity) => {
    const sev = String(severity || '').toUpperCase();
    switch (sev) {
      case 'CRITICAL': return 'bg-danger-subtle text-danger border border-danger-subtle';
      case 'HIGH': return 'bg-warning-subtle text-warning border border-warning-subtle';
      case 'MEDIUM': return 'bg-info-subtle text-info border border-info-subtle';
      default: return 'bg-success-subtle text-success border border-success-subtle';
    }
  };

  // Helper for Prediction Badges
  const getPredictionBadgeClass = (pred) => {
    const p = String(pred || '').toUpperCase();
    switch (p) {
      case 'CRITICAL': return 'badge bg-danger-subtle text-danger border border-danger-subtle';
      case 'SUSPICIOUS': return 'badge bg-warning-subtle text-warning border border-warning-subtle';
      default: return 'badge bg-success-subtle text-success border border-success-subtle';
    }
  };

  // Handle CSV Export
  const handleCSVExport = () => {
    if (filteredEvents.length === 0) return;

    const headers = ['Event ID', 'Event Type', 'Prediction', 'Confidence', 'Severity', 'Timestamp', 'Source IP', 'Destination IP'];
    const rows = filteredEvents.map(e => [
      e.id || e.event_id || '',
      e.name || e.event_type || '',
      e.prediction || '',
      `${e.confidence || 0}%`,
      e.severity || '',
      e.time || e.timestamp || '',
      e.source || e.source_ip || '',
      e.target || e.destination_ip || ''
    ]);

    const csvContent = [
      headers.join(','), 
      ...rows.map(r => r.map(val => {
        let str = String(val);
        if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
          str = str.replace(/"/g, '""');
          return `"${str}"`;
        }
        return `"${str}"`;
      }).join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `security_threat_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="threat-table-card p-4 rounded-4 mb-4" style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border-color)',
      boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.08)',
      transition: 'var(--transition)'
    }}>
      {/* Table Title and Toolbar */}
      <div className="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4 pb-2" style={{ borderBottom: '1px solid var(--border-color)' }}>
        <div>
          <div className="d-flex align-items-center gap-2 mb-1">
            <Layers size={18} className="text-success" />
            <h4 className="fw-bold m-0" style={{ color: 'var(--text-primary)', fontSize: '17px' }}>Threat Detection Telemetry Logs</h4>
          </div>
          <p className="text-secondary small m-0" style={{ fontSize: '12.5px' }}>
            Real-time audit log of ML-classified network security events &amp; anomalies
          </p>
        </div>

        {/* Toolbar */}
        <div className="d-flex flex-wrap align-items-center gap-2">
          {/* Search bar */}
          <div className="position-relative">
            <Search className="position-absolute top-50 translate-middle-y text-secondary ms-3" size={14} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              placeholder="Search event ID, type, IP..."
              className="rounded-pill px-4 ps-5 py-2 small"
              style={{ 
                fontSize: '12.5px', 
                width: '230px',
                backgroundColor: 'var(--bg-deep)',
                border: '1px solid var(--border-color)',
                color: 'var(--text-primary)',
                outline: 'none',
                transition: 'border-color 0.2s ease'
              }}
            />
          </div>

          {/* Quick Filters */}
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
            className="rounded-pill px-3 py-2 small"
            style={{ 
              fontSize: '12.5px', 
              width: '135px',
              backgroundColor: 'var(--bg-deep)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-primary)',
              outline: 'none',
              cursor: 'pointer'
            }}
            title="Filter by Severity"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={predictionFilter}
            onChange={(e) => { setPredictionFilter(e.target.value); setCurrentPage(1); }}
            className="rounded-pill px-3 py-2 small"
            style={{ 
              fontSize: '12.5px', 
              width: '145px',
              backgroundColor: 'var(--bg-deep)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-primary)',
              outline: 'none',
              cursor: 'pointer'
            }}
            title="Filter by Prediction"
          >
            <option value="ALL">All Predictions</option>
            <option value="CRITICAL">Critical</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="NORMAL">Normal</option>
          </select>

          <button 
            onClick={handleCSVExport} 
            className="btn btn-outline-secondary btn-sm rounded-pill px-3 py-2 d-flex align-items-center gap-1.5"
            style={{ borderColor: 'var(--border-color)', color: 'var(--text-secondary)', transition: 'var(--transition)' }}
            title="Export filtered records to CSV"
          >
            <Download size={14} />
            <span style={{ fontSize: '12.5px', fontWeight: '600' }}>CSV Export</span>
          </button>
        </div>
      </div>

      {/* Table Container */}
      <div className="table-responsive" style={{ maxHeight: '440px', overflowY: 'auto' }}>
        <table className="table align-middle m-0" style={{ borderCollapse: 'separate', borderSpacing: '0 4px', color: 'var(--text-primary)' }}>
          <thead className="sticky-top" style={{ zIndex: 5, backgroundColor: 'var(--bg-surface)' }}>
            <tr className="text-secondary small font-mono" style={{ borderBottom: '1px solid var(--border-color)', fontSize: '11px', letterSpacing: '0.04em' }}>
              <th className="py-3 px-3 cursor-pointer" onClick={() => handleSort('id')}>
                Event ID {sortColumn === 'id' ? (sortDirection === 'asc' ? <ChevronUp size={12} className="inline ms-1" /> : <ChevronDown size={12} className="inline ms-1" />) : ''}
              </th>
              <th className="py-3 px-2 cursor-pointer" onClick={() => handleSort('name')}>
                Event Type {sortColumn === 'name' ? (sortDirection === 'asc' ? <ChevronUp size={12} className="inline ms-1" /> : <ChevronDown size={12} className="inline ms-1" />) : ''}
              </th>
              <th className="py-3 px-2 cursor-pointer" onClick={() => handleSort('prediction')}>
                ML Classification {sortColumn === 'prediction' ? (sortDirection === 'asc' ? <ChevronUp size={12} className="inline ms-1" /> : <ChevronDown size={12} className="inline ms-1" />) : ''}
              </th>
              <th className="py-3 px-2 cursor-pointer" onClick={() => handleSort('confidence')}>
                Confidence {sortColumn === 'confidence' ? (sortDirection === 'asc' ? <ChevronUp size={12} className="inline ms-1" /> : <ChevronDown size={12} className="inline ms-1" />) : ''}
              </th>
              <th className="py-3 px-2 cursor-pointer" onClick={() => handleSort('severity')}>
                Severity {sortColumn === 'severity' ? (sortDirection === 'asc' ? <ChevronUp size={12} className="inline ms-1" /> : <ChevronDown size={12} className="inline ms-1" />) : ''}
              </th>
              <th className="py-3 px-2 cursor-pointer" onClick={() => handleSort('time')}>
                Timestamp {sortColumn === 'time' ? (sortDirection === 'asc' ? <ChevronUp size={12} className="inline ms-1" /> : <ChevronDown size={12} className="inline ms-1" />) : ''}
              </th>
              <th className="py-3 px-3 text-end">Action</th>
            </tr>
          </thead>
          <tbody>
            {paginatedEvents.length === 0 ? (
              <tr>
                <td colSpan="7" className="text-center text-secondary py-5">
                  <AlertCircle size={26} className="mx-auto mb-2 text-warning d-block" />
                  <div className="fw-semibold">No telemetry records match the selected filters.</div>
                  <div className="small text-secondary mt-1">Try resetting the search query or severity dropdown.</div>
                </td>
              </tr>
            ) : (
              paginatedEvents.map((evt) => (
                <tr key={evt.id || evt.event_id} style={{ 
                  borderBottom: '1px solid var(--border-color)', 
                  transition: 'background-color 0.2s ease',
                  cursor: 'pointer'
                }}>
                  <td className="py-3 px-3">
                    <button
                      onClick={() => onSelectEvent(evt.id || evt.event_id)}
                      className="btn btn-link p-0 text-decoration-none font-mono fw-bold text-success"
                      style={{ fontSize: '13px' }}
                    >
                      {evt.id || evt.event_id}
                    </button>
                  </td>
                  <td className="py-3 px-2 fw-semibold" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                    {evt.name || evt.event_type}
                  </td>
                  <td className="py-3 px-2">
                    <span className={getPredictionBadgeClass(evt.prediction)}>
                      {evt.prediction}
                    </span>
                  </td>
                  <td className="py-3 px-2 font-mono fw-bold" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                    {evt.confidence}%
                  </td>
                  <td className="py-3 px-2">
                    <span className={`badge ${getSeverityBadgeClass(evt.severity)} px-2.5 py-1 rounded small`}>
                      {evt.severity}
                    </span>
                  </td>
                  <td className="py-3 px-2 font-mono text-secondary small">{evt.time || evt.timestamp}</td>
                  <td className="py-3 px-3 text-end">
                    <button
                      onClick={() => onSelectEvent(evt.id || evt.event_id)}
                      className="btn btn-sm btn-outline-success rounded-pill px-3 d-inline-flex align-items-center gap-1.5"
                      style={{ fontSize: '12px', fontWeight: '600' }}
                    >
                      <Eye size={12} />
                      <span>Investigate</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="d-flex justify-content-between align-items-center flex-wrap gap-2 mt-4 pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
        <span className="small text-secondary font-mono">
          Showing <strong>{totalRecords === 0 ? 0 : startIndex + 1}</strong> to <strong>{Math.min(startIndex + pageSize, totalRecords)}</strong> of <strong>{totalRecords}</strong> events
        </span>

        <div className="d-flex align-items-center gap-2">
          <button
            onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
            disabled={activePage === 1}
            className="btn btn-sm btn-outline-secondary px-3 py-1 rounded-pill"
            style={{ borderColor: 'var(--border-color)', color: 'var(--text-secondary)' }}
          >
            Prev
          </button>
          
          <div className="d-flex gap-1">
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              let pageNum;
              if (totalPages <= 5) {
                pageNum = i + 1;
              } else if (activePage <= 3) {
                pageNum = i + 1;
              } else if (activePage >= totalPages - 2) {
                pageNum = totalPages - 4 + i;
              } else {
                pageNum = activePage - 2 + i;
              }
              return (
                <button
                  key={pageNum}
                  onClick={() => setCurrentPage(pageNum)}
                  className={`btn btn-sm rounded-circle ${activePage === pageNum ? 'btn-success text-white' : 'btn-outline-secondary text-secondary'}`}
                  style={{ width: '28px', height: '28px', padding: 0, borderColor: 'var(--border-color)', fontSize: '12px', fontWeight: '600' }}
                >
                  {pageNum}
                </button>
              );
            })}
          </div>

          <button
            onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
            disabled={activePage === totalPages}
            className="btn btn-sm btn-outline-secondary px-3 py-1 rounded-pill"
            style={{ borderColor: 'var(--border-color)', color: 'var(--text-secondary)' }}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
