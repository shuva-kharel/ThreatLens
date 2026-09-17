'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  RotateCw,
  Bug,
  Shield,
  ExternalLink,
  CheckCircle,
  FileText,
  AlertTriangle,
  Play,
  ArrowRight,
} from 'lucide-react'
import { api, type VulnerabilityFinding } from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

export default function VulnerabilityCenterPage() {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityFinding[]>([])
  const [selectedVuln, setSelectedVuln] = useState<VulnerabilityFinding | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filterQuery, setFilterQuery] = useState('')

  const loadData = () => {
    setLoading(true)
    setError(null)
    api.vulnerabilities()
      .then((data) => {
        setVulnerabilities(data)
        if (data.length > 0 && !selectedVuln) {
          setSelectedVuln(data[0])
        }
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Unable to load vulnerability registry.')
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  const filtered = vulnerabilities.filter(
    (v) =>
      `${v.cve_id} ${v.title} ${v.affected_product} ${v.severity}`
        .toLowerCase()
        .includes(filterQuery.toLowerCase())
  )

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-surface-raised border border-border text-muted">
              VULNERABILITY &amp; EXPOSURE REGISTRY
            </span>
            <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-accent-soft text-accent border border-accent-border">
              COMMON CVE MITIGATIONS
            </span>
          </div>
          <h1>Vulnerability Center</h1>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={loadData}>
            <RotateCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      {error && <ErrorState error={error} retry={loadData} />}

      {/* Metrics Row */}
      <section className="metric-grid">
        <article className="metric-card-clean">
          <strong>{vulnerabilities.length}</strong>
          <span>Tracked Vulnerabilities</span>
          <small>Known CVEs &amp; configuration weaknesses</small>
        </article>

        <article className="metric-card-clean">
          <strong>
            {vulnerabilities.filter((v) => v.severity === 'critical' || v.severity === 'high').length}
          </strong>
          <span>Critical / High Severity</span>
          <small>Requiring active mitigation</small>
        </article>

        <article className="metric-card-clean">
          <strong>{vulnerabilities.filter((v) => v.auto_response_eligible).length}</strong>
          <span>Auto-Response Eligible</span>
          <small>Low-risk hardening playbooks</small>
        </article>

        <article className="metric-card-clean">
          <strong>
            {Array.from(new Set(vulnerabilities.flatMap((v) => v.affected_assets))).length}
          </strong>
          <span>Affected Internal Assets</span>
          <small>Observed across telemetry</small>
        </article>
      </section>

      {loading ? (
        <LoadingState label="Inspecting vulnerability registry..." />
      ) : (
        <div className="dashboard-grid">
          {/* Vulnerability Table */}
          <section className="panel">
            <div className="panel-header">
              <h2>Detected CVEs &amp; Configuration Flaws</h2>
              <div className="toolbar">
                <input
                  placeholder="Filter CVEs..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="font-mono text-[11px]"
                />
              </div>
            </div>

            <div className="soc-table-wrap">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Vulnerability Title</th>
                    <th>Product</th>
                    <th>Severity</th>
                    <th>Response Playbook</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((vuln) => (
                    <tr
                      key={vuln.cve_id}
                      className={selectedVuln?.cve_id === vuln.cve_id ? 'active' : ''}
                      onClick={() => setSelectedVuln(vuln)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="font-mono text-[11px] font-semibold text-accent">{vuln.cve_id}</td>
                      <td className="text-[12px] font-medium">{vuln.title}</td>
                      <td className="font-mono text-[11px] text-muted">{vuln.affected_product}</td>
                      <td>
                        <span
                          className={`text-[10.5px] font-mono uppercase px-1.5 py-0.5 rounded ${vuln.severity === 'critical'
                              ? 'bg-sev-critical-bg text-sev-critical border border-sev-critical-border'
                              : vuln.severity === 'high'
                                ? 'bg-sev-high-bg text-sev-high border border-sev-high-border'
                                : 'bg-sev-medium-bg text-sev-medium border border-sev-medium-border'
                            }`}
                        >
                          {vuln.severity}
                        </span>
                      </td>
                      <td className="font-mono text-[11px]">
                        <span className="px-1.5 py-0.5 rounded bg-surface-raised border border-border">
                          {vuln.playbook_id}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Vulnerability Inspector */}
          <section className="panel">
            <div className="panel-header">
              <h2>Remediation Specification</h2>
              <Link href="/response" className="secondary-button text-[11px] py-0.5">
                Response Center <ArrowRight className="w-3 h-3 ml-1" />
              </Link>
            </div>

            {selectedVuln ? (
              <div className="p-4 space-y-4 text-[12px]">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-[11px] font-semibold text-accent">
                      {selectedVuln.cve_id}
                    </span>
                    <span
                      className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded ${selectedVuln.severity === 'critical'
                          ? 'bg-sev-critical-bg text-sev-critical'
                          : selectedVuln.severity === 'high'
                            ? 'bg-sev-high-bg text-sev-high'
                            : 'bg-sev-medium-bg text-sev-medium'
                        }`}
                    >
                      {selectedVuln.severity}
                    </span>
                  </div>
                  <h3 className="text-[14px] font-bold text-text">{selectedVuln.title}</h3>
                  <p className="text-muted text-[11.5px] mt-1.5 leading-relaxed">
                    {selectedVuln.description}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3 py-3 border-y border-border">
                  <div>
                    <span className="text-muted text-[11px] block">Affected Product</span>
                    <strong className="font-mono text-[11.5px]">{selectedVuln.affected_product}</strong>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Affected Versions</span>
                    <span className="font-mono text-[11px]">{selectedVuln.affected_versions}</span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Associated Playbook</span>
                    <span className="font-mono text-[11px] font-semibold text-accent">
                      {selectedVuln.playbook_id}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Approval Policy</span>
                    <span className="font-mono text-[11px]">
                      {selectedVuln.approval_required ? 'Approval Required' : 'Auto-Response Allowed'}
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-muted text-[11px] uppercase tracking-wider mb-1">
                    Detection Method
                  </h4>
                  <p className="font-mono text-[11.5px] text-text bg-surface-raised p-2 rounded border border-border">
                    {selectedVuln.detection_method}
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-muted text-[11px] uppercase tracking-wider mb-1">
                    Direct Mitigation
                  </h4>
                  <p className="font-mono text-[11.5px] text-text bg-surface-raised p-2 rounded border border-border">
                    {selectedVuln.mitigation}
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-muted text-[11px] uppercase tracking-wider mb-1">
                    Permanent Remediation
                  </h4>
                  <p className="text-muted text-[11.5px]">
                    {selectedVuln.remediation}
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-muted text-[11px] uppercase tracking-wider mb-1">
                    Verification Method
                  </h4>
                  <p className="font-mono text-[11px] text-faint">
                    {selectedVuln.verification_method}
                  </p>
                </div>

                {selectedVuln.references.length > 0 && (
                  <div>
                    <h4 className="font-semibold text-muted text-[11px] uppercase tracking-wider mb-1">
                      Advisory References
                    </h4>
                    <ul className="space-y-1">
                      {selectedVuln.references.map((ref, idx) => (
                        <li key={idx}>
                          <a
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-accent underline font-mono text-[11px] flex items-center gap-1 hover:text-text"
                          >
                            {ref} <ExternalLink className="w-3 h-3" />
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <EmptyState title="No CVE selected" description="Select a vulnerability from the table to view remediation." />
            )}
          </section>
        </div>
      )}
    </ThreatLensShell>
  )
}