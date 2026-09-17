'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  ShieldCheck,
  RotateCw,
  CheckCircle,
  AlertTriangle,
  FileText,
  Sliders,
  Play,
  RotateCcw,
  Check,
  X,
  Clock,
  Shield,
  Search,
} from 'lucide-react'
import {
  api,
  type ActionType,
  type ResponseExecutionRecord,
  type ResponsePlaybook,
  type ResponsePolicy,
  type ResponseAuditEntry,
} from '@/lib/api'
import { ThreatLensShell } from '@/components/threatlens/shell'
import { EmptyState, ErrorState, LoadingState } from '@/components/threatlens/ui'
import { formatDate, titleCase } from '@/components/threatlens/format'

type TabType = 'executions' | 'playbooks' | 'policies' | 'audit'

export default function ResponseCenterPage() {
  const [activeTab, setActiveTab] = useState<TabType>('executions')
  const [playbooks, setPlaybooks] = useState<ResponsePlaybook[]>([])
  const [policies, setPolicies] = useState<ResponsePolicy[]>([])
  const [executions, setExecutions] = useState<ResponseExecutionRecord[]>([])
  const [auditLog, setAuditLog] = useState<ResponseAuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)
  const [selectedPlaybook, setSelectedPlaybook] = useState<ResponsePlaybook | null>(null)
  const [selectedExecution, setSelectedExecution] = useState<ResponseExecutionRecord | null>(null)
  const [filterQuery, setFilterQuery] = useState('')

  const loadData = () => {
    setLoading(true)
    setError(null)
    setActionSuccess(null)
    Promise.all([
      api.responsePlaybooks(),
      api.responsePolicies(),
      api.responseExecutions(),
      api.responseAudit(),
    ])
      .then(([pb, pol, exec, aud]) => {
        setPlaybooks(pb)
        setPolicies(pol)
        setExecutions(exec)
        setAuditLog(aud)
        if (pb.length > 0 && !selectedPlaybook) setSelectedPlaybook(pb[0])
        if (exec.length > 0 && !selectedExecution) setSelectedExecution(exec[0])
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Unable to load Response Center data.')
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleTogglePolicy = async (policy: ResponsePolicy, key: 'auto_execute' | 'enabled' | 'requires_approval') => {
    try {
      const updated = await api.updateResponsePolicy(policy.action_type, {
        [key]: !policy[key],
      })
      setPolicies((prev) =>
        prev.map((p) => (p.action_type === updated.action_type ? updated : p))
      )
      setActionSuccess(`Policy for ${policy.action_type} updated successfully.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update response policy.')
    }
  }

  const handleRollback = async (executionId: string, incidentId: string) => {
    try {
      await api.rollbackIncidentResponse(incidentId, executionId, 'SOC Lead Operator')
      setActionSuccess(`Execution ${executionId} rolled back successfully. Target restored.`)
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rollback execution failed.')
    }
  }

  const pendingApprovals = executions.filter((e) => e.status === 'pending_approval')
  const verifiedExecutions = executions.filter((e) => e.status === 'verified' || e.status === 'executed')

  return (
    <ThreatLensShell>
      <section className="page-heading">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-surface-raised border border-border text-muted">
              DEFENSIVE RESPONSE SUBSYSTEM
            </span>
            <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-accent-soft text-accent border border-accent-border">
              DEMO MODE ACTIVE
            </span>
          </div>
          <h1>AI Security Response Center</h1>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={loadData}>
            <RotateCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
        </div>
      </section>

      {actionSuccess && (
        <div className="p-3 rounded bg-surface-raised border border-success text-success text-[12px] font-mono mb-4 flex items-center gap-2">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {error && <ErrorState error={error} retry={loadData} />}

      {/* Metrics Row */}
      <section className="metric-grid mb-4">
        <div className="metric-card">
          <span className="metric-label">Approved Playbooks</span>
          <strong className="metric-value">{playbooks.length}</strong>
          <small className="metric-meta">Deterministic defensive recipes</small>
        </div>
        <div className="metric-card">
          <span className="metric-label">Active Policies</span>
          <strong className="metric-value">
            {policies.filter((p) => p.enabled).length} / {policies.length}
          </strong>
          <small className="metric-meta">Autonomous gates &amp; approval boundaries</small>
        </div>
        <div className="metric-card">
          <span className="metric-label">Total Executions</span>
          <strong className="metric-value">{executions.length}</strong>
          <small className="metric-meta">{verifiedExecutions.length} verified safe</small>
        </div>
        <div className="metric-card">
          <span className="metric-label">Audit Trail Records</span>
          <strong className="metric-value">{auditLog.length}</strong>
          <small className="metric-meta">Append-only immutable record</small>
        </div>
      </section>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-border mb-4">
        <button
          className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
            activeTab === 'executions'
              ? 'border-accent text-text'
              : 'border-transparent text-muted hover:text-text'
          }`}
          onClick={() => setActiveTab('executions')}
        >
          Executions &amp; Jobs ({executions.length})
        </button>
        <button
          className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
            activeTab === 'playbooks'
              ? 'border-accent text-text'
              : 'border-transparent text-muted hover:text-text'
          }`}
          onClick={() => setActiveTab('playbooks')}
        >
          Playbook Registry ({playbooks.length})
        </button>
        <button
          className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
            activeTab === 'policies'
              ? 'border-accent text-text'
              : 'border-transparent text-muted hover:text-text'
          }`}
          onClick={() => setActiveTab('policies')}
        >
          Policy Engine ({policies.length})
        </button>
        <button
          className={`px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
            activeTab === 'audit'
              ? 'border-accent text-text'
              : 'border-transparent text-muted hover:text-text'
          }`}
          onClick={() => setActiveTab('audit')}
        >
          Append-Only Audit Log ({auditLog.length})
        </button>
      </div>

      {loading ? (
        <LoadingState label="Inspecting response subsystem..." />
      ) : activeTab === 'executions' ? (
        <div className="dashboard-grid">
          {/* Execution List */}
          <section className="panel">
            <div className="panel-header">
              <h2>Recent Defensive Actions</h2>
              <div className="toolbar">
                <input
                  placeholder="Filter executions..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="font-mono text-[11px]"
                />
              </div>
            </div>
            {executions.length === 0 ? (
              <EmptyState
                title="No response actions yet"
                description="Run an attack simulation or trigger an AI response from Incident Detail to observe containment actions."
              />
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Execution ID</th>
                      <th>Incident</th>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Started</th>
                    </tr>
                  </thead>
                  <tbody>
                    {executions
                      .filter(
                        (e) =>
                          `${e.execution_id} ${e.incident_id} ${e.action} ${e.target} ${e.status}`
                            .toLowerCase()
                            .includes(filterQuery.toLowerCase())
                      )
                      .map((exec) => (
                        <tr
                          key={exec.execution_id}
                          className={selectedExecution?.execution_id === exec.execution_id ? 'active' : ''}
                          onClick={() => setSelectedExecution(exec)}
                          style={{ cursor: 'pointer' }}
                        >
                          <td className="font-mono text-[11px] font-semibold">{exec.execution_id}</td>
                          <td>
                            <Link
                              href={`/incidents/${exec.incident_id}`}
                              className="text-muted hover:text-text underline font-mono text-[11px]"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {exec.incident_id.slice(0, 8)}...
                            </Link>
                          </td>
                          <td className="font-mono text-[11.5px]">{titleCase(exec.action)}</td>
                          <td className="font-mono text-[11px]">{exec.target}</td>
                          <td>
                            <span
                              className={`text-[11px] font-mono px-1.5 py-0.5 rounded ${
                                exec.status === 'verified'
                                  ? 'bg-success-bg text-success border border-success-border'
                                  : exec.status === 'rolled_back'
                                  ? 'bg-surface-raised text-muted border border-border'
                                  : 'bg-accent-soft text-accent border border-accent-border'
                              }`}
                            >
                              {exec.dry_run ? 'DRY RUN' : exec.status.toUpperCase()}
                            </span>
                          </td>
                          <td className="font-mono text-[11px] text-muted">{formatDate(exec.started_at)}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Execution Detail Inspector */}
          <section className="panel">
            <div className="panel-header">
              <h2>Execution Inspector</h2>
              {selectedExecution?.rollback_available && (
                <button
                  className="secondary-button text-[11px] py-1"
                  onClick={() => handleRollback(selectedExecution.execution_id, selectedExecution.incident_id)}
                >
                  <RotateCcw className="w-3 h-3 mr-1 text-sev-high" /> Rollback Action
                </button>
              )}
            </div>

            {selectedExecution ? (
              <div className="p-4 space-y-4 text-[12px]">
                <div className="grid grid-cols-2 gap-3 pb-3 border-b border-border">
                  <div>
                    <span className="text-muted text-[11px] block">Execution ID</span>
                    <strong className="font-mono">{selectedExecution.execution_id}</strong>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Incident Link</span>
                    <Link
                      href={`/incidents/${selectedExecution.incident_id}`}
                      className="font-mono text-accent underline"
                    >
                      {selectedExecution.incident_id}
                    </Link>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Action Applied</span>
                    <span className="font-mono">{titleCase(selectedExecution.action)}</span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Target Entity</span>
                    <span className="font-mono font-semibold">{selectedExecution.target}</span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Approved By</span>
                    <span className="font-mono">{selectedExecution.approved_by || 'Autonomous Policy'}</span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Playbook</span>
                    <span className="font-mono">{selectedExecution.playbook_id}</span>
                  </div>
                </div>

                <div>
                  <h3 className="text-[12px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                    Execution Result
                  </h3>
                  <pre className="p-3 bg-surface-raised border border-border rounded font-mono text-[11px] overflow-x-auto text-text">
                    {JSON.stringify(selectedExecution.result, null, 2)}
                  </pre>
                </div>

                <div>
                  <h3 className="text-[12px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                    Verification Telemetry
                  </h3>
                  {selectedExecution.verification_result ? (
                    <div className="p-3 bg-surface-raised border border-border rounded space-y-1">
                      <div className="flex items-center gap-2">
                        <Check className="w-3.5 h-3.5 text-success" />
                        <strong className="font-mono text-[11.5px]">
                          {selectedExecution.verification_result.method}
                        </strong>
                      </div>
                      <p className="text-muted text-[11.5px]">
                        {selectedExecution.verification_result.details}
                      </p>
                      <span className="text-faint text-[10.5px] font-mono block">
                        Verified at: {selectedExecution.verification_result.timestamp}
                      </span>
                    </div>
                  ) : (
                    <p className="text-muted text-[11px]">Verification pending or not required.</p>
                  )}
                </div>
              </div>
            ) : (
              <EmptyState title="No execution selected" description="Select an execution from the list to inspect details." />
            )}
          </section>
        </div>
      ) : activeTab === 'playbooks' ? (
        <div className="dashboard-grid">
          {/* Playbook List */}
          <section className="panel">
            <div className="panel-header">
              <h2>Registered Defensive Playbooks</h2>
            </div>
            <div className="divide-y divide-border">
              {playbooks.map((pb) => (
                <div
                  key={pb.id}
                  onClick={() => setSelectedPlaybook(pb)}
                  className={`p-3 transition-colors cursor-pointer hover:bg-surface-hover ${
                    selectedPlaybook?.id === pb.id ? 'bg-surface-raised' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[11px] text-accent font-semibold">{pb.id}</span>
                    <span
                      className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded ${
                        pb.risk_level === 'low'
                          ? 'bg-surface text-muted border border-border'
                          : pb.risk_level === 'medium'
                          ? 'bg-sev-medium-bg text-sev-medium border border-sev-medium-border'
                          : 'bg-sev-critical-bg text-sev-critical border border-sev-critical-border'
                      }`}
                    >
                      {pb.risk_level} RISK
                    </span>
                  </div>
                  <strong className="block text-[12px] text-text mb-1">{pb.name}</strong>
                  <p className="text-muted text-[11.5px] line-clamp-2">{pb.description}</p>
                </div>
              ))}
            </div>
          </section>

          {/* Playbook Detail */}
          <section className="panel">
            <div className="panel-header">
              <h2>Playbook Specification</h2>
            </div>
            {selectedPlaybook ? (
              <div className="p-4 space-y-4 text-[12px]">
                <div>
                  <span className="font-mono text-[11px] text-muted">{selectedPlaybook.id}</span>
                  <h3 className="text-[14px] font-bold text-text mt-0.5">{selectedPlaybook.name}</h3>
                  <p className="text-muted text-[12px] mt-1">{selectedPlaybook.description}</p>
                </div>

                <div className="grid grid-cols-2 gap-3 py-3 border-y border-border">
                  <div>
                    <span className="text-muted text-[11px] block">Action Type</span>
                    <span className="font-mono font-medium">{selectedPlaybook.action_type}</span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Autonomous Execution</span>
                    <span className="font-mono">
                      {selectedPlaybook.auto_execute_allowed ? 'Permitted (Policy Dependent)' : 'Approval Required'}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Required Permissions</span>
                    <span className="font-mono text-[11px]">
                      {selectedPlaybook.required_permissions.join(', ') || 'None'}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted text-[11px] block">Supported Incidents</span>
                    <span className="font-mono text-[11px]">
                      {selectedPlaybook.supported_incident_types.join(', ')}
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-muted text-[11.5px] uppercase tracking-wider mb-2">
                    Verification Steps
                  </h4>
                  <ul className="space-y-1.5">
                    {selectedPlaybook.verification_steps.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-[11.5px] font-mono">
                        <Check className="w-3.5 h-3.5 text-success shrink-0 mt-0.5" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 className="font-semibold text-muted text-[11.5px] uppercase tracking-wider mb-2">
                    Rollback Procedure
                  </h4>
                  <ul className="space-y-1.5">
                    {selectedPlaybook.rollback_steps.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-[11.5px] font-mono">
                        <RotateCcw className="w-3.5 h-3.5 text-sev-high shrink-0 mt-0.5" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <EmptyState title="No playbook selected" description="Select a defensive playbook to inspect specification." />
            )}
          </section>
        </div>
      ) : activeTab === 'policies' ? (
        <section className="panel">
          <div className="panel-header">
            <h2>Deterministic Response Policy Configuration</h2>
            <small className="text-muted">
              AI proposals are strictly bounded by these policies. No action executes autonomously unless permitted here.
            </small>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Action Type</th>
                  <th>Status</th>
                  <th>Autonomous Execution</th>
                  <th>Mandatory Human Approval</th>
                  <th>Min Confidence</th>
                  <th>Allowed Severities</th>
                  <th>Controls</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((pol) => (
                  <tr key={pol.action_type}>
                    <td className="font-mono font-semibold text-[12px]">{titleCase(pol.action_type)}</td>
                    <td>
                      <span
                        className={`text-[11px] font-mono px-1.5 py-0.5 rounded ${
                          pol.enabled
                            ? 'bg-success-bg text-success border border-success-border'
                            : 'bg-surface-raised text-muted border border-border'
                        }`}
                      >
                        {pol.enabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </td>
                    <td>
                      <button
                        className={`text-[11px] font-mono px-2 py-0.5 rounded border transition-colors ${
                          pol.auto_execute
                            ? 'bg-success-bg text-success border-success-border'
                            : 'bg-surface-raised text-muted border-border'
                        }`}
                        onClick={() => handleTogglePolicy(pol, 'auto_execute')}
                      >
                        {pol.auto_execute ? 'Auto Allowed' : 'Manual Only'}
                      </button>
                    </td>
                    <td>
                      <button
                        className={`text-[11px] font-mono px-2 py-0.5 rounded border transition-colors ${
                          pol.requires_approval
                            ? 'bg-sev-high-bg text-sev-high border-sev-high-border'
                            : 'bg-surface-raised text-muted border-border'
                        }`}
                        onClick={() => handleTogglePolicy(pol, 'requires_approval')}
                      >
                        {pol.requires_approval ? 'Required' : 'Bypassed if Confidence Met'}
                      </button>
                    </td>
                    <td className="font-mono text-[11.5px]">{Math.round(pol.minimum_confidence * 100)}%</td>
                    <td className="font-mono text-[11px] text-muted">{pol.allowed_severities.join(', ')}</td>
                    <td>
                      <button
                        className="secondary-button text-[11px] py-0.5 px-2"
                        onClick={() => handleTogglePolicy(pol, 'enabled')}
                      >
                        {pol.enabled ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : (
        /* Audit Log */
        <section className="panel">
          <div className="panel-header">
            <h2>Immutable SOC Defensive Audit Trail</h2>
            <small className="text-muted">
              Append-only chronological record of all AI proposals, policy decisions, executions, and verifications.
            </small>
          </div>
          {auditLog.length === 0 ? (
            <EmptyState
              title="No audit entries"
              description="Actions taken via response playbooks will append records here automatically."
            />
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Audit ID</th>
                    <th>Timestamp</th>
                    <th>Incident</th>
                    <th>Action</th>
                    <th>Policy Decision</th>
                    <th>Target</th>
                    <th>Operator</th>
                    <th>Mode</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLog.map((log) => (
                    <tr key={log.id}>
                      <td className="font-mono text-[11px] font-semibold">{log.id}</td>
                      <td className="font-mono text-[11px] text-muted">{formatDate(log.timestamp)}</td>
                      <td>
                        <Link
                          href={`/incidents/${log.incident_id}`}
                          className="font-mono text-[11px] text-accent underline"
                        >
                          {log.incident_id.slice(0, 8)}...
                        </Link>
                      </td>
                      <td className="font-mono text-[11.5px]">{titleCase(log.action)}</td>
                      <td className="font-mono text-[11px]">{log.policy_decision}</td>
                      <td className="font-mono text-[11px]">{log.target}</td>
                      <td className="font-mono text-[11px]">{log.operator}</td>
                      <td>
                        <span
                          className={`text-[10px] font-mono px-1 py-0.5 rounded ${
                            log.dry_run
                              ? 'bg-surface-raised text-muted border border-border'
                              : 'bg-success-bg text-success border border-success-border'
                          }`}
                        >
                          {log.dry_run ? 'DRY RUN' : 'EXECUTED'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </ThreatLensShell>
  )
}
