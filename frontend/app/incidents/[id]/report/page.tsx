"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Download, ArrowLeft } from "lucide-react";
import { api, type IncidentReport } from "@/lib/api";
import { ThreatLensShell } from "@/components/threatlens/shell";
import { ErrorState, LoadingState, SeverityBadge } from "@/components/threatlens/ui";
import { entityList, formatReportDate, formatTime, titleCase } from "@/components/threatlens/format";

function ValueTable({ rows }: { rows: Record<string, unknown> }) {
  return (
    <table className="report-table">
      <tbody>
        {Object.entries(rows).filter(([, value]) => value !== null && value !== undefined && value !== "").map(([key, value]) => (
          <tr key={key}>
            <th>{key}</th>
            <td>{Array.isArray(value) ? value.join(", ") || "Not available" : String(value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ReportSection({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="report-section"><h2>{title}</h2>{children}</section>;
}

export default function IncidentReportPage() {
  const params = useParams();
  const id = typeof params?.id === "string" ? params.id : Array.isArray(params?.id) ? params.id[0] : "";
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!id) return;
    setLoading(true);
    setError(null);
    api.incidentReport(id)
      .then(setReport)
      .catch((err) => setError(err instanceof Error ? err.message : "Unable to generate report."))
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => { load(); }, [load]);

  return (
    <ThreatLensShell>
      {loading ? <LoadingState label="Generating incident report..." /> : error ? <ErrorState error={error} retry={load} /> : report ? (
        <>
          <section className="page-heading report-actions">
            <div>
              <div className="eyebrow">Incident Report Preview</div>
              <h1>{report.incident.title}</h1>
            </div>
            <div className="heading-actions">
              <Link className="secondary-button" href={`/incidents/${id}`}><ArrowLeft /> Investigation</Link>
              <button className="primary-button" onClick={() => window.print()}><Download /> Download PDF</button>
            </div>
          </section>

          <article className="incident-report">
            <header className="report-cover">
              <div>
                <strong>THREATLENS</strong>
                <h1>Security Incident Report</h1>
              </div>
              <div className="report-meta">
                <span>Incident ID: {report.incident.id}</span>
                <span>Classification: Analyst Selected / Internal</span>
                <span>Status: {titleCase(report.incident.status)}</span>
                <span>Generated: {formatReportDate(report.metadata.generated_at)}</span>
                <span>{report.metadata.display_timezone} {report.metadata.display_utc_offset}</span>
              </div>
            </header>

            <ReportSection title="Executive Summary">
              <p>{report.executive_summary}</p>
            </ReportSection>

            <ReportSection title="Incident Overview">
              <ValueTable rows={{
                ...report.overview,
                "First Seen": formatReportDate(String(report.overview["First Seen"] ?? "")),
                "Last Seen": formatReportDate(String(report.overview["Last Seen"] ?? "")),
              }} />
            </ReportSection>

            {report.timeline.length > 0 && (
              <ReportSection title="Incident Timeline">
                <table className="report-table">
                  <thead><tr><th>Time</th><th>Type</th><th>Activity</th><th>Evidence</th></tr></thead>
                  <tbody>{report.timeline.map((item, index) => (
                    <tr key={`${item.timestamp}-${index}`}>
                      <td className="mono-data">{formatTime(item.timestamp, true)}</td>
                      <td>{titleCase(item.type)}</td>
                      <td><strong>{titleCase(item.title)}</strong><br />{item.description ?? "Not available"}</td>
                      <td className="mono-data">{item.evidence_id ?? "Not available"}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </ReportSection>
            )}

            {(report.attack_narrative.observed_evidence.length > 0 || report.attack_narrative.interpretation.length > 0) && (
              <ReportSection title="Attack Narrative">
                {report.attack_narrative.observed_evidence.length > 0 && <><h3>Observed Evidence</h3><ul>{report.attack_narrative.observed_evidence.map((item) => <li key={item}>{item}</li>)}</ul></>}
                {report.attack_narrative.interpretation.length > 0 && <><h3>Analyst / AI Interpretation</h3><ul>{report.attack_narrative.interpretation.map((item) => <li key={item}>{item}</li>)}</ul></>}
              </ReportSection>
            )}

            <ReportSection title="Indicators / Entities">
              <ValueTable rows={{
                "Source IP": entityList(report.entities.source_ips),
                "Destination / Host": entityList(report.entities.target_hosts),
                "Users": entityList(report.entities.usernames),
              }} />
            </ReportSection>

            {report.mitre.length > 0 && (
              <ReportSection title="MITRE ATT&CK Mapping">
                <table className="report-table"><thead><tr><th>Tactic</th><th>Technique</th><th>Description</th></tr></thead>
                  <tbody>{report.mitre.map((tech) => <tr key={tech.id}><td>{tech.tactic}</td><td><strong>{tech.id}</strong> - {tech.name}</td><td>{tech.description}</td></tr>)}</tbody>
                </table>
              </ReportSection>
            )}

            {report.alerts.length > 0 && (
              <ReportSection title="Associated Alerts">
                <table className="report-table"><thead><tr><th>Alert</th><th>Severity</th><th>Detection</th><th>Timestamp</th><th>Evidence</th></tr></thead>
                  <tbody>{report.alerts.map((alert) => <tr key={alert.id}><td>{alert.id}</td><td><SeverityBadge value={alert.severity} /></td><td>{titleCase(alert.alert_type)}<br />{alert.description}</td><td>{formatReportDate(alert.created_at)}</td><td>{alert.evidence?.join(", ") || "Not available"}</td></tr>)}</tbody>
                </table>
              </ReportSection>
            )}

            {report.ai_assisted_analysis && (
              <ReportSection title="AI Analyst Assessment">
                <p><strong>AI-Assisted Analysis:</strong> {report.ai_assisted_analysis.summary ?? "Not available"}</p>
                {report.ai_assisted_analysis.recommendations.length > 0 && <ul>{report.ai_assisted_analysis.recommendations.map((item) => <li key={item}>{item}</li>)}</ul>}
              </ReportSection>
            )}

            {report.responses.length > 0 && (
              <ReportSection title="Response & Containment">
                <table className="report-table"><thead><tr><th>Execution</th><th>Action</th><th>Target</th><th>Status</th><th>Mode</th></tr></thead>
                  <tbody>{report.responses.map((exec) => <tr key={exec.execution_id}><td>{exec.execution_id}</td><td>{titleCase(exec.action)}</td><td>{exec.target}</td><td>{titleCase(exec.status)}</td><td>{exec.dry_run ? "Dry run / simulated" : "Executed"}</td></tr>)}</tbody>
                </table>
              </ReportSection>
            )}

            {report.verification.length > 0 && (
              <ReportSection title="Verification">
                <table className="report-table"><thead><tr><th>Response</th><th>Execution Time</th><th>Method</th><th>Verification Time</th><th>Result</th></tr></thead>
                  <tbody>{report.verification.map((exec) => <tr key={exec.execution_id}><td>{exec.execution_id}</td><td>{formatReportDate(exec.started_at)}</td><td>{exec.verification_result?.method ?? "Not available"}</td><td>{formatReportDate(exec.verification_result?.timestamp)}</td><td className={exec.verification_result?.verified ? "verified-cell" : ""}>{exec.verification_result?.verified ? "VERIFIED" : "Not verified"}</td></tr>)}</tbody>
                </table>
              </ReportSection>
            )}

            {report.human_escalation?.requires_human_review && (
              <ReportSection title="Human Escalation">
                <div className="report-alert">HUMAN REVIEW REQUIRED</div>
                <ValueTable rows={{
                  "Recurrence Count": report.human_escalation.recurrence_count,
                  "Previous Response": report.human_escalation.previous_action,
                  "Previous Verification": formatReportDate(report.human_escalation.previous_verification_at),
                  "New Activity Time": formatReportDate(report.human_escalation.last_activity_at),
                  "Escalation Reason": report.human_escalation.reason,
                  "Escalation Status": report.human_escalation.status,
                  "Assigned Analyst": report.human_escalation.assigned_to ?? "Unassigned",
                  "Slack Notification Status": report.human_escalation.slack_notification_status,
                }} />
              </ReportSection>
            )}

            {report.recommendations.length > 0 && <ReportSection title="Recommendations / Next Steps"><ul>{report.recommendations.map((item) => <li key={item}>{item}</li>)}</ul></ReportSection>}

            <ReportSection title="Evidence Summary">
              <ValueTable rows={report.evidence_summary} />
            </ReportSection>

            {report.audit_history.length > 0 && (
              <ReportSection title="Audit / Response History">
                <table className="report-table"><thead><tr><th>Time</th><th>Action</th><th>Decision</th><th>Operator</th></tr></thead>
                  <tbody>{report.audit_history.map((audit) => <tr key={audit.id}><td>{formatReportDate(audit.timestamp)}</td><td>{titleCase(audit.action)}</td><td>{audit.policy_decision}</td><td>{audit.operator}</td></tr>)}</tbody>
                </table>
              </ReportSection>
            )}

            <footer>Generated by ThreatLens | Security Incident Report | {report.incident.id}</footer>
          </article>
        </>
      ) : null}
    </ThreatLensShell>
  );
}
