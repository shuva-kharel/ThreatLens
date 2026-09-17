from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
from app.models.response_models import (
    ActionType, RiskLevel, ExecutionStatus,
    ResponsePlaybook, ResponsePolicy, ResponseProposal,
    PolicyEvaluationResult, ResponseExecutionRecord,
    ResponseVerificationResult, ResponseAuditEntry
)

class ResponseService:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ResponseService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.playbooks: Dict[str, ResponsePlaybook] = self._init_playbooks()
        self.policies: Dict[ActionType, ResponsePolicy] = self._init_policies()
        self.executions: Dict[str, ResponseExecutionRecord] = {}
        self.audit_log: List[ResponseAuditEntry] = []
        # Containment state tracking for idempotency & rollback
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.disabled_accounts: Dict[str, Dict[str, Any]] = {}
        self.isolated_endpoints: Dict[str, Dict[str, Any]] = {}
        self.applied_mitigations: Dict[str, Dict[str, Any]] = {}

    def _init_playbooks(self) -> Dict[str, ResponsePlaybook]:
        pbs = [
            ResponsePlaybook(
                id="PB-BLOCK-IP",
                name="Boundary Firewall Malicious IP Block",
                description="Adds confirmed malicious IP to network boundary perimeter blocklist.",
                action_type=ActionType.BLOCK_IP,
                risk_level=RiskLevel.LOW,
                supported_incident_types=["SSH Brute Force", "Port Scan", "Credential Access", "Command & Control"],
                required_permissions=["firewall:write", "net:acl"],
                auto_execute_allowed=True,
                verification_steps=[
                    "Query perimeter firewall rule table for source IP drop rule",
                    "Verify synthetic syn-ack probe drops from target IP",
                    "Monitor for absence of ingress traffic for 60 seconds"
                ],
                rollback_steps=[
                    "Remove drop rule for IP from perimeter firewall table",
                    "Flush connection state table entry",
                    "Verify connectivity restoration"
                ]
            ),
            ResponsePlaybook(
                id="PB-DISABLE-ACCOUNT",
                name="Compromised User Account Lockout",
                description="Immediately suspends compromised user account credentials and revokes authentication tokens.",
                action_type=ActionType.DISABLE_ACCOUNT,
                risk_level=RiskLevel.MEDIUM,
                supported_incident_types=["Credential Access", "Privilege Escalation", "Successful Login After Failures"],
                required_permissions=["iam:users:update", "auth:sessions:revoke"],
                auto_execute_allowed=False,
                verification_steps=[
                    "Query IAM directory status confirming account Disabled state",
                    "Check token revocation list for active user tokens"
                ],
                rollback_steps=[
                    "Restore user account status to Active in IAM directory",
                    "Notify security operations and asset owner"
                ]
            ),
            ResponsePlaybook(
                id="PB-FORCE-PASSWORD-RESET",
                name="Enforce Credential Reset",
                description="Flags targeted account for mandatory credential rotation on next authentication.",
                action_type=ActionType.FORCE_PASSWORD_RESET,
                risk_level=RiskLevel.LOW,
                supported_incident_types=["Credential Access", "SSH Brute Force"],
                required_permissions=["iam:users:update"],
                auto_execute_allowed=True,
                verification_steps=[
                    "Verify password_reset_required flag in identity store",
                    "Confirm temporary session token issuance restricted"
                ],
                rollback_steps=[
                    "Clear password_reset_required flag if false positive confirmed"
                ]
            ),
            ResponsePlaybook(
                id="PB-TERMINATE-SESSION",
                name="Revoke Active Authentication Session",
                description="Kills active SSH / Web sessions associated with suspicious activity.",
                action_type=ActionType.TERMINATE_SESSION,
                risk_level=RiskLevel.LOW,
                supported_incident_types=["Successful Login After Failures", "Initial Access"],
                required_permissions=["host:sessions:terminate"],
                auto_execute_allowed=True,
                verification_steps=[
                    "Check target host active session list (w/who/sshd pid)",
                    "Verify session descriptor terminated"
                ],
                rollback_steps=[
                    "Inform operator; session terminations cannot be reconnected directly"
                ]
            ),
            ResponsePlaybook(
                id="PB-ISOLATE-ENDPOINT",
                name="Host Network Isolation",
                description="Isolates infected host from LAN, preserving only SOC management tunnel.",
                action_type=ActionType.ISOLATE_ENDPOINT,
                risk_level=RiskLevel.HIGH,
                supported_incident_types=["Privilege Escalation", "Execution", "Lateral Movement", "Ransomware"],
                required_permissions=["edr:isolate", "net:quarantine"],
                auto_execute_allowed=False,
                verification_steps=[
                    "Check EDR agent quarantine status report",
                    "Verify all outbound subnet routes dropped except SOC controller IP"
                ],
                rollback_steps=[
                    "Remove EDR network isolation filter",
                    "Restore default gateway routing tables",
                    "Verify management & LAN ping responses"
                ]
            ),
            ResponsePlaybook(
                id="PB-DISABLE-SERVICE",
                name="Vulnerable Service Shutdown",
                description="Gracefully stops vulnerable or compromised daemon service on host.",
                action_type=ActionType.DISABLE_SERVICE,
                risk_level=RiskLevel.HIGH,
                supported_incident_types=["Execution", "Vulnerability Exploit"],
                required_permissions=["host:systemctl:manage"],
                auto_execute_allowed=False,
                verification_steps=[
                    "Verify systemd service unit status is inactive (dead)",
                    "Confirm listening port closed on host interface"
                ],
                rollback_steps=[
                    "Restart daemon service via systemctl start",
                    "Confirm listening port reopened and healthy"
                ]
            ),
            ResponsePlaybook(
                id="PB-APPLY-MITIGATION",
                name="Security Configuration Hardening / Hotfix",
                description="Applies vendor-recommended configuration mitigation for identified vulnerability.",
                action_type=ActionType.APPLY_MITIGATION,
                risk_level=RiskLevel.MEDIUM,
                supported_cves=["CVE-2023-48795", "CVE-2024-6387", "CVE-2021-44228"],
                supported_incident_types=["Vulnerability Exploit", "Configuration Weakness"],
                required_permissions=["config:remediate"],
                auto_execute_allowed=False,
                verification_steps=[
                    "Inspect configuration file checksum / directive",
                    "Verify patched behavioral response against test harness"
                ],
                rollback_steps=[
                    "Restore backup configuration file",
                    "Reload service configuration"
                ]
            ),
            ResponsePlaybook(
                id="PB-ROTATE-CREDENTIAL",
                name="Service Secret & Key Rotation",
                description="Invalidates exposed API keys or service credentials and injects newly generated secrets.",
                action_type=ActionType.ROTATE_CREDENTIAL,
                risk_level=RiskLevel.MEDIUM,
                supported_incident_types=["Credential Access", "Exfiltration"],
                required_permissions=["vault:secrets:rotate"],
                auto_execute_allowed=False,
                verification_steps=[
                    "Verify previous secret key hash invalidated in Vault",
                    "Confirm test authentication succeeds with rotated secret"
                ],
                rollback_steps=[
                    "Re-enable prior secret version in Vault if dependent services break"
                ]
            ),
            ResponsePlaybook(
                id="PB-COLLECT-EVIDENCE",
                name="Automated Digital Forensics Triage",
                description="Collects memory dump, process trees, volatile network sockets, and auth logs from target host.",
                action_type=ActionType.COLLECT_EVIDENCE,
                risk_level=RiskLevel.LOW,
                supported_incident_types=["*"],
                required_permissions=["forensics:collect"],
                auto_execute_allowed=True,
                verification_steps=[
                    "Confirm archive checksum and size in secure evidence store",
                    "Verify cryptographic hash chain integrity"
                ],
                rollback_steps=[
                    "No rollback required (read-only forensic preservation)"
                ]
            )
        ]
        return {pb.id: pb for pb in pbs}

    def _init_policies(self) -> Dict[ActionType, ResponsePolicy]:
        return {
            ActionType.BLOCK_IP: ResponsePolicy(
                action_type=ActionType.BLOCK_IP,
                enabled=True,
                auto_execute=True,
                minimum_confidence=0.85,
                allowed_severities=["medium", "high", "critical"],
                requires_approval=False,
                dry_run_default=False
            ),
            ActionType.DISABLE_ACCOUNT: ResponsePolicy(
                action_type=ActionType.DISABLE_ACCOUNT,
                enabled=True,
                auto_execute=False,
                minimum_confidence=0.90,
                allowed_severities=["high", "critical"],
                requires_approval=True,
                dry_run_default=True
            ),
            ActionType.FORCE_PASSWORD_RESET: ResponsePolicy(
                action_type=ActionType.FORCE_PASSWORD_RESET,
                enabled=True,
                auto_execute=True,
                minimum_confidence=0.80,
                allowed_severities=["medium", "high", "critical"],
                requires_approval=False,
                dry_run_default=False
            ),
            ActionType.TERMINATE_SESSION: ResponsePolicy(
                action_type=ActionType.TERMINATE_SESSION,
                enabled=True,
                auto_execute=True,
                minimum_confidence=0.85,
                allowed_severities=["medium", "high", "critical"],
                requires_approval=False,
                dry_run_default=False
            ),
            ActionType.ISOLATE_ENDPOINT: ResponsePolicy(
                action_type=ActionType.ISOLATE_ENDPOINT,
                enabled=True,
                auto_execute=False,
                minimum_confidence=0.95,
                allowed_severities=["critical"],
                requires_approval=True,
                dry_run_default=True
            ),
            ActionType.DISABLE_SERVICE: ResponsePolicy(
                action_type=ActionType.DISABLE_SERVICE,
                enabled=True,
                auto_execute=False,
                minimum_confidence=0.90,
                allowed_severities=["high", "critical"],
                requires_approval=True,
                dry_run_default=True
            ),
            ActionType.APPLY_MITIGATION: ResponsePolicy(
                action_type=ActionType.APPLY_MITIGATION,
                enabled=True,
                auto_execute=False,
                minimum_confidence=0.85,
                allowed_severities=["medium", "high", "critical"],
                requires_approval=True,
                dry_run_default=True
            ),
            ActionType.ROTATE_CREDENTIAL: ResponsePolicy(
                action_type=ActionType.ROTATE_CREDENTIAL,
                enabled=True,
                auto_execute=False,
                minimum_confidence=0.90,
                allowed_severities=["high", "critical"],
                requires_approval=True,
                dry_run_default=True
            ),
            ActionType.COLLECT_EVIDENCE: ResponsePolicy(
                action_type=ActionType.COLLECT_EVIDENCE,
                enabled=True,
                auto_execute=True,
                minimum_confidence=0.70,
                allowed_severities=["low", "medium", "high", "critical"],
                requires_approval=False,
                dry_run_default=False
            )
        }

    def evaluate_policy(self, action: ActionType, incident_severity: str, confidence: float) -> PolicyEvaluationResult:
        policy = self.policies.get(action)
        if not policy or not policy.enabled:
            return PolicyEvaluationResult(
                allowed=False,
                requires_approval=True,
                reason=f"Action '{action.value}' is disabled by security policy.",
                policy_id=f"POL-{action.value}",
                auto_execute=False
            )

        if incident_severity.lower() not in [s.lower() for s in policy.allowed_severities]:
            return PolicyEvaluationResult(
                allowed=False,
                requires_approval=True,
                reason=f"Incident severity '{incident_severity}' does not meet policy threshold {policy.allowed_severities}.",
                policy_id=f"POL-{action.value}",
                auto_execute=False
            )

        if confidence < policy.minimum_confidence:
            return PolicyEvaluationResult(
                allowed=True,
                requires_approval=True,
                reason=f"Incident confidence ({confidence:.2f}) is below auto-execution threshold ({policy.minimum_confidence:.2f}). Analyst review required.",
                policy_id=f"POL-{action.value}",
                auto_execute=False
            )

        if policy.requires_approval or not policy.auto_execute:
            return PolicyEvaluationResult(
                allowed=True,
                requires_approval=True,
                reason=f"Policy requires mandatory human analyst approval for '{action.value}' due to operational impact risks.",
                policy_id=f"POL-{action.value}",
                auto_execute=False
            )

        return PolicyEvaluationResult(
            allowed=True,
            requires_approval=False,
            reason=f"Policy allows autonomous execution for low-risk action '{action.value}' (confidence {confidence:.2f} >= {policy.minimum_confidence:.2f}).",
            policy_id=f"POL-{action.value}",
            auto_execute=True
        )

    def formulate_proposal(self, incident: Any, alerts: List[Any], trace: Optional[Dict[str, Any]] = None) -> ResponseProposal:
        """Bounded AI response reasoning engine over structured evidence."""
        title = getattr(incident, "title", "Unknown Incident")
        severity = getattr(incident, "severity", "medium")
        if hasattr(severity, "value"):
            severity = severity.value
        confidence = float(getattr(incident, "confidence", 0.85))

        sources = getattr(incident, "source_entities", []) or []
        targets = getattr(incident, "target_entities", []) or []
        primary_source = sources[0] if sources else "10.10.10.50"
        primary_target = targets[0] if targets else "10.10.10.10"

        # Deterministic attack classification & playbook recommendation
        title_lower = title.lower()
        if "brute force" in title_lower or "ssh" in title_lower or "recon" in title_lower:
            recommended_action = ActionType.BLOCK_IP
            playbook_id = "PB-BLOCK-IP"
            classification = "SSH Brute Force / Perimeter Probing"
            target = primary_source
            reason = f"Repeated unauthorized authentication failures originating from source {primary_source} exceeded containment threshold."
            evidence = [
                f"Source entity: {primary_source}",
                f"Target entity: {primary_target}",
                f"{len(alerts)} correlated security alert events detected",
                "MITRE T1110 (Brute Force) signature pattern confirmed"
            ]
            risk_level = RiskLevel.LOW
        elif "privilege" in title_lower or "escalation" in title_lower or "root" in title_lower:
            recommended_action = ActionType.ISOLATE_ENDPOINT
            playbook_id = "PB-ISOLATE-ENDPOINT"
            classification = "Host Compromise & Privilege Escalation"
            target = primary_target
            reason = f"Host {primary_target} exhibited post-exploitation privilege elevation; network isolation prevents lateral propagation."
            evidence = [
                f"Target host: {primary_target}",
                "Elevated process activity observed",
                "MITRE T1068 / T1548 technique detected"
            ]
            risk_level = RiskLevel.HIGH
        elif "credential" in title_lower or "login" in title_lower:
            recommended_action = ActionType.FORCE_PASSWORD_RESET
            playbook_id = "PB-FORCE-PASSWORD-RESET"
            classification = "Credential Exposure / Account Hijacking"
            target = "admin"
            reason = f"Suspicious login anomalies detected against administrative accounts on {primary_target}."
            evidence = [
                "Authentication anomaly after credential access",
                f"Target account: admin on {primary_target}"
            ]
            risk_level = RiskLevel.LOW
        else:
            recommended_action = ActionType.BLOCK_IP
            playbook_id = "PB-BLOCK-IP"
            classification = "Suspicious Network Incursion"
            target = primary_source
            reason = f"Defensive perimeter block on suspicious origin {primary_source} to neutralize ongoing telemetry."
            evidence = [f"Source: {primary_source}", f"Target: {primary_target}"]
            risk_level = RiskLevel.LOW

        policy_eval = self.evaluate_policy(recommended_action, severity, confidence)
        playbook = self.playbooks.get(playbook_id)

        dry_run_preview = {
            "proposed_action": recommended_action.value,
            "target": target,
            "reason": reason,
            "expected_effect": f"Immediately drops network traffic or access for {target} via {playbook.name if playbook else playbook_id}",
            "potential_impact": "Operational disruption is minimal; boundary firewall rules isolate malicious origin without host downtime" if risk_level == RiskLevel.LOW else "High operational impact; requires authorized analyst sign-off before containment.",
            "rollback_method": playbook.rollback_steps[0] if playbook and playbook.rollback_steps else "Automatic rule deletion",
            "verification_steps": playbook.verification_steps if playbook else ["Rule status check"]
        }

        return ResponseProposal(
            incident_id=str(getattr(incident, "id", "")),
            classification=classification,
            confidence=confidence,
            recommended_action=recommended_action,
            playbook_id=playbook_id,
            target=target,
            reason=reason,
            evidence=evidence,
            requires_approval=policy_eval.requires_approval,
            risk_level=risk_level,
            verification_required=True,
            policy_evaluation=policy_eval,
            dry_run_preview=dry_run_preview
        )

    def execute_action(
        self,
        incident_id: str,
        action: ActionType,
        target: str,
        playbook_id: Optional[str] = None,
        dry_run: bool = True,
        approved_by: str = "analyst",
        parameters: Optional[Dict[str, Any]] = None
    ) -> ResponseExecutionRecord:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        pb_id = playbook_id or f"PB-{action.value.upper()}"
        playbook = self.playbooks.get(pb_id) or self.playbooks.get("PB-BLOCK-IP")

        started_at = datetime.utcnow()

        # Idempotency check
        if action == ActionType.BLOCK_IP and target in self.blocked_ips and not dry_run:
            return ResponseExecutionRecord(
                execution_id=execution_id,
                incident_id=incident_id,
                playbook_id=pb_id,
                action=action,
                target=target,
                requested_by="response_agent",
                approved_by=approved_by,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                status=ExecutionStatus.VERIFIED,
                dry_run=False,
                result={
                    "mode": "DEMO MODE (Simulated)",
                    "idempotent": True,
                    "message": f"Target IP {target} is already blocked in perimeter ACL.",
                    "applied_rule": self.blocked_ips[target]
                },
                verification_result={
                    "verified": True,
                    "method": "Perimeter ACL check",
                    "details": f"Drop rule for {target} active and confirmed.",
                    "timestamp": datetime.utcnow().isoformat()
                },
                rollback_available=True
            )

        # Simulation execution logic
        if dry_run:
            status = ExecutionStatus.EXECUTED
            result = {
                "mode": "DRY RUN (Preview Only)",
                "action": action.value,
                "target": target,
                "simulated_effect": f"Would apply {playbook.name} on target {target}",
                "no_changes_made": True
            }
            verification = {
                "verified": True,
                "method": "Dry-run validation",
                "details": "Simulated dry-run verification completed successfully. No state altered.",
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            status = ExecutionStatus.EXECUTED
            rule_id = f"RULE-{uuid.uuid4().hex[:6].upper()}"
            result = {
                "mode": "DEMO MODE (Simulated Execution)",
                "action": action.value,
                "target": target,
                "rule_id": rule_id,
                "playbook": playbook.name if playbook else pb_id,
                "execution_time_ms": 42,
                "message": f"Successfully executed defensive playbook {playbook.name if playbook else pb_id} on target {target}."
            }

            # Update tracked state
            if action == ActionType.BLOCK_IP:
                self.blocked_ips[target] = {"rule_id": rule_id, "timestamp": started_at.isoformat(), "incident_id": incident_id}
            elif action == ActionType.DISABLE_ACCOUNT:
                self.disabled_accounts[target] = {"timestamp": started_at.isoformat(), "incident_id": incident_id}
            elif action == ActionType.ISOLATE_ENDPOINT:
                self.isolated_endpoints[target] = {"timestamp": started_at.isoformat(), "incident_id": incident_id}

            # Verification step
            verification = {
                "verified": True,
                "method": playbook.verification_steps[0] if playbook and playbook.verification_steps else "Synthetic probe",
                "details": f"Verification passed: No telemetry flows or unauthorized sessions detected from {target}.",
                "timestamp": datetime.utcnow().isoformat()
            }
            status = ExecutionStatus.VERIFIED

        record = ResponseExecutionRecord(
            execution_id=execution_id,
            incident_id=incident_id,
            playbook_id=pb_id,
            action=action,
            target=target,
            requested_by="response_agent",
            approved_by=approved_by,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            status=status,
            dry_run=dry_run,
            result=result,
            verification_result=verification,
            rollback_available=not dry_run and action in [ActionType.BLOCK_IP, ActionType.DISABLE_ACCOUNT, ActionType.ISOLATE_ENDPOINT]
        )

        self.executions[execution_id] = record

        # Record to append-only audit log
        audit_entry = ResponseAuditEntry(
            id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow(),
            incident_id=incident_id,
            agent="ThreatLens AI Response Agent",
            action=action,
            policy_decision="Authorized by Operator" if approved_by != "policy_engine" else "Autonomous Policy Allowed",
            target=target,
            operator=approved_by or "system",
            execution_result=result,
            verification=verification,
            dry_run=dry_run
        )
        self.audit_log.insert(0, audit_entry)

        return record

    def rollback_action(self, execution_id: str, operator: str = "analyst") -> Dict[str, Any]:
        record = self.executions.get(execution_id)
        if not record:
            return {"status": "error", "message": f"Execution {execution_id} not found"}

        if not record.rollback_available:
            return {"status": "error", "message": "Rollback not available for this action or dry-run execution"}

        target = record.target
        action = record.action

        if action == ActionType.BLOCK_IP:
            self.blocked_ips.pop(target, None)
        elif action == ActionType.DISABLE_ACCOUNT:
            self.disabled_accounts.pop(target, None)
        elif action == ActionType.ISOLATE_ENDPOINT:
            self.isolated_endpoints.pop(target, None)

        record.status = ExecutionStatus.ROLLED_BACK
        record.rollback_available = False

        rollback_details = {
            "rolled_back_at": datetime.utcnow().isoformat(),
            "operator": operator,
            "restored_target": target,
            "message": f"Rollback successfully restored previous defensive state for {target}."
        }

        # Audit rollback
        audit_entry = ResponseAuditEntry(
            id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow(),
            incident_id=record.incident_id,
            agent="ThreatLens Rollback Controller",
            action=action,
            policy_decision="Rollback Requested",
            target=target,
            operator=operator,
            execution_result={"rollback": True},
            verification={"status": "Restored"},
            rollback=rollback_details,
            dry_run=False
        )
        self.audit_log.insert(0, audit_entry)

        return {
            "status": "success",
            "execution_id": execution_id,
            "rollback": rollback_details
        }
