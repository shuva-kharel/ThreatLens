import asyncio
import httpx
import json
import pytest

BASE_URL = "http://127.0.0.1:8000"

@pytest.mark.asyncio
async def test_backend():
    async with httpx.AsyncClient(timeout=30.0) as client:
        print("[TEST] 1. Testing /health endpoint...")
        res = await client.get(f"{BASE_URL}/health")
        assert res.status_code == 200, f"Health check failed: {res.text}"
        print(f"       Health status: {res.json()['status']}, DB: {res.json()['database']}")

        print("[TEST] 2. Testing Playbooks API...")
        res = await client.get(f"{BASE_URL}/api/v1/response/playbooks")
        assert res.status_code == 200, f"Playbooks failed: {res.text}"
        playbooks = res.json()
        print(f"       Loaded {len(playbooks)} playbooks. First: {playbooks[0]['id']} ({playbooks[0]['name']})")

        print("[TEST] 3. Testing Policies API...")
        res = await client.get(f"{BASE_URL}/api/v1/response/policies")
        assert res.status_code == 200, f"Policies failed: {res.text}"
        policies = res.json()
        print(f"       Loaded {len(policies)} response policies.")

        print("[TEST] 4. Testing Vulnerabilities API...")
        res = await client.get(f"{BASE_URL}/api/v1/vulnerabilities")
        assert res.status_code == 200, f"Vulnerabilities failed: {res.text}"
        vulns = res.json()
        print(f"       Loaded {len(vulns)} CVEs. First: {vulns[0]['cve_id']}")

        print("[TEST] 5. Simulating Full Attack Pipeline...")
        res = await client.post(f"{BASE_URL}/api/v1/simulate/full-attack?attacker_ip=10.10.10.99&target_ip=10.10.10.10")
        assert res.status_code == 200, f"Simulation failed: {res.text}"
        sim_data = res.json()
        print(f"       Simulation result: {sim_data['events_sent']} events sent, {sim_data['alerts_created']} alerts, {sim_data['incidents_created']} incidents.")

        print("[TEST] 6. Fetching generated incident...")
        res = await client.get(f"{BASE_URL}/api/v1/incidents?limit=1")
        assert res.status_code == 200
        incidents = res.json()
        assert len(incidents) > 0, "No incidents found after simulation"
        incident = incidents[0]
        inc_id = incident["id"]
        print(f"       Incident: {inc_id} - {incident['title']} ({incident['status']})")

        print("[TEST] 7. Testing TraceAI reconstruction...")
        res = await client.get(f"{BASE_URL}/api/v1/incidents/{inc_id}/trace")
        assert res.status_code == 200
        trace = res.json()
        print(f"       Trace timeline events: {len(trace.get('timeline', []))}, Attack graph nodes: {len(trace.get('attack_graph', {}).get('nodes', []))}")

        print("[TEST] 8. Planning AI Response Proposal...")
        res = await client.post(f"{BASE_URL}/api/v1/response/incidents/{inc_id}/plan")
        assert res.status_code == 200, f"Plan failed: {res.text}"
        proposal = res.json()
        print(f"       Proposal action: {proposal['recommended_action']}, target: {proposal['target']}")
        print(f"       Policy check: Auto allowed = {proposal['policy_evaluation']['auto_execute']}, Requires approval = {proposal['requires_approval']}")

        print("[TEST] 9. Executing Dry Run Preview...")
        exec_payload = {
            "action": proposal["recommended_action"],
            "target": proposal["target"],
            "playbook_id": proposal["playbook_id"],
            "dry_run": True,
            "approved_by": "test_suite"
        }
        res = await client.post(f"{BASE_URL}/api/v1/response/incidents/{inc_id}/execute", json=exec_payload)
        assert res.status_code == 200
        dry_exec = res.json()
        print(f"       Dry run execution {dry_exec['execution_id']} status: {dry_exec['status']} (Verified: {dry_exec['verification_result']['verified']})")

        print("[TEST] 10. Executing Verified Containment Action (Demo Mode)...")
        exec_payload["dry_run"] = False
        res = await client.post(f"{BASE_URL}/api/v1/response/incidents/{inc_id}/execute", json=exec_payload)
        assert res.status_code == 200
        live_exec = res.json()
        print(f"       Live execution {live_exec['execution_id']} status: {live_exec['status']} (Verification: {live_exec['verification_result']['details']})")

        print("[TEST] 11. Verifying Incident State updated to contained...")
        res = await client.get(f"{BASE_URL}/api/v1/incidents/{inc_id}")
        assert res.status_code == 200
        updated_inc = res.json()["incident"]
        print(f"       Incident updated status: {updated_inc['status']}")
        assert updated_inc["status"] == "contained", f"Expected status 'contained', got {updated_inc['status']}"

        print("[TEST] 12. Testing Idempotency on repeated execution...")
        res = await client.post(f"{BASE_URL}/api/v1/response/incidents/{inc_id}/execute", json=exec_payload)
        assert res.status_code == 200
        idempotent_exec = res.json()
        print(f"       Idempotent execution status: {idempotent_exec['status']}, idempotent flag: {idempotent_exec['result'].get('idempotent')}")

        print("[TEST] 13. Testing Rollback...")
        res = await client.post(f"{BASE_URL}/api/v1/response/incidents/{inc_id}/rollback?execution_id={live_exec['execution_id']}&operator=test_suite")
        assert res.status_code == 200
        rollback_res = res.json()
        print(f"       Rollback result: {rollback_res['status']}, restored target: {rollback_res['rollback']['restored_target']}")

        print("[TEST] 14. Testing Audit Log...")
        res = await client.get(f"{BASE_URL}/api/v1/response/audit")
        assert res.status_code == 200
        audit_records = res.json()
        print(f"       Audit records count: {len(audit_records)}. Latest audit: {audit_records[0]['action']} on {audit_records[0]['target']}")

        print("[TEST] 15. Testing Incident Exports (JSON & CSV)...")
        res_json = await client.get(f"{BASE_URL}/api/v1/incidents/export/{inc_id}/export/json")
        assert res_json.status_code == 200
        res_csv = await client.get(f"{BASE_URL}/api/v1/incidents/export/{inc_id}/export/csv")
        assert res_csv.status_code == 200
        print("       Export endpoints operational (JSON + CSV).")

        print("\n[SUCCESS] ALL 15 END-TO-END VERIFICATION CHECKS PASSED!")

if __name__ == "__main__":
    asyncio.run(test_backend())
