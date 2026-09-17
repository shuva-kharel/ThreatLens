from fastapi import APIRouter, HTTPException, Depends
from typing import List
from app.models.response_models import VulnerabilityFinding
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()

def get_vuln_service() -> VulnerabilityService:
    return VulnerabilityService()

@router.get("", response_model=List[VulnerabilityFinding])
async def list_vulnerabilities(service: VulnerabilityService = Depends(get_vuln_service)):
    """List all tracked demonstration CVEs and configuration weaknesses."""
    return service.list_vulnerabilities()

@router.get("/{cve_id}", response_model=VulnerabilityFinding)
async def get_vulnerability(cve_id: str, service: VulnerabilityService = Depends(get_vuln_service)):
    """Get details, mitigation guidance, and remediation playbook for a CVE."""
    vuln = service.get_vulnerability(cve_id)
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability {cve_id} not found")
    return vuln
