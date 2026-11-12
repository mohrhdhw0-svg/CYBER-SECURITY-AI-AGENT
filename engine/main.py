import ipaddress, os, secrets, subprocess, xml.etree.ElementTree as ET
from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Cyber Security AI Agent Engine", version="0.1.0")
TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
NETWORKS = []
for item in os.environ.get("AUTHORIZED_CIDRS", "").split(","):
    item = item.strip()
    if item:
        NETWORKS.append(ipaddress.ip_network(item, strict=False))

class ScanRequest(BaseModel):
    target_ip: str
    authorization_reference: str = Field(min_length=4, max_length=120)
    confirm_authorized: bool
    top_ports: int = Field(default=100, ge=10, le=100)

def require_auth(value: Optional[str]):
    if not TOKEN or not value or not secrets.compare_digest(value, f"Bearer {TOKEN}"):
        raise HTTPException(status_code=401, detail="Valid engine bearer token required")

def check_target(value: str):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Target must be a literal IP address; DNS names are not accepted by this runner.")
    if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local:
        raise HTTPException(status_code=400, detail="This address class is not an eligible scan target.")
    if not NETWORKS or not any(address.version == net.version and address in net for net in NETWORKS):
        raise HTTPException(status_code=403, detail="Target is outside the configured AUTHORIZED_CIDRS allowlist.")
    return str(address)

@app.get("/health")
def health():
    return {"status":"ok","engine":"nmap-safe-profile","allowlist_configured":bool(NETWORKS),"execution_enabled":bool(TOKEN and NETWORKS)}

@app.get("/tools")
def tools():
    return {"available":[{"name":"Nmap","state":"ready" if TOKEN and NETWORKS else "blocked_until_configured","profile":"service discovery; top ports only; no scripts or exploit modules"}]}

@app.post("/scans/nmap")
def nmap_scan(request: ScanRequest, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    target = check_target(request.target_ip)
    command = ["nmap","-sV","-T2","--top-ports",str(request.top_ports),"-oX","-",target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Scan timed out after 90 seconds.")
    if result.returncode not in (0, 1):
        raise HTTPException(status_code=502, detail="Nmap execution failed; consult engine logs.")
    try:
        root = ET.fromstring(result.stdout)
        host = root.find("host")
        ports = []
        if host is not None:
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                ports.append({"port":port.get("portid"),"protocol":port.get("protocol"),"state":state.get("state") if state is not None else "unknown","service":service.get("name") if service is not None else "unknown","product":service.get("product") if service is not None else None,"version":service.get("version") if service is not None else None})
        return {"status":"completed","target":target,"authorization_reference":request.authorization_reference,"profile":"nmap-safe-profile","ports":ports,"summary":{"ports_observed":len(ports)}}
    except ET.ParseError:
        raise HTTPException(status_code=502, detail="Could not parse scanner output.")
