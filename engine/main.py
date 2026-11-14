import base64, hashlib, hmac, ipaddress, json, os, secrets, shutil, subprocess, time, xml.etree.ElementTree as ET
from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Cyber Security AI Agent Engine", version="0.2.0")
NMAP_PATH = shutil.which("nmap")
TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
PERMIT_SECRET = os.environ.get("SCAN_APPROVAL_SECRET", "")
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

def valid_dynamic_permit(value: Optional[str], target: str) -> bool:
    if not value or not PERMIT_SECRET:
        return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied):
            return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data.get("ip") == target and bool(data.get("id")) and isinstance(data.get("exp"), (int, float)) and data["exp"] > time.time() * 1000
    except Exception:
        return False

def check_target(value: str, permit: Optional[str]):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Target must be a literal IP address.")
    if not address.is_global:
        raise HTTPException(status_code=400, detail="Only globally routable public IP addresses are eligible.")
    static_allowed = any(address.version == net.version and address in net for net in NETWORKS)
    if not static_allowed and not valid_dynamic_permit(permit, str(address)):
        raise HTTPException(status_code=403, detail="Target requires an active admin approval bound to this exact IP.")
    return str(address)

@app.get("/health")
def health(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    ready = bool(TOKEN and NMAP_PATH and (NETWORKS or PERMIT_SECRET))
    return {"status":"ok" if ready else "degraded","engine":"nmap-safe-profile","allowlist_configured":bool(NETWORKS),"dynamic_approval_configured":bool(PERMIT_SECRET),"nmap_available":bool(NMAP_PATH),"execution_enabled":ready}

@app.get("/tools")
def tools(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    return {"available":[{"name":"Nmap","state":"ready" if TOKEN and NMAP_PATH and (NETWORKS or PERMIT_SECRET) else "blocked_until_configured","binary_available":bool(NMAP_PATH),"profile":"service discovery; top ports only; no scripts or exploit modules"}]}

@app.post("/scans/nmap")
def nmap_scan(request: ScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    if not NMAP_PATH:
        raise HTTPException(status_code=503, detail="Nmap binary is not installed in this engine image.")
    target = check_target(request.target_ip, x_scan_approval)
    command = [NMAP_PATH,"-n","-sT","-sV","-T2","--max-retries","2","--host-timeout","85s","--top-ports",str(request.top_ports),"-oX","-",target]
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
