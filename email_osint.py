import sys, asyncio, hashlib, socket
from email_validator import validate_email, EmailNotValidError
import dns.resolver, dns.reversename
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import pyperclip
    HAS_CLIP = True
except ImportError:
    HAS_CLIP = False

console = Console(force_terminal=True)

ASCII_BANNER = r"""
 ________  ________  ________  ________  ________  ___       ___     
|\   ____\|\   __  \|\   __  \|\   __  \|\   __  \|\  \     |\  \    
\ \  \___|\ \  \|\  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \    \ \  \   
 \ \  \    \ \  \\\  \ \   _  _\ \   ____\ \  \\\  \ \  \    \ \  \  
  \ \  \____\ \  \\\  \ \  \\  \\ \  \___|\ \  \\\  \ \  \____\ \  \ 
   \ \_______\ \_______\ \__\\ _\\ \__\    \ \_______\ \_______\ \__\
    \|_______|\|_______|\|__|\|__|\|__|     \|_______|\|_______|\|__|  
"""

PROMPT = "[+]wiz#mail-> "

def print_banner():
    banner = Text(ASCII_BANNER, style="bold magenta")
    console.print(Panel(banner, border_style="purple"))

async def lookup_mx(domain: str):
    """Return MX records with priorities, IPs, and PTRs."""
    mx_info = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for r in answers:
            host = str(r.exchange).rstrip(".")
            priority = r.preference
            ips = []
            ptrs = []
            try:
                ip_answers = dns.resolver.resolve(host, "A")
                ips = [a.to_text() for a in ip_answers]
                for ip in ips:
                    try:
                        rev = dns.reversename.from_address(ip)
                        ptr_ans = dns.resolver.resolve(rev, "PTR")
                        ptrs.extend([p.to_text().rstrip(".") for p in ptr_ans])
                    except Exception:
                        ptrs.append("N/A")
            except Exception:
                ips = ["N/A"]
            mx_info.append({
                "host": host,
                "priority": priority,
                "ips": ips,
                "ptrs": ptrs
            })
    except Exception:
        pass
    return mx_info

async def lookup_txt(domain: str, keyword: str):
    """Find TXT records matching keyword"""
    results = []
    try:
        records = dns.resolver.resolve(domain, "TXT")
        for r in records:
            txt = r.to_text().strip('"')
            if keyword in txt:
                results.append(txt)
    except Exception:
        pass
    return results

async def lookup_soa(domain: str):
    """Get SOA record (if exists)"""
    try:
        soa = dns.resolver.resolve(domain, "SOA")[0]
        return {
            "mname": str(soa.mname),
            "rname": str(soa.rname),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum": soa.minimum,
        }
    except Exception:
        return None

async def lookup_a_records(domain: str):
    """Get A and AAAA records"""
    a, aaaa = [], []
    try:
        for r in dns.resolver.resolve(domain, "A"):
            a.append(r.to_text())
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(domain, "AAAA"):
            aaaa.append(r.to_text())
    except Exception:
        pass
    return {"A": a, "AAAA": aaaa}

async def gather_email_info(addr: str):
    """Gather all available info about the email"""
    info = {
        "valid": False,
        "email": addr,
        "error": None,
        "normalized": None,
        "mx": [],
        "spf": [],
        "dmarc": [],
        "a_records": {},
        "soa": None,
        "whois": None,
        "gravatar": None,
    }
    try:
        v = validate_email(addr, check_deliverability=False)
        normalized = v.normalized
        info["normalized"] = normalized
    except EmailNotValidError as e:
        info["error"] = str(e)
        return info

    domain = normalized.split("@")[1]

    info["mx"] = await lookup_mx(domain)
    info["spf"] = await lookup_txt(domain, "v=spf1")
    info["dmarc"] = await lookup_txt(f"_dmarc.{domain}", "v=DMARC1")
    info["a_records"] = await lookup_a_records(domain)
    info["soa"] = await lookup_soa(domain)

    if HAS_WHOIS:
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            expiration = w.expiration_date

            if isinstance(creation, (list, tuple)):
                creation = creation[0]
            if isinstance(expiration, (list, tuple)):
                expiration = expiration[0]
            info["whois"] = {
                "registrar": getattr(w, "registrar", None),
                "creation_date": creation,
                "expiration_date": expiration,
                "country": getattr(w, "country", None),
            }
        except Exception:
            info["whois"] = None

    info["gravatar"] = hashlib.md5(normalized.lower().encode()).hexdigest()
    info["valid"] = True if info["mx"] else False
    return info

def show_info(info: dict):
    """Display results in a nice formatted way"""
    console.rule("[bold purple]Corpoli Email Intelligence Result")

    if not info["valid"]:
        console.print("[INVALID]", style="bold red")
        console.print(f"Error: {info['error']}", style="red")
        return

    console.print("[VALID]", style="bold green")

    table = Table(title=f"Details for {info['normalized']}", style="bold white")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    table.add_row("Normalized", info["normalized"])

    if info["a_records"]["A"] or info["a_records"]["AAAA"]:
        a_val = "\n".join(info["a_records"]["A"]) if info["a_records"]["A"] else "None"
        aaaa_val = "\n".join(info["a_records"]["AAAA"]) if info["a_records"]["AAAA"] else "None"
        table.add_row("A Records", a_val)
        table.add_row("AAAA Records", aaaa_val)

    if info["mx"]:
        for mx in info["mx"]:
            val = f"{mx['host']} (prio {mx['priority']})\nIPs: {', '.join(mx['ips'])}\nPTRs: {', '.join(mx['ptrs'])}"
            table.add_row("MX", val)
    else:
        table.add_row("MX Records", "None")

    table.add_row("SPF", "\n".join(info["spf"]) if info["spf"] else "None")
    table.add_row("DMARC", "\n".join(info["dmarc"]) if info["dmarc"] else "None")
    table.add_row("Gravatar MD5", info["gravatar"])

    if info["soa"]:
        soa_val = f"MNAME: {info['soa']['mname']}\nRNAME: {info['soa']['rname']}\nSerial: {info['soa']['serial']}"
        table.add_row("SOA", soa_val)

    if info["whois"]:
        table.add_row("Registrar", str(info["whois"].get("registrar")))
        table.add_row("Created", str(info["whois"].get("creation_date")))
        table.add_row("Expires", str(info["whois"].get("expiration_date")))
        table.add_row("Country", str(info["whois"].get("country")))

    console.print(table)

    if HAS_CLIP:
        pyperclip.copy(info["normalized"])
        console.print("(Email copied to clipboard)", style="dim")

async def interactive_loop():
    while True:
        print_banner()
        try:
            inp = console.input(f"[bold red on magenta]{PROMPT}[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\nExiting...", style="bold white")
            break

        if inp.lower() in {"exit", "quit"}:
            break

        info = await gather_email_info(inp)
        show_info(info)

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    asyncio.run(interactive_loop())

