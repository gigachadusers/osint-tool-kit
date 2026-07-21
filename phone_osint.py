from __future__ import annotations
import sys, argparse, hashlib, json, asyncio, random, socket, re, csv, time
from typing import Optional, List, Dict, Any, Tuple


try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as tzmod, NumberParseException, PhoneMetadata
except Exception:
    print("Missing 'phonenumbers'. Install: pip install phonenumbers")
    raise

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
except Exception:
    print("Missing 'rich'. Install: pip install rich")
    raise


try:
    import aiohttp
    from aiohttp import ClientTimeout, TCPConnector
    from bs4 import BeautifulSoup
    HAS_WEB = True
except Exception:
    aiohttp = None
    ClientTimeout = None
    TCPConnector = None
    BeautifulSoup = None
    HAS_WEB = False


try:
    import pyperclip
    HAS_CLIP = True
except Exception:
    pyperclip = None
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
PROMPT = "[+]wiz#PHONE-> "


DEFAULT_UAS = [
    "CorpoliPhoneRecon/1.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]


WEB_CHECK_SITES = [
    ("Google (search)", "https://www.google.com/search?q={q}"),
    ("Bing (search)", "https://www.bing.com/search?q={q}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("Truecaller (web)", "https://www.truecaller.com/search/{q}"),
    ("Sync.Me", "https://sync.me/search/{q}"),
    ("WhoCallsMe", "https://whocallsme.com/Phone-Report/{q}"),
    ("NumLookup", "https://www.numlookup.com/search?query={q}"),
    ("Telegram (search)", "https://t.me/s/{q}"),
    ("Twitter/X search", "https://x.com/search?q={q}"),
    ("Facebook search", "https://www.facebook.com/search/top/?q={q}"),
    ("Reddit search", "https://www.reddit.com/search/?q={q}"),
]


USER_AGENTS_MASTER: List[str] = []
USER_AGENT_QUEUE: List[str] = []
UA_LOCK = None

def init_ua_pool(uas: Optional[List[str]] = None):
    global USER_AGENTS_MASTER, USER_AGENT_QUEUE, UA_LOCK
    if not uas:
        uas = list(DEFAULT_UAS)
    USER_AGENTS_MASTER = [u for u in uas if u]
    random.shuffle(USER_AGENTS_MASTER)
    USER_AGENT_QUEUE = USER_AGENTS_MASTER.copy()
    UA_LOCK = asyncio.Lock()

async def next_ua() -> str:
    global USER_AGENT_QUEUE, USER_AGENT_MASTER, UA_LOCK
    if UA_LOCK is None:
        UA_LOCK = asyncio.Lock()
    async with UA_LOCK:
        if not USER_AGENT_QUEUE:
            USER_AGENT_QUEUE = USER_AGENTS_MASTER.copy()
            random.shuffle(USER_AGENT_QUEUE)
        return USER_AGENT_QUEUE.pop()


def print_banner():
    banner = Text(ASCII_BANNER, style="bold magenta")
    console.print(Panel(banner, border_style="purple"))

def mask_number(e164: str) -> str:
    if not e164:
        return ""
    sign = "+" if e164.startswith("+") else ""
    body = e164.lstrip("+")
    if len(body) <= 4:
        return sign + "X" * len(body)
    return sign + "X" * (len(body)-4) + body[-4:]

def hashes_of(s: str) -> Dict[str,str]:
    return {"md5": hashlib.md5(s.encode()).hexdigest(), "sha1": hashlib.sha1(s.encode()).hexdigest()}


def analyze_number(raw: str, default_region: Optional[str] = None) -> Dict[str,Any]:
    out: Dict[str,Any] = {"input": raw, "valid": False}
    try:
        raw_clean = raw.strip()
        if default_region:
            num = phonenumbers.parse(raw_clean, default_region.upper())
        else:
            num = phonenumbers.parse(raw_clean, None)
        out["valid"] = phonenumbers.is_valid_number(num)
        out["possible"] = phonenumbers.is_possible_number(num)
        out["e164"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        out["international"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        out["national"] = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
        out["region_code"] = phonenumbers.region_code_for_number(num)
        out["country_code"] = num.country_code
        
        nsn = phonenumbers.national_significant_number(num)
        out["nsn"] = nsn
        
        try:
            m = phonenumbers.PhoneMetadata.metadata_for_region(out["region_code"])
            
            out["possible_lengths"] = m.general_desc.national_number_pattern if m and m.general_desc else None
        except Exception:
            out["possible_lengths"] = None
       
        ntype = phonenumbers.number_type(num)
        out["type"] = str(ntype)
        try:
            out["carrier"] = carrier.name_for_number(num, "en")
        except Exception:
            out["carrier"] = None
        
        try:
            out["geocoded"] = geocoder.description_for_number(num, "en")
        except Exception:
            out["geocoded"] = None
        try:
            out["timezones"] = tzmod.time_zones_for_number(num)
        except Exception:
            out["timezones"] = []
        
        try:
            
            ndc = phonenumbers.length_of_geographical_area_code(num)
            out["ndc_length"] = ndc
            if ndc and ndc > 0:
                out["ndc"] = nsn[:ndc]
                out["subscriber_number"] = nsn[ndc:]
            else:
                out["ndc"] = None
                out["subscriber_number"] = nsn
        except Exception:
            out["ndc_length"] = None
            out["ndc"] = None
            out["subscriber_number"] = nsn
        
        out["masked"] = mask_number(out.get("e164") or raw_clean)
        out["hashes"] = hashes_of(out.get("e164") or raw_clean)
        
        q = out.get("e164") or raw_clean
        q_safe = re.sub(r"^\+", "%2B", q) 
        out["query"] = q_safe
    except NumberParseException as e:
        out["error"] = str(e)
    except Exception as e:
        out["error"] = str(e)
    return out

def build_search_urls(q: str) -> List[Dict[str,str]]:
    urls = []
    for name, pattern in WEB_CHECK_SITES:
        try:
            urls.append({"name": name, "url": pattern.format(q=q)})
        except Exception:
            continue
    return urls


async def fetch_site(session: "aiohttp.ClientSession", site_name: str, url: str, q: str, timeout: float=10.0) -> Dict[str,Any]:
    res = {"site": site_name, "url": url, "status": None, "found": False, "snippet": None, "ua": None}
    if aiohttp is None:
        res["status"] = "aiohttp-missing"
        return res
    ua = await next_ua()
    res["ua"] = ua
    headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    try:
        async with session.get(url, headers=headers, allow_redirects=True, timeout=ClientTimeout(total=timeout)) as r:
            res["status"] = r.status
            text = await r.text(errors="ignore")
            low = (text or "").lower()
            if q.lower().replace("%2b","+").replace("%2B","+") in low or q.replace("%2B","+").replace("%2b","+") in low:
                res["found"] = True
                
                idx = low.find(q.lower().replace("%2b","+").replace("%2B","+"))
                start = max(0, idx-80)
                res["snippet"] = (text[start:start+200].strip().replace("\n"," "))
            
            if BeautifulSoup:
                try:
                    soup = BeautifulSoup(text, "html.parser")
                    if soup.title and soup.title.string:
                        res["title"] = soup.title.string.strip()
                except Exception:
                    pass
    except Exception as e:
        res["status"] = f"err:{e}"
    return res

async def perform_web_checks(query: str, concurrency: int = 6, delay: float = 0.2, ua_file: Optional[str] = None) -> List[Dict[str,Any]]:
    if not HAS_WEB:
        return []
    
    uas = None
    if ua_file:
        try:
            with open(ua_file, "r", encoding="utf-8", errors="ignore") as fh:
                uas = [ln.strip() for ln in fh if ln.strip()]
        except Exception:
            uas = None
    init_ua_pool(uas)
    connector = TCPConnector(limit_per_host=5, ssl=False)
    timeout = ClientTimeout(total=12)
    tasks = []
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for name, pattern in WEB_CHECK_SITES:
            url = pattern.format(q=query)
            async def bound(name=name, url=url):
                async with sem:
                    await asyncio.sleep(delay)
                    return await fetch_site(session, name, url, query)
            tasks.append(asyncio.create_task(bound()))
        results = await asyncio.gather(*tasks, return_exceptions=False)
    return results


def present_full(out: Dict[str,Any], web_results: Optional[List[Dict[str,Any]]] = None):
    print_banner()
    console.print("[bold white]Corpoli Phone Recon — Advanced[/]\n")
    t = Table(show_header=False)
    t.add_row("Input", out.get("input") or "-")
    t.add_row("Valid", "[green]YES[/]" if out.get("valid") else "[red]NO[/]")
    t.add_row("E.164", out.get("e164") or "-")
    t.add_row("International", out.get("international") or "-")
    t.add_row("National", out.get("national") or "-")
    t.add_row("Region code", str(out.get("region_code") or "-"))
    t.add_row("Country code", str(out.get("country_code") or "-"))
    t.add_row("Geocoded", str(out.get("geocoded") or "-"))
    t.add_row("Type", str(out.get("type") or "-"))
    t.add_row("Carrier", str(out.get("carrier") or "-"))
    t.add_row("ND C", str(out.get("ndc") or "-"))
    t.add_row("Subscriber", str(out.get("subscriber_number") or "-"))
    t.add_row("Possible", str(out.get("possible")))
    t.add_row("Timezones", ", ".join(out.get("timezones") or []) or "-")
    t.add_row("Masked", out.get("masked") or "-")
    t.add_row("MD5", out.get("hashes", {}).get("md5") or "-")
    t.add_row("SHA1", out.get("hashes", {}).get("sha1") or "-")
    console.print(Panel(t, title="[bold magenta]Corpoli Phone Facts", border_style="purple"))

    console.print("\n[bold white]Search / OSINT Links (open in browser)[/]")
    url_table = Table(show_header=True, header_style="bold magenta")
    url_table.add_column("Site", style="cyan", no_wrap=True)
    url_table.add_column("URL", style="blue", overflow="fold")
    for u in build_search_urls(out.get("query") or ""):
        url_table.add_row(u["name"], u["url"])
    console.print(url_table)

    if HAS_CLIP and out.get("e164"):
        try:
            pyperclip.copy(out.get("e164"))
            console.print("(Normalized number copied to clipboard)", style="dim")
        except Exception:
            pass

    if web_results is not None:
        console.print("\n[bold white]Optional Web Checks (quick summary)[/]")
        wtab = Table(show_header=True, header_style="bold magenta")
        wtab.add_column("Site", style="cyan", no_wrap=True)
        wtab.add_column("Status", style="white", no_wrap=True)
        wtab.add_column("Found", style="green")
        wtab.add_column("Snippet / Title", style="dim")
        for r in web_results:
            found = "[green]YES[/]" if r.get("found") else "[red]NO[/]"
            snippet = (r.get("snippet") or r.get("title") or "")[:120]
            wtab.add_row(r.get("site") or "-", str(r.get("status") or "-"), found, snippet)
        console.print(wtab)

    console.print("\n[bold yellow]Limitations[/]: The tool cannot retrieve SIM/IMSI, call logs, SMS contents, or operator-controlled subscriber records.without entering the proper api keys ", style="yellow")


def parse_cli():
    p = argparse.ArgumentParser(description="Corpoli Phone Recon Plus")
    p.add_argument("--number", "-n", help="Phone number to analyze (E.164 or national)")
    p.add_argument("--region", "-r", help="Default region (2-letter, e.g. US, GB)", default=None)
    p.add_argument("--web-check", action="store_true", help="Perform optional web checks against public pages (polite, opt-in)")
    p.add_argument("--concurrency", type=int, default=6, help="Concurrency for web checks")
    p.add_argument("--delay", type=float, default=0.25, help="Delay between web requests (s)")
    p.add_argument("--ua-file", type=str, help="Optional UA file (one per line) for rotation")
    p.add_argument("--export-json", type=str, help="Save JSON output to file")
    p.add_argument("--export-csv", type=str, help="Save flat CSV of web results")
    return p.parse_args()


def main():
    args = parse_cli()
    if args.number:
        num = args.number
    else:
        print_banner()
        try:
            num = console.input(f"[bold red on magenta]{PROMPT}[/] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\nExiting...", style="bold white"); return

    out = analyze_number(num, default_region=args.region)
    web_results = None
    if args.web_check:
        if not HAS_WEB:
            console.print("[bold red]aiohttp/bs4 not installed — cannot perform web checks[/]", style="red")
        else:
            
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                ua_file = args.ua_file
                web_results = loop.run_until_complete(perform_web_checks(out.get("query") or "", concurrency=args.concurrency, delay=args.delay, ua_file=ua_file))
            except Exception as e:
                console.print(f"[red]Web checks failed: {e}[/]")

    present_full(out, web_results)

    
    if args.export_json:
        try:
            with open(args.export_json, "w", encoding="utf-8") as fh:
                json.dump({"analysis": out, "web": web_results}, fh, indent=2)
            console.print(f"Saved JSON to {args.export_json}", style="dim")
        except Exception as e:
            console.print(f"Failed to export JSON: {e}", style="red")
    if args.export_csv and web_results:
        try:
            keys = set()
            for r in web_results:
                keys.update(r.keys())
            keys = list(keys)
            with open(args.export_csv, "w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=keys)
                writer.writeheader()
                for r in web_results:
                    writer.writerow({k: str(r.get(k,"")) for k in keys})
            console.print(f"Saved CSV to {args.export_csv}", style="dim")
        except Exception as e:
            console.print(f"Failed to export CSV: {e}", style="red")

    console.print("\nPress Enter to continue...", style="dim")
    try:
        console.input()
    except Exception:
        pass

if __name__ == "__main__":
    main()

