from __future__ import annotations
import sys, asyncio, time, hashlib, socket, json, csv, random, re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field


try:
    from email_validator import validate_email, EmailNotValidError
except Exception:
    validate_email = None
    EmailNotValidError = Exception

try:
    import dns.resolver, dns.reversename
except Exception:
    dns = None

try:
    import whois as pywhois
    HAS_WHOIS = True
except Exception:
    pywhois = None
    HAS_WHOIS = False

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except Exception:
    IPWhois = None
    HAS_IPWHOIS = False

try:
    import aiohttp
    from aiohttp import ClientTimeout, TCPConnector
except Exception:
    aiohttp = None
    ClientTimeout = None
    TCPConnector = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import pyperclip
    HAS_CLIP = True
except Exception:
    pyperclip = None
    HAS_CLIP = False


try:
    import spf as pyspf
    HAS_PYSPF = True
except Exception:
    pyspf = None
    HAS_PYSPF = False

try:
    import dkim as dkimpy  
    HAS_DKIMPY = True
except Exception:
    dkimpy = None
    HAS_DKIMPY = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

try:
    import smtplib, ssl
except Exception:
    smtplib = None
    ssl = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
except Exception:
    print("Install rich: pip install rich")
    raise

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

PROMPT = "[+]wiz#osint-> "


DEFAULT_UAS = [
    "Corpoli/2.0 (+https://example.local)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:114.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:113.0) Gecko/20100101 Firefox/113.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6; rv:112.0) Gecko/20100101 Firefox/112.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Safari/537.36 Edg/116.0.1938.76",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36 Edg/115.0.1901.183",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36 Edg/114.0.1823.79",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36 Edg/115.0.1901.188",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.126 Safari/537.36 Edg/113.0.1774.57",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:116.0) Gecko/116.0 Firefox/116.0",
    "Mozilla/5.0 (Linux; Android 12; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 9; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.126 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.64 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux i686; rv:114.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:113.0) Gecko/20100101 Firefox/113.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6; rv:112.0) Gecko/20100101 Firefox/112.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; Pixel 4a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.126 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_8_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:116.0) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1"
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "Yahoo! Slurp",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "YandexBot/3.0 (+http://yandex.com/bots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "PostmanRuntime/7.32.2",
    "Python-urllib/3.10",
    "Java/1.8.0_321",
    "Go-http-client/1.1",
    "PHP/8.1.10",
    "Mozilla/5.0 (Linux; Android 8.1.0; Nexus 5X Build/OPM6.171019.030) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.105 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 7.0; SM-G930F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.105 Mobile Safari/537.36",
]

USER_AGENTS_MASTER: List[str] = []
USER_AGENT_QUEUE: List[str] = []
UA_LOCK: Optional[asyncio.Lock] = None

CACHE: Dict[str, Any] = {}


DEFAULT_CONCURRENCY = 14
DEFAULT_DELAY = 0.06
DNS_TIMEOUT = 4.0
HTTP_TIMEOUT = 12.0
MX_CERT_TIMEOUT = 6.0
SMTP_TIMEOUT = 6.0

SITES = [
    ("GitHub", "https://github.com/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("Bitbucket", "https://bitbucket.org/{u}"),
    ("StackOverflow", "https://stackoverflow.com/users/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("Twitter/X", "https://x.com/{u}"),
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("Facebook (profile)", "https://www.facebook.com/{u}"),
    ("YouTube", "https://www.youtube.com/{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
    ("Medium", "https://medium.com/@{u}"),
    ("Dev.to", "https://dev.to/{u}"),
    ("Hacker News", "https://news.ycombinator.com/user?id={u}"),
    ("Tumblr", "https://{u}.tumblr.com/"),
    ("SoundCloud", "https://soundcloud.com/{u}"),
    ("Vimeo", "https://vimeo.com/{u}"),
    ("Flickr", "https://www.flickr.com/people/{u}/"),
    ("Imgur", "https://imgur.com/user/{u}"),
    ("Gravatar", "https://en.gravatar.com/{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
    ("Xbox", "https://account.xbox.com/en-us/profile?gamertag={u}"),
    ("PlayStation", "https://my.playstation.com/{u}"),
    ("Goodreads", "https://www.goodreads.com/{u}"),
    ("Patreon", "https://www.patreon.com/{u}"),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{u}"),
    ("Wikimedia", "https://meta.wikimedia.org/wiki/User:{u}"),
    ("Telegram", "https://t.me/{u}"),
    ("Pastebin", "https://pastebin.com/u/{u}"),
    ("Gitea", "https://try.gitea.io/{u}"),
    ("Keybase", "https://keybase.io/{u}"),
    ("npm", "https://www.npmjs.com/~{u}"),
    ("PyPI", "https://pypi.org/user/{u}/"),
    ("Crates", "https://crates.io/users/{u}"),
    ("Docker Hub", "https://hub.docker.com/u/{u}"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}"),
    ("Dribbble", "https://dribbble.com/{u}"),
    ("Behance", "https://www.behance.net/{u}"),
    ("Ello", "https://ello.co/{u}"),
    ("Codeberg", "https://codeberg.org/{u}"),
    ("Replit", "https://replit.com/@{u}"),
    ("Kaggle", "https://www.kaggle.com/{u}"),
    ("Codementor", "https://www.codementor.io/{u}"),
    ("Hugging Face", "https://huggingface.co/{u}"),
    ("Snapchat", "https://www.snapchat.com/add/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("Threads", "https://www.threads.net/@{u}"),
    ("Truth Social", "https://truthsocial.com/@{u}"),
    ("Gab", "https://gab.com/{u}"),
    ("Parler", "https://parler.com/{u}"),
    ("Mastodon (mastodon.social)", "https://mastodon.social/@{u}"),
    ("Blogger", "https://{u}.blogspot.com"),
    ("WordPress", "https://{u}.wordpress.com"),
    ("About.me", "https://about.me/{u}"),
    ("AngelList", "https://angel.co/u/{u}"),
    ("ProductHunt", "https://www.producthunt.com/@{u}"),
    ("Mix", "https://mix.com/{u}"),
    ("WeHeartIt", "https://weheartit.com/{u}"),
    ("500px", "https://500px.com/{u}"),
    ("Tripadvisor", "https://www.tripadvisor.com/members/{u}"),
    ("Last.fm", "https://www.last.fm/user/{u}"),
    ("Bandcamp", "https://bandcamp.com/{u}"),
    ("MyAnimeList", "https://myanimelist.net/profile/{u}"),
    ("Roblox", "https://www.roblox.com/user.aspx?username={u}"),
    ("Scratch", "https://scratch.mit.edu/users/{u}"),
    ("Chess.com", "https://www.chess.com/member/{u}"),
    ("Fandom (Wikia)", "https://www.fandom.com/u/{u}"),
    ("Quora", "https://www.quora.com/profile/{u}"),
    ("DeviantArt", "https://www.deviantart.com/{u}"),
    ("Gaia Online", "https://www.gaiaonline.com/profiles/{u}")
   
]

COMMON_NEGATIVE_KEYWORDS = [
    "not found", "404", "page not found", "profile not found", "no such user", "user not found", "couldn't find"
]


def print_banner():
    console.print(Panel(Text(ASCII_BANNER, style="bold magenta"), border_style="purple"))


def init_user_agents(uas: Optional[List[str]] = None):
    global USER_AGENTS_MASTER, USER_AGENT_QUEUE, UA_LOCK
    UA_LOCK = asyncio.Lock()
    if not uas or not isinstance(uas, list) or not any(uas):
        uas = list(DEFAULT_UAS)
    USER_AGENTS_MASTER = [u for u in uas if u]
    random.shuffle(USER_AGENTS_MASTER)
    USER_AGENT_QUEUE = USER_AGENTS_MASTER.copy()

async def next_user_agent() -> str:
    global USER_AGENT_QUEUE, UA_LOCK, USER_AGENTS_MASTER
    if UA_LOCK is None:
        UA_LOCK = asyncio.Lock()
    async with UA_LOCK:
        if not USER_AGENT_QUEUE:
            
            USER_AGENT_QUEUE = USER_AGENTS_MASTER.copy()
            random.shuffle(USER_AGENT_QUEUE)
        return USER_AGENT_QUEUE.pop()

def load_uas_from_file(path: str) -> List[str]:
    uas = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                s = ln.strip()
                if s:
                    uas.append(s)
    except Exception:
        pass
    return uas


def normalize_email(addr: str) -> Optional[str]:
    if not addr:
        return None
    addr = addr.strip()
    if validate_email:
        try:
            v = validate_email(addr, check_deliverability=False)
            return v.normalized
        except EmailNotValidError:
            return None
    return addr.lower()

def gravatar_hash(email: str) -> str:
    return hashlib.md5(email.lower().encode()).hexdigest()

def name_parts(name: str) -> Tuple[str,str]:
    parts = [p for p in re.split(r"\s+", name.strip()) if p]
    first = parts[0] if parts else ""
    last = parts[-1] if len(parts) > 1 else ""
    return first, last


async def dns_lookup(domain: str) -> Dict[str,Any]:
    key = f"dns:{domain}"
    if key in CACHE:
        return CACHE[key]
    out = {"A":[], "AAAA":[], "MX":[], "SPF":[], "DMARC":[], "SOA":None}
    if dns is None:
        CACHE[key] = out; return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        for r in resolver.resolve(domain, "A"):
            out["A"].append(r.to_text())
    except Exception:
        pass
    try:
        for r in resolver.resolve(domain, "AAAA"):
            out["AAAA"].append(r.to_text())
    except Exception:
        pass
    try:
        for r in resolver.resolve(domain, "MX"):
            out["MX"].append({"host": str(r.exchange).rstrip("."), "prio": r.preference})
    except Exception:
        pass
    try:
        for r in resolver.resolve(domain, "TXT"):
            txt = r.to_text().strip('"')
            if "v=spf1" in txt.lower():
                out["SPF"].append(txt)
    except Exception:
        pass
    try:
        for r in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = r.to_text().strip('"')
            if "v=DMARC1" in txt:
                out["DMARC"].append(txt)
    except Exception:
        pass
    try:
        s = resolver.resolve(domain, "SOA")[0]
        out["SOA"] = {"mname": str(s.mname), "rname": str(s.rname), "serial": s.serial}
    except Exception:
        pass
    CACHE[key] = out
    return out

def whois_lookup(domain: str) -> Optional[Dict[str,Any]]:
    key = f"whois:{domain}"
    if key in CACHE:
        return CACHE[key]
    if not HAS_WHOIS:
        CACHE[key] = None; return None
    try:
        w = pywhois.whois(domain)
        registrar = getattr(w, "registrar", None)
        creation = getattr(w, "creation_date", None)
        expiration = getattr(w, "expiration_date", None)
        if isinstance(creation, (list,tuple)):
            creation = creation[0]
        if isinstance(expiration, (list,tuple)):
            expiration = expiration[0]
        res = {"registrar": registrar, "creation": str(creation), "expiration": str(expiration)}
        CACHE[key] = res
        return res
    except Exception:
        CACHE[key] = None
        return None

def fetch_mx_cert(host: str, port:int=25, timeout:float=MX_CERT_TIMEOUT) -> Optional[Dict[str,Any]]:
    """Try to STARTTLS to obtain server cert (best-effort, may be blocked)."""
    key = f"mxcert:{host}:{port}"
    if key in CACHE:
        return CACHE[key]
    if not HAS_CRYPTO:
        CACHE[key] = None; return None
    try:
        
        ctx = ssl.create_default_context()
       
        cert = None
        for p in (465, 25):
            try:
                with socket.create_connection((host, p), timeout=timeout) as sock:
                    if p == 465:
                        ss = ctx.wrap_socket(sock, server_hostname=host)
                        der = ss.getpeercert(True)
                    else:
                        
                        if smtplib is None:
                            continue
                        smtp = smtplib.SMTP(host, 25, timeout=timeout)
                        smtp.ehlo()
                        if smtp.has_extn('STARTTLS'):
                            smtp.starttls(context=ctx)
                            
                            socketobj = smtp.sock
                            
                            der = socketobj.getpeercert(True)
                            smtp.quit()
                        else:
                            smtp.quit()
                            continue
                    cert = x509.load_der_x509_certificate(der, backend=default_backend())
                    break
            except Exception:
                continue
        if not cert:
            CACHE[key] = None; return None
        sans = []
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []
        issuer = cert.issuer.rfc4514_string()
        fp = cert.fingerprint(hashes.SHA256()).hex()
        rec = {"issuer": issuer, "sans": sans, "not_before": str(cert.not_valid_before), "not_after": str(cert.not_valid_after), "fingerprint": fp}
        CACHE[key] = rec
        return rec
    except Exception:
        CACHE[key] = None
        return None

def dkim_discovery(domain: str) -> List[Tuple[str,str]]:
    """Try common DKIM selectors and return TXT if found: (selector, record)"""
    if dns is None:
        return []
    selectors = ["default", "google", "selector1", "s1024", "s1", "mail", "smtp"]
    found = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        try:
            for r in dns.resolver.resolve(name, "TXT"):
                txt = r.to_text().strip('"')
                if "p=" in txt:
                    found.append((sel, txt))
        except Exception:
            continue
    return found

def spf_evaluate(domain: str) -> Optional[str]:
    """Parse SPF record using pyspf if available."""
    if not HAS_PYSPF:
        return None
    try:
       
        res = None
        if dns:
            try:
                for r in dns.resolver.resolve(domain, "TXT"):
                    txt = r.to_text().strip('"')
                    if "v=spf1" in txt.lower():
                        res = txt
                        break
            except Exception:
                pass
        return res
    except Exception:
        return None


def gen_username_variants(name: str, max_variants:int=12) -> List[str]:
    first, last = name_parts(name)
    variants = []
    if first and last:
        variants += [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{first}-{last}",
            f"{last}{first}",
            f"{last}.{first}",
            f"{first}",
            f"{last}"
        ]
    elif first:
        variants += [first, first + "1", first + "_"]
    variants = [v.lower() for v in dict.fromkeys(variants)]
    return variants[:max_variants]


async def fetch_profile(session: "aiohttp.ClientSession", site: str, url: str, username: str, timeout:float=HTTP_TIMEOUT) -> Dict[str,Any]:
    out = {"site": site, "url": url, "username": username, "status": None, "exists": False, "title": None, "avatar": None, "notes": "", "ua": None}
    if aiohttp is None:
        out["notes"] = "aiohttp missing"
        return out
    ua = await next_user_agent()
    out["ua"] = ua
    headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    try:
        async with session.get(url, headers=headers, allow_redirects=True) as resp:
            out["status"] = resp.status
            text = await resp.text(errors="ignore")
            low = (text or "").lower()
            if resp.status == 200:
                if any(k in low for k in COMMON_NEGATIVE_KEYWORDS):
                    out["exists"] = False
                    out["notes"] = "page contains negative keywords"
                else:
                    out["exists"] = True
                    out["notes"] = "200 OK"
            elif resp.status in (301,302):
                final = str(resp.url)
                if username.lower() in final.lower():
                    out["exists"] = True
                    out["notes"] = f"redirects->{final}"
                else:
                    out["exists"] = False
                    out["notes"] = f"redirects->{final}"
            elif resp.status == 404:
                out["exists"] = False
                out["notes"] = "404"
            else:
                out["exists"] = False
                out["notes"] = f"HTTP {resp.status}"
            if text and BeautifulSoup:
                try:
                    soup = BeautifulSoup(text, "html.parser")
                    if soup.title and soup.title.string:
                        out["title"] = soup.title.string.strip()
                    img = soup.find("meta", property="og:image") or soup.find("meta", attrs={"name":"twitter:image"})
                    if img and img.get("content"):
                        out["avatar"] = img.get("content")
                    
                    for tag in soup.find_all(["h1","h2","h3","p","span"], limit=8):
                        if tag and tag.get_text() and username.lower() in tag.get_text().lower():
                            out["notes"] += "; username appears"
                            break
                except Exception:
                    pass
    except asyncio.TimeoutError:
        out["notes"] = "timeout"
    except Exception as e:
        out["notes"] = f"err:{e}"
    return out

async def bulk_username_scan(usernames: List[str], concurrency:int=DEFAULT_CONCURRENCY, delay:float=DEFAULT_DELAY) -> List[Dict[str,Any]]:
    if aiohttp is None:
        return []
    connector = TCPConnector(limit_per_host=6, ssl=False)
    timeout = ClientTimeout(total=HTTP_TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        sem = asyncio.Semaphore(concurrency)
        tasks = []
        
        ua_cycle = USER_AGENTS_MASTER.copy() or DEFAULT_UAS
        if not ua_cycle:
            ua_cycle = DEFAULT_UAS
        random.shuffle(ua_cycle)
        ua_len = len(ua_cycle)
        i = 0
        for uname in usernames:
            for site, pattern in SITES:
                url = pattern.format(u=socket.getfqdn(uname)) if "{u}" not in pattern else pattern.format(u=urllib_quote(uname))
                ua = ua_cycle[i % ua_len]
                i += 1
                async def bound_fetch(site=site, url=url, uname=uname, ua=ua):
                    async with sem:
                        await asyncio.sleep(delay)
                        res = await fetch_profile(session, site, url, uname)
                        res['ua'] = ua
                        return res
                tasks.append(asyncio.create_task(bound_fetch()))
        results = await asyncio.gather(*tasks, return_exceptions=False)
    return results


def urllib_quote(s: str) -> str:
    try:
        import urllib.parse as up
        return up.quote(s, safe="-._~@")
    except Exception:
        return s


def smtp_check_rcpt(mx_host: str, from_addr: str, rcpt_addr: str, timeout:float=SMTP_TIMEOUT) -> Tuple[bool,str]:
    """Synchronous SMTP RCPT check. WARNING: option must be explicitly enabled."""
    if smtplib is None:
        return False, "smtplib not available"
    try:
        s = smtplib.SMTP(mx_host, 25, timeout=timeout)
        s.ehlo()
        if s.has_extn('STARTTLS'):
            ctx = ssl.create_default_context()
            s.starttls(context=ctx)
            s.ehlo()
        
        code, resp = s.mail(from_addr)
        code2, resp2 = s.rcpt(rcpt_addr)
        s.quit()
        accepted = 200 <= code2 < 400
        return accepted, f"{code2} {resp2}"
    except Exception as e:
        return False, f"err:{e}"


@dataclass
class Candidate:
    url: str
    site: str
    title: Optional[str] = None
    avatar: Optional[str] = None
    notes: str = ""
    score: float = 0.0
    meta: Dict[str,Any] = field(default_factory=dict)

def score_candidate(res: Dict[str,Any], query: Dict[str,Any]) -> float:
    score = 0.0
    username = (query.get("username") or "").lower()
    name = (query.get("name") or "").lower()
    url = (res.get("url") or "").lower()
    if username and username in url:
        score += 30
    if res.get("avatar"):
        score += 5
    if res.get("notes") and "username appears" in res.get("notes").lower():
        score += 10
    title = (res.get("title") or "").lower()
    if name and any(p in title for p in name.split()):
        score += 20
    
    site = (res.get("site") or "").lower()
    if any(k in site for k in ("github","linkedin","twitter","x","instagram")):
        score += 6
    return score

def aggregate_results(results: List[Dict[str,Any]], query: Dict[str,Any]) -> List[Candidate]:
    grouped: Dict[str, Candidate] = {}
    for r in results:
        url = r.get("url") or r.get("site") or str(hash(str(r)))
        c = Candidate(url=url, site=r.get("site") or "", title=r.get("title"), avatar=r.get("avatar"), notes=r.get("notes",""), score=score_candidate(r, query), meta=r)
        if url in grouped:
            grouped[url].score += c.score
            if c.notes and c.notes not in grouped[url].notes:
                grouped[url].notes += "; " + c.notes
        else:
            grouped[url] = c
    candidates = sorted(grouped.values(), key=lambda x: x.score, reverse=True)
    return candidates


def present_quick_facts(email_info: Optional[Dict[str,Any]], dns_info: Optional[Dict[str,Any]], ip_info: Optional[Dict[str,Any]]):
    print_banner()
    console.print("[bold white]Quick Facts[/]\n")
    t = Table(show_header=False)
    if email_info:
        t.add_row("Email (normalized)", email_info.get("normalized","-"))
        t.add_row("Gravatar MD5", email_info.get("gravatar","-"))
        t.add_row("Domain", email_info.get("domain","-"))
        if email_info.get("whois"):
            t.add_row("Domain registrar", str(email_info["whois"].get("registrar")))
    if dns_info:
        t.add_row("A records", ", ".join(dns_info.get("A") or []) or "-")
        t.add_row("MX hosts", ", ".join([m['host'] for m in (dns_info.get("MX") or [])]) or "-")
        t.add_row("SPF", "; ".join(dns_info.get("SPF") or []) or "-")
        t.add_row("DMARC", "; ".join(dns_info.get("DMARC") or []) or "-")
    if ip_info:
        t.add_row("IP", ip_info.get("ip"))
        t.add_row("rDNS", ip_info.get("rDNS") or "-")
        t.add_row("ASN", ip_info.get("asn") or "-")
    console.print(t)

def present_candidates(cands: List[Candidate], top_n:int=8):
    console.print("\n[bold white]Top candidate matches[/]\n")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Score", style="bold green", no_wrap=True)
    table.add_column("Site", style="cyan")
    table.add_column("Title/Name", style="green")
    table.add_column("URL", style="blue", overflow="fold")
    table.add_column("Notes", style="dim")
    for c in cands[:top_n]:
        table.add_row(str(int(c.score)), c.site, c.title or "", c.url, c.notes or "")
    console.print(table)
    if cands and HAS_CLIP:
        try:
            pyperclip.copy(cands[0].url)
            console.print("(Top candidate copied to clipboard)", style="dim")
        except Exception:
            pass

def export_results_json(path: str, obj: Any):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        console.print(f"Exported JSON to {path}", style="dim")
    except Exception as e:
        console.print(f"Failed to write JSON: {e}", style="red")

def export_results_csv(path: str, rows: List[Dict[str,Any]]):
    try:
        keys = set()
        for r in rows:
            keys.update(r.keys())
        keys = list(keys)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: str(r.get(k,"")) for k in keys})
        console.print(f"Exported CSV to {path}", style="dim")
    except Exception as e:
        console.print(f"Failed to write CSV: {e}", style="red")


async def perform_osint(query: Dict[str,Any], ua_file:Optional[str]=None, do_username_variants:bool=True, smtp_check:bool=False, concurrency:int=DEFAULT_CONCURRENCY, delay:float=DEFAULT_DELAY, export_json:Optional[str]=None, export_csv:Optional[str]=None):
    
    uas = DEFAULT_UAS.copy()
    if ua_file:
        uas_file = load_uas_safe(ua_file)
        if uas_file:
            uas = uas_file
    init_user_agents(uas)

    
    email_info = None
    dns_info = None
    ip_info = None
    username_results_all = []

    
    if query.get("email"):
        norm = normalize_email(query["email"])
        if norm:
            email_info = {"normalized": norm, "gravatar": gravatar_hash(norm), "domain": norm.split("@",1)[1]}
            dns_info = await dns_lookup(email_info["domain"])
            email_info["dns"] = dns_info
            email_info["whois"] = whois_lookup(email_info["domain"])
            
            email_info["dkim"] = dkim_discovery(email_info["domain"])
            email_info["spf_parsed"] = spf_evaluate(email_info["domain"])
            
            mx_certs = []
            for mx in dns_info.get("MX") or []:
                cert = fetch_mx_cert(mx['host'])
                if cert:
                    mx_certs.append({ "host": mx['host'], "cert": cert })
            email_info["mx_certs"] = mx_certs

    
    if query.get("ip"):
        ip = query["ip"]
        r = None
        try:
            r = socket.gethostbyaddr(ip)[0]
        except Exception:
            r = None
        ipwho = {}
        if HAS_IPWHOIS and IPWhois:
            try:
                obj = IPWhois(ip)
                rd = obj.lookup_rdap(depth=1)
                ipwho = {"asn": rd.get("asn"), "asn_country": rd.get("asn_country_code"), "network_name": rd.get("network",{}).get("name")}
            except Exception:
                ipwho = {}
        ip_info = {"ip": ip, "rDNS": r, "whois": ipwho}

    
    username_to_scan = query.get("username")
    if not username_to_scan and query.get("name") and do_username_variants:
       
        username_to_scan = gen_username_variants(query["name"], max_variants=6)[0] if gen_username_variants(query["name"]) else None

    if username_to_scan and aiohttp:
        
        primary_results = await bulk_username_scan([username_to_scan], concurrency=concurrency, delay=delay)
        username_results_all.extend(primary_results)
        
        if do_username_variants and query.get("name"):
            variants = gen_username_variants(query["name"], max_variants=6)
            
            variants = [v for v in variants if v != username_to_scan]
            for v in variants:
                res = await bulk_username_scan([v], concurrency=max(4, concurrency//2), delay=delay)
                username_results_all.extend(res)

    
    smtp_results = []
    if smtp_check:
        console.print("[bold yellow]WARNING:[/] SMTP RCPT checks are enabled. Only use for accounts/domains you own or are authorized to test.", style="yellow")
        confirm = console.input("Type 'I UNDERSTAND' to proceed: ").strip()
        if confirm == "I UNDERSTAND":
            if email_info and dns_info and dns_info.get("MX"):
                for mx in dns_info["MX"]:
                    ok, info = smtp_check_rcpt(mx['host'], "noreply@corpoli.local", email_info["normalized"])
                    smtp_results.append({"mx": mx['host'], "accepted": ok, "info": info})
                    await asyncio.sleep(0.5)
        else:
            console.print("SMTP checks skipped (no confirmation).", style="yellow")

    
    flat_results = []
    
    flat_results.extend(username_results_all)
    
    if email_info:
        grav_url = f"https://www.gravatar.com/avatar/{email_info['gravatar']}"
        flat_results.append({"site":"Gravatar","url":grav_url,"title":email_info.get("normalized"), "avatar":grav_url, "notes":"gravatar", "exists":True})
        for mx in (dns_info.get("MX") or []):
            flat_results.append({"site":"MailHost","url":f"https://{mx['host']}", "title": mx['host'], "notes": f"mx prio {mx['prio']}", "exists": True})
    
    if ip_info:
        flat_results.append({"site":"IP", "url": f"ip://{ip_info['ip']}", "title": ip_info['ip'], "notes": ip_info.get("rDNS") or "", "exists": True})

    
    candidates = aggregate_results(flat_results, query)

    
    present_quick_facts(email_info, dns_info, ip_info)
    present_candidates(candidates, top_n=10)

    
    if export_json:
        export_results_json(export_json, {"query": query, "email_info": email_info, "ip_info": ip_info, "candidates": [c.__dict__ for c in candidates]})
    if export_csv:
        export_results_csv(export_csv, flat_results + (smtp_results if smtp_results else []))


    console.print("\nType 'raw' to view raw JSON, or press Enter to return.", style="dim")
    try:
        if console.input(f"[bold red on magenta]{PROMPT}[/] ").strip().lower() == "raw":
            outdump = {"query": query, "email_info": email_info, "dns_info": dns_info, "ip_info": ip_info, "candidates": [c.__dict__ for c in candidates]}
            console.print_json(json.dumps(outdump))
    except (KeyboardInterrupt, EOFError):
        pass


def load_uas_safe(path: str) -> List[str]:
    try:
        return load_uas(path)
    except Exception:
        return []

def load_uas(path: str) -> List[str]:
    arr=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as fh:
        for ln in fh:
            s = ln.strip()
            if s:
                arr.append(s)
    return arr


def ask_interactive() -> Dict[str,Any]:
    print_banner()
    console.print("Enter any fields (press Enter to skip):", style="bold white")
    try:
        name = console.input("Name: ").strip()
        email = console.input("Email: ").strip()
        username = console.input("Username: ").strip()
        age = console.input("Age: ").strip()
        country = console.input("Country: ").strip()
        ip = console.input("IP: ").strip()
    except (KeyboardInterrupt, EOFError):
        console.print("\nInterrupted", style="bold white"); sys.exit(0)
    q={}
    if name: q["name"]=name
    if email: q["email"]=email
    if username: q["username"]=username
    if age: q["age"]=age
    if country: q["country"]=country
    if ip: q["ip"]=ip
    return q

def parse_args():
    import argparse
    p=argparse.ArgumentParser(prog="corpoli-ultimate-osint-v2")
    p.add_argument("--name", type=str)
    p.add_argument("--email", type=str)
    p.add_argument("--username", type=str)
    p.add_argument("--ip", type=str)
    p.add_argument("--ua-file", type=str, help="file with User-Agents, one per line")
    p.add_argument("--no-variants", action="store_true", help="disable username permutations")
    p.add_argument("--smtp-check", action="store_true", help="enable SMTP RCPT checks (explicit confirmation required; dangerous)")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    p.add_argument("--export-json", type=str, help="export results to JSON")
    p.add_argument("--export-csv", type=str, help="export flat results to CSV")
    return p.parse_args()

def main():
    args = parse_args()
    query={}
    if any([args.name, args.email, args.username, args.ip]):
        if args.name: query["name"]=args.name
        if args.email: query["email"]=args.email
        if args.username: query["username"]=args.username
        if args.ip: query["ip"]=args.ip
    else:
        query = ask_interactive()

    uas = None
    if args.ua_file:
        uas = load_uas_safe(args.ua_file)
    try:
        asyncio.run(perform_osint(query, ua_file=args.ua_file, do_username_variants=not args.no_variants, smtp_check=args.smtp_check, concurrency=args.concurrency, delay=args.delay, export_json=args.export_json, export_csv=args.export_csv))
    except KeyboardInterrupt:
        console.print("\nInterrupted", style="bold white")

if __name__ == "__main__":
    main()

