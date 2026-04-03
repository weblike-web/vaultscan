"""
VaultScan Backend v1.1 — FastAPI + NVIDIA NIM AI
"""
import asyncio, json, os, re, time, ssl, socket, hashlib, logging
from collections import defaultdict
from datetime import datetime
from typing import List
from urllib.parse import urlparse

import dns.resolver
import httpx
import whois
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="VaultScan API", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

_rate_store: dict = defaultdict(list)
def is_rate_limited(ip: str) -> bool:
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < 60]
    if len(_rate_store[ip]) >= 10: return True
    _rate_store[ip].append(now); return False

_scan_cache: dict = {}
def get_cached(url):
    key = hashlib.md5(url.encode()).hexdigest()
    if key in _scan_cache:
        data, ts = _scan_cache[key]
        if time.time() - ts < 3600: return data
    return None
def set_cache(url, data):
    _scan_cache[hashlib.md5(url.encode()).hexdigest()] = (data, time.time())

BLOCKED_HOSTS = {"localhost","127.0.0.1","0.0.0.0","169.254.169.254"}
def is_safe_url(url):
    try:
        p = urlparse(url)
        if p.scheme not in ("http","https"): return False
        h = (p.hostname or "").lower()
        if not h or h in BLOCKED_HOSTS: return False
        if h.startswith(("192.168.","10.","172.16.")): return False
        return True
    except: return False

class ScanRequest(BaseModel):
    url: str
class ReviewRequest(BaseModel):
    name: str; role: str; stars: int; comment: str

_reviews: List[dict] = []

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://","https://")): url = "https://" + url
    return url
def extract_domain(url): return urlparse(url).netloc or url

async def analyze_dns(domain):
    result = {"a_records":[],"mx_records":[],"ns_records":[],"spf":None,"dmarc":None,"dnssec":False,"issues":[],"info":[]}
    r = dns.resolver.Resolver(); r.timeout = 5; r.lifetime = 5
    try:
        ans = r.resolve(domain,"A"); result["a_records"] = [str(x) for x in ans]
        result["info"].append(f"Resolves to: {', '.join(result['a_records'][:3])}")
    except Exception as e:
        logger.warning(f"DNS A failed {domain}: {e}"); result["issues"].append("Domain does not resolve")
    try: ans = r.resolve(domain,"MX"); result["mx_records"] = [str(x.exchange) for x in ans]
    except: pass
    try: ans = r.resolve(domain,"NS"); result["ns_records"] = [str(x) for x in ans]
    except: pass
    try:
        ans = r.resolve(domain,"TXT")
        for rd in ans:
            t = str(rd).strip('"')
            if t.startswith("v=spf1"): result["spf"] = t
        if not result["spf"]: result["issues"].append("Missing SPF record — email spoofing possible")
    except Exception as e:
        logger.warning(f"TXT failed {domain}: {e}"); result["issues"].append("Could not retrieve TXT records")
    try:
        ans = r.resolve(f"_dmarc.{domain}","TXT")
        for rd in ans:
            t = str(rd).strip('"')
            if t.startswith("v=DMARC1"): result["dmarc"] = t
        if not result["dmarc"]: result["issues"].append("Missing DMARC record — phishing risk")
    except: result["issues"].append("Missing DMARC record — phishing risk")
    try: r.resolve(domain,"DS"); result["dnssec"] = True
    except: result["issues"].append("DNSSEC not enabled")
    return result

async def analyze_whois(domain):
    result = {"registrar":None,"creation_date":None,"expiration_date":None,"domain_age_days":None,"expires_in_days":None,"privacy_protected":False,"name_servers":[],"issues":[],"info":[]}
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        result["registrar"] = str(w.registrar) if w.registrar else None
        cd = w.creation_date
        if isinstance(cd,list): cd = cd[0]
        if cd and hasattr(cd,"strftime"):
            result["creation_date"] = cd.strftime("%Y-%m-%d")
            age = (datetime.now()-cd).days; result["domain_age_days"] = age
            if age<180: result["issues"].append(f"Domain only {age} days old — higher risk")
            else: result["info"].append(f"Domain age: {age//365} year(s)")
        ed = w.expiration_date
        if isinstance(ed,list): ed = ed[0]
        if ed and hasattr(ed,"strftime"):
            result["expiration_date"] = ed.strftime("%Y-%m-%d")
            exp = (ed-datetime.now()).days; result["expires_in_days"] = exp
            if exp<30: result["issues"].append(f"Domain expires in {exp} days!")
        if w.name_servers: result["name_servers"] = [str(ns).lower() for ns in w.name_servers]
        if any(k in str(w).lower() for k in ["privacy","redacted","protected"]): result["privacy_protected"] = True
    except Exception as e: logger.warning(f"WHOIS failed {domain}: {e}")
    return result

async def check_ssl(domain):
    result = {"valid":False,"expires_in_days":None,"issuer":None,"issues":[],"info":[]}
    try:
        loop = asyncio.get_event_loop()
        def _check():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as conn:
                conn.settimeout(5); conn.connect((domain,443))
                cert = conn.getpeercert()
                exp = datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z")
                days = (exp-datetime.now()).days
                issuer = dict(x[0] for x in cert.get("issuer",[]))
                return {"valid":True,"expires_in_days":days,"issuer":issuer.get("organizationName","Unknown")}
        result.update(await loop.run_in_executor(None,_check))
        d = result["expires_in_days"]
        if d is not None:
            if d<14: result["issues"].append(f"SSL expires in {d} days!")
            elif d<30: result["issues"].append(f"SSL expiring soon ({d} days)")
            else: result["info"].append(f"SSL valid for {d} days")
    except ssl.SSLCertVerificationError: result["issues"].append("SSL certificate invalid or self-signed")
    except Exception as e: logger.warning(f"SSL failed {domain}: {e}"); result["issues"].append("SSL check failed")
    return result

TECH_SIGS = {
    "WordPress":{"h":[],"html":["wp-content","wp-includes"]},
    "Shopify":{"h":["x-shopid"],"html":["cdn.shopify.com"]},
    "Wix":{"h":[],"html":["wixstatic.com"]},
    "Drupal":{"h":["x-generator: drupal"],"html":["drupal.js"]},
    "Ghost":{"h":[],"html":["ghost.io"]},
    "Webflow":{"h":[],"html":["webflow.com"]},
    "React":{"h":[],"html":["data-reactroot","__NEXT_DATA__","_reactFiber"]},
    "Next.js":{"h":["x-powered-by: next.js"],"html":["__NEXT_DATA__","_next/static"]},
    "Vue.js":{"h":[],"html":["vue-router","data-v-"]},
    "Angular":{"h":[],"html":["ng-version","ng-app"]},
    "Nuxt.js":{"h":[],"html":["__nuxt","_nuxt/"]},
    "Svelte":{"h":[],"html":["__svelte"]},
    "Bootstrap":{"h":[],"html":["bootstrap.min.css","bootstrap.bundle"]},
    "Tailwind":{"h":[],"html":["tailwindcss","cdn.tailwindcss"]},
    "PHP":{"h":["x-powered-by: php"],"html":[]},
    "ASP.NET":{"h":["x-powered-by: asp.net"],"html":["__VIEWSTATE"]},
    "Django":{"h":[],"html":["csrfmiddlewaretoken"]},
    "Laravel":{"h":["set-cookie: laravel_session"],"html":[]},
    "Cloudflare":{"h":["cf-ray","server: cloudflare"],"html":[]},
    "Vercel":{"h":["x-vercel-id"],"html":[]},
    "Netlify":{"h":["x-nf-request-id"],"html":[]},
    "AWS CloudFront":{"h":["x-amz-cf-id"],"html":[]},
    "Nginx":{"h":["server: nginx"],"html":[]},
    "Apache":{"h":["server: apache"],"html":[]},
    "IIS":{"h":["server: microsoft-iis"],"html":[]},
    "Google Analytics":{"h":[],"html":["gtag(","google-analytics.com"]},
    "Google Tag Manager":{"h":[],"html":["googletagmanager.com"]},
    "Hotjar":{"h":[],"html":["hotjar.com"]},
    "Stripe":{"h":[],"html":["js.stripe.com"]},
    "PayPal":{"h":[],"html":["paypal.com/sdk"]},
}
TECH_CAT = {
    "WordPress":"CMS","Shopify":"CMS","Wix":"CMS","Drupal":"CMS","Ghost":"CMS","Webflow":"CMS",
    "React":"JS Framework","Next.js":"JS Framework","Vue.js":"JS Framework","Angular":"JS Framework","Nuxt.js":"JS Framework","Svelte":"JS Framework",
    "Bootstrap":"CSS Framework","Tailwind":"CSS Framework",
    "PHP":"Backend","ASP.NET":"Backend","Django":"Backend","Laravel":"Backend",
    "Cloudflare":"CDN","Vercel":"Hosting","Netlify":"Hosting","AWS CloudFront":"CDN",
    "Nginx":"Server","Apache":"Server","IIS":"Server",
    "Google Analytics":"Analytics","Google Tag Manager":"Analytics","Hotjar":"Analytics",
    "Stripe":"Payments","PayPal":"Payments",
}

async def detect_technologies(url, html, headers):
    detected=[]; issues=[]
    hl=html.lower(); hs=" ".join(f"{k}: {v}" for k,v in headers.items()).lower()
    for tech,sigs in TECH_SIGS.items():
        if any(h.lower() in hs for h in sigs["h"]) or any(h.lower() in hl for h in sigs["html"]):
            detected.append({"name":tech,"category":TECH_CAT.get(tech,"Other")})
    m = re.search(r'jquery[.\-](\d+\.\d+)',hl)
    if m:
        v=m.group(1); out=int(v.split(".")[0])<3
        detected.append({"name":f"jQuery {v}","category":"JS Library","outdated":out})
        if out: issues.append(f"jQuery {v} is outdated — known CVEs exist")
    return {"technologies":detected,"issues":issues}

SEC_HDRS = {
    "Strict-Transport-Security":("high","Missing HSTS — HTTP downgrade possible","Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy":("high","Missing CSP — XSS attacks possible","Define Content-Security-Policy header"),
    "X-Frame-Options":("medium","Missing X-Frame-Options — clickjacking risk","Add: X-Frame-Options: DENY"),
    "X-Content-Type-Options":("medium","Missing X-Content-Type-Options — MIME sniffing","Add: X-Content-Type-Options: nosniff"),
    "Referrer-Policy":("low","Missing Referrer-Policy","Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy":("low","Missing Permissions-Policy","Add: Permissions-Policy: camera=(), microphone=()"),
}

def analyze_headers(headers):
    hl={k.lower():v for k,v in headers.items()}; findings=[]
    for hdr,(sev,desc,fix) in SEC_HDRS.items():
        if hdr.lower() not in hl:
            findings.append({"title":f"Missing {hdr}","subtitle":hdr,"severity":sev,"description":desc,"evidence":f"Header '{hdr}' absent","remediation":fix,"category":"Security Headers"})
    sv=hl.get("server","")
    if sv and any(v in sv.lower() for v in ["apache/","nginx/","iis/","php/"]):
        findings.append({"title":"Server Version Disclosure","subtitle":f"Server: {sv}","severity":"medium","description":f"Server reveals: {sv}","evidence":f"Server: {sv}","remediation":"Hide version in server config","category":"Info Disclosure"})
    xpb=hl.get("x-powered-by","")
    if xpb: findings.append({"title":"Technology Disclosure","subtitle":f"X-Powered-By: {xpb}","severity":"low","description":f"X-Powered-By reveals: {xpb}","evidence":f"X-Powered-By: {xpb}","remediation":"Remove X-Powered-By header","category":"Info Disclosure"})
    return {"findings":findings}

def map_owasp(hf,di,ti):
    s=" ".join([f["title"] for f in hf]+di+ti).lower()
    def st(fk,wk=None): return "fail" if any(k in s for k in fk) else "warn" if wk and any(k in s for k in wk) else "pass"
    return [
        {"id":"A01","name":"Broken Access Control","status":st(["access control"])},
        {"id":"A02","name":"Cryptographic Failures","status":st(["hsts","ssl","tls"])},
        {"id":"A03","name":"Injection","status":st(["xss","injection"],["csp"])},
        {"id":"A04","name":"Insecure Design","status":st([],["missing"])},
        {"id":"A05","name":"Security Misconfiguration","status":st(["disclosure","x-powered-by"],["missing"])},
        {"id":"A06","name":"Vulnerable Components","status":st(["outdated","cve"])},
        {"id":"A07","name":"Auth Failures","status":st(["authentication"])},
        {"id":"A08","name":"Data Integrity Failures","status":st(["dmarc","spf"])},
        {"id":"A09","name":"Logging Failures","status":st(["logging"])},
        {"id":"A10","name":"SSRF","status":st(["ssrf"])},
    ]

COMMON_SUBS=["www","api","admin","mail","dev","staging","app","dashboard","portal","blog","shop","cdn","static"]
async def find_subdomains(domain):
    found=[]
    r=dns.resolver.Resolver(); r.timeout=2; r.lifetime=2
    async def check(sub):
        try:
            loop=asyncio.get_event_loop()
            await loop.run_in_executor(None,r.resolve,f"{sub}.{domain}","A")
            found.append(f"{sub}.{domain}")
        except: pass
    await asyncio.gather(*[check(s) for s in COMMON_SUBS])
    return found

async def get_ai_analysis(url,findings,dns_data,whois_data,tech_data):
    if not NVIDIA_API_KEY: return "AI analysis unavailable — set NVIDIA_API_KEY environment variable."
    summary={"url":url,"dns_issues":dns_data.get("issues",[]),"technologies":[t["name"] for t in tech_data.get("technologies",[])],"findings":[{"title":f["title"],"severity":f["severity"]} for f in findings]}
    prompt=f"""You are a senior penetration tester writing a security report.\nTarget: {url}\nData: {json.dumps(summary)}\nWrite 3 paragraphs: 1) Overall risk and critical issues 2) Attack surface observations 3) Remediation roadmap. Prose only."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r=await client.post(f"{NVIDIA_BASE_URL}/chat/completions",headers={"Authorization":f"Bearer {NVIDIA_API_KEY}","Content-Type":"application/json"},json={"model":"meta/llama-3.1-8b-instruct","messages":[{"role":"user","content":prompt}],"max_tokens":600,"temperature":0.7})
            data=r.json()
            if "choices" in data: return data["choices"][0]["message"]["content"]
            return f"AI error: {str(data)[:150]}"
    except Exception as e: logger.error(f"AI failed: {e}"); return f"AI analysis failed: {str(e)[:100]}"

def calc_score(findings):
    d={"critical":25,"high":15,"medium":8,"low":3,"info":0}
    sc=max(0,100-sum(d.get(f.get("severity","info"),0) for f in findings))
    return sc,("A" if sc>=90 else "B" if sc>=75 else "C" if sc>=60 else "D" if sc>=40 else "F")

@app.post("/scan")
async def scan(req: ScanRequest, request: Request):
    client_ip=request.client.host if request.client else "unknown"
    if is_rate_limited(client_ip): raise HTTPException(429,"Too many requests")
    url=normalize_url(req.url); domain=extract_domain(url)
    if not domain: raise HTTPException(400,"Invalid URL")
    if not is_safe_url(url): raise HTTPException(400,"URL not allowed")
    cached=get_cached(url)
    if cached: return {**cached,"cached":True}
    start=time.time(); html=""; hdrs={}
    try:
        async with httpx.AsyncClient(timeout=10,follow_redirects=True,headers={"User-Agent":"Mozilla/5.0 (VaultScan/1.1)"}) as c:
            r=await c.get(url); html=r.text; hdrs=dict(r.headers)
    except Exception as e: logger.warning(f"Fetch failed {url}: {e}")
    dns_data,whois_data,ssl_data,subdomains=await asyncio.gather(analyze_dns(domain),analyze_whois(domain),check_ssl(domain),find_subdomains(domain))
    tech_data=await detect_technologies(url,html,hdrs)
    hdr_data=analyze_headers(hdrs)
    findings=list(hdr_data["findings"])
    for i in dns_data["issues"]: findings.append({"title":i,"subtitle":"DNS","severity":"medium" if any(k in i.lower() for k in ["spf","dmarc"]) else "low","description":i,"evidence":f"DNS: {domain}","remediation":"Fix DNS records","category":"DNS"})
    for i in whois_data["issues"]: findings.append({"title":i,"subtitle":"WHOIS","severity":"medium","description":i,"evidence":f"WHOIS: {domain}","remediation":"Update domain registration","category":"Domain"})
    for i in tech_data["issues"]: findings.append({"title":i,"subtitle":"Outdated Component","severity":"high","description":i,"evidence":"HTML fingerprinting","remediation":"Update to latest version","category":"Components"})
    for i in ssl_data["issues"]: findings.append({"title":i,"subtitle":"SSL/TLS","severity":"high" if "invalid" in i.lower() else "medium","description":i,"evidence":f"SSL: {domain}:443","remediation":"Fix SSL certificate","category":"SSL/TLS"})
    score,grade=calc_score(findings)
    owasp=map_owasp(hdr_data["findings"],dns_data["issues"],tech_data["issues"])
    stats={"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings: stats[f.get("severity","info")]=stats.get(f.get("severity","info"),0)+1
    ai=await get_ai_analysis(url,findings,dns_data,whois_data,tech_data)
    elapsed=round(time.time()-start,2)
    result={"score":score,"grade":grade,"summary":f"Found {len(findings)} issues in {elapsed}s.","elapsed":elapsed,"domain":domain,"cached":False,"stats":stats,"owasp":owasp,"findings":findings,"dns":{"records":{"A":dns_data["a_records"],"MX":dns_data["mx_records"],"NS":dns_data["ns_records"]},"spf":dns_data["spf"],"dmarc":dns_data["dmarc"],"dnssec":dns_data["dnssec"],"info":dns_data["info"]},"whois":{"registrar":whois_data["registrar"],"creation_date":whois_data["creation_date"],"expiration_date":whois_data["expiration_date"],"domain_age_days":whois_data["domain_age_days"],"expires_in_days":whois_data["expires_in_days"],"name_servers":whois_data["name_servers"],"privacy_protected":whois_data["privacy_protected"],"info":whois_data["info"]},"ssl":ssl_data,"subdomains":subdomains,"technologies":tech_data["technologies"],"ai_analysis":ai}
    set_cache(url,result)
    return result

@app.get("/health")
async def health(): return {"status":"ok","version":"1.1.0","ai":"nvidia-nim","cache_entries":len(_scan_cache)}

@app.post("/reviews")
async def add_review(req: ReviewRequest, request: Request):
    client_ip=request.client.host if request.client else "unknown"
    if is_rate_limited(client_ip): raise HTTPException(429,"Too many requests")
    if not (1<=req.stars<=5): raise HTTPException(400,"Stars must be 1-5")
    if len(req.name.strip())<2: raise HTTPException(400,"Name too short")
    if len(req.comment.strip())<10: raise HTTPException(400,"Comment too short")
    if len(req.comment)>500: raise HTTPException(400,"Comment too long")
    review={"id":len(_reviews)+1,"name":req.name.strip()[:50],"role":req.role.strip()[:60],"stars":req.stars,"comment":req.comment.strip()[:500],"date":datetime.now().strftime("%B %Y")}
    _reviews.append(review)
    logger.info(f"Review: {req.name} — {req.stars}★")
    return {"success":True,"review":review}

@app.get("/reviews")
async def get_reviews():
    avg=round(sum(r["stars"] for r in _reviews)/len(_reviews),1) if _reviews else 0
    return {"reviews":list(reversed(_reviews)),"total":len(_reviews),"average":avg}