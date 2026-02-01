import re
from urllib.parse import urlparse
import utils

class URLAnalyzer:
    def analyze(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()
        
        factors = []
        
        # 1. IP-based URL
        if utils.is_ip_address(domain):
            factors.append({'msg': 'IP address used instead of domain name', 'impact': 40})
            
        # 2. Suspicious Keywords
        found_keywords = [word for word in utils.SENSITIVE_KEYWORDS if word in full_url]
        if found_keywords:
            factors.append({'msg': f'Suspicious keywords detected: {", ".join(found_keywords)}', 'impact': 15 * len(found_keywords)})
            
        # 3. URL Length
        if len(url) > 75:
            factors.append({'msg': f'Excessively long URL ({len(url)} chars)', 'impact': 20})
            
        # 4. Multiple Subdomains
        dots = domain.count('.')
        if dots > 3:
            factors.append({'msg': f'Too many subdomains ({dots})', 'impact': 25})
            
        # 5. Suspicious TLD
        if any(domain.endswith(tld) for tld in utils.SUSPICIOUS_TLDS):
            factors.append({'msg': f'Suspicious Top Level Domain (TLD) detected', 'impact': 30})
            
        # 6. URL Shorteners
        if any(shortener in domain for shortener in utils.URL_SHORTENERS):
            factors.append({'msg': 'URL shortener detected (hides destination)', 'impact': 35})

        # 7. Redirect Indicators
        if any(term in query for term in ['redirect', 'url=', 'next=', 'dest=']):
            factors.append({'msg': 'Potential redirect/forwarding parameter found', 'impact': 20})

        # 8. Obfuscation (Encoding)
        if '%' in full_url:
            factors.append({'msg': 'URL contains encoding (obfuscation risk)', 'impact': 15})

        score = utils.calculate_score(factors)
        level = utils.get_risk_level(score)
        
        return {
            'score': score,
            'level': level,
            'factors': factors,
            'type': 'URL'
        }

class FileAnalyzer:
    def analyze(self, filename):
        factors = []
        filename_lower = filename.lower()
        
        # 1. Dangerous Extensions
        if any(filename_lower.endswith(ext) for ext in utils.DANGEROUS_EXTENSIONS):
            factors.append({'msg': 'Dangerous file extension detected', 'impact': 50})
            
        # 2. Double Extensions
        parts = filename.split('.')
        if len(parts) > 2:
            last_ext = parts[-1].lower()
            prev_ext = parts[-2].lower()
            if last_ext in ['exe', 'scr', 'vbs', 'js', 'bat'] and prev_ext in ['pdf', 'doc', 'docx', 'jpg', 'png']:
                factors.append({'msg': f'Double extension detected: .{prev_ext}.{last_ext}', 'impact': 45})
                
        # 3. Suspicious Naming Patterns
        # Random looking strings or many numbers
        digits = sum(c.isdigit() for c in filename)
        if digits > 8:
            factors.append({'msg': 'Excessive numeric content in filename', 'impact': 15})
            
        if re.search(r'[a-zA-Z0-9]{15,}', filename):
            factors.append({'msg': 'Long randomized character string detected', 'impact': 20})

        score = utils.calculate_score(factors)
        level = utils.get_risk_level(score)
        
        return {
            'score': score,
            'level': level,
            'factors': factors,
            'type': 'FILE'
        }
