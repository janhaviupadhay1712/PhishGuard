import math,re
from collections import Counter
from urllib.parse import urlparse
SUSPICIOUS_WORDS=['login','verify','account','secure','update','password','bank','signin','confirm','wallet','payment','unlock','recover']
SHORTENERS={'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','buff.ly','rebrand.ly','cutt.ly','shorturl.at'}
SUSPICIOUS_TLDS={'.zip','.review','.country','.kim','.work','.click','.top','.gq','.tk','.ml','.ga','.cf'}
def _entropy(s):
 c=Counter(s); n=len(s)
 return 0.0 if not s else -sum((v/n)*math.log2(v/n) for v in c.values())
def extract_features(raw_url):
 u=raw_url.strip(); parsed=urlparse(u if re.match(r'^https?://',u,re.I) else 'http://'+u); host=parsed.hostname or ''; path=parsed.path or ''; query=parsed.query or ''; parts=host.split('.') if host else []; lower=u.lower()
 f={'url_length':len(u),'domain_length':len(host),'num_dots':u.count('.'),'num_hyphens':u.count('-'),'num_special_chars':len(re.findall(r'[^A-Za-z0-9]',u)),'num_digits':sum(c.isdigit() for c in u),'num_subdomains':max(0,len(parts)-2),'is_ip':int(bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}',host))),'is_https':int(parsed.scheme.lower()=='https'),'has_at':int('@' in u),'num_query_params':len([x for x in query.split('&') if x]) if query else 0,'num_url_params':u.count('?')+u.count('&'),'num_equals':u.count('='),'num_percent':u.count('%'),'path_length':len(path),'domain_entropy':_entropy(host),'url_entropy':_entropy(u),'has_suspicious_tld':int(any(host.lower().endswith(t) for t in SUSPICIOUS_TLDS)),'is_shortener':int(host.lower() in SHORTENERS),'has_punycode':int('xn--' in host.lower()),'has_hex':int(bool(re.search(r'0x[0-9a-f]+',lower)))}
 for w in SUSPICIOUS_WORDS:f['kw_'+w]=int(w in lower)
 return f
FEATURE_NAMES=list(extract_features('https://example.com').keys())
def explain_features(f):
 checks=[('is_ip','URL uses an IP address instead of a normal domain.'),('has_at','URL contains @, which can obscure the true destination.'),('is_shortener','URL uses a URL-shortening service.'),('has_punycode','Domain contains punycode.'),('has_suspicious_tld','Top-level domain is on the heuristic suspicious-TLD list.'),('has_hex','URL contains hexadecimal-style obfuscation.'),('is_https','URL does not use HTTPS.'),('num_subdomains','URL contains multiple subdomains.'),('url_length','URL is unusually long.'),('num_special_chars','URL contains many special characters.'),('kw_login','Suspicious keyword "login" detected.'),('kw_verify','Suspicious keyword "verify" detected.'),('kw_account','Suspicious keyword "account" detected.'),('kw_password','Suspicious keyword "password" detected.'),('kw_bank','Suspicious keyword "bank" detected.'),('kw_signin','Suspicious keyword "signin" detected.'),('kw_confirm','Suspicious keyword "confirm" detected.')]
 out=[]
 for k,msg in checks:
  v=f.get(k,0); ok=(v==0 if k=='is_https' else v>=2 if k=='num_subdomains' else v>=100 if k=='url_length' else v>=12 if k=='num_special_chars' else bool(v))
  if ok:out.append(msg)
 return out[:7]
