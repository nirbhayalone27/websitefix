import json, os, socket, ssl, ipaddress, urllib.parse, http.client, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from collections import defaultdict, deque

MAX_BODY=800000
class Page(HTMLParser):
 def __init__(self):
  super().__init__(); self.title=""; self.intitle=False; self.meta={}; self.h1=0; self.images=0; self.alt_missing=0; self.lang=False; self.viewport=False
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag=="title": self.intitle=True
  if tag=="html": self.lang=bool(a.get("lang"))
  if tag=="h1": self.h1+=1
  if tag=="img":
   self.images+=1
   if "alt" not in a: self.alt_missing+=1
  if tag=="meta":
   self.meta[(a.get("name") or "").lower()]=a.get("content","")
   if (a.get("name") or "").lower()=="viewport": self.viewport=True
 def handle_endtag(self,tag):
  if tag=="title": self.intitle=False
 def handle_data(self,data):
  if self.intitle: self.title+=data

def validate(url):
 if not isinstance(url,str) or len(url)>2048: raise ValueError("Invalid URL")
 p=urllib.parse.urlsplit(url)
 if p.scheme not in ("http","https") or not p.hostname or p.username or p.password or p.port not in (None,80,443): raise ValueError("Use a public HTTP(S) URL on a standard port")
 host=p.hostname.lower().rstrip(".")
 if host=="localhost" or host.endswith((".local",".internal",".localhost",".onion")): raise ValueError("Private host blocked")
 return p

def public_ip(host,port):
 ips={r[4][0] for r in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)}
 if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips): raise ValueError("Only public IP addresses are allowed")
 return sorted(ips)[0]

class PinnedHTTP(http.client.HTTPConnection):
 def __init__(self,host,port,ip): super().__init__(host,port,timeout=7);self.ip=ip
 def connect(self): self.sock=socket.create_connection((self.ip,self.port),self.timeout)
class PinnedHTTPS(http.client.HTTPSConnection):
 def __init__(self,host,port,ip): super().__init__(host,port,timeout=7,context=ssl.create_default_context());self.ip=ip
 def connect(self):
  raw=socket.create_connection((self.ip,self.port),self.timeout)
  self.sock=self._context.wrap_socket(raw,server_hostname=self.host)

def fetch(url):
 p=validate(url);port=443 if p.scheme=="https" else 80
 ip=public_ip(p.hostname,port)
 conn=(PinnedHTTPS if p.scheme=="https" else PinnedHTTP)(p.hostname,port,ip)
 try:
  path=urllib.parse.urlunsplit(("","",p.path or "/",p.query,""))
  conn.request("GET",path,headers={"Host":p.hostname,"User-Agent":"WebsiteFix/1.0","Accept":"text/html","Connection":"close"})
  r=conn.getresponse();body=r.read(MAX_BODY+1)
  return r.status,dict(r.getheaders()),body[:MAX_BODY],len(body)>MAX_BODY
 finally: conn.close()

def scan(url):
 p=validate(url);started=time.monotonic();status,headers,body,truncated=fetch(url)
 for _ in range(3):
  if status not in (301,302,303,307,308): break
  location=next((v for k,v in headers.items() if k.lower()=="location"),None)
  if not location: break
  dest=urllib.parse.urljoin(url,location)
  if validate(dest).hostname!=p.hostname: raise ValueError("Cross-host redirects are not followed. Enter the final URL.")
  url=dest;status,headers,body,truncated=fetch(url)
 if status in (301,302,303,307,308): raise ValueError("Too many redirects")
 if status>=400: raise ValueError("Website returned HTTP "+str(status))
 content_type=next((v for k,v in headers.items() if k.lower()=="content-type"),"")
 if "html" not in content_type.lower(): raise ValueError("URL does not return HTML")
 doc=Page();doc.feed(body.decode("utf-8","replace"));issues=[]
 def issue(severity,title,detail,fix):issues.append({"severity":severity,"title":title,"evidence":detail,"fix":fix})
 if not doc.title.strip(): issue("high","Missing title","No page title","Add a unique descriptive title")
 if not doc.meta.get("description"): issue("medium","Missing meta description","No meta description","Add a concise page summary")
 if doc.h1==0: issue("medium","Missing H1","No primary heading","Add a clear H1 heading")
 if not doc.lang: issue("medium","Missing document language","HTML lang not found","Set the correct HTML lang")
 if not doc.viewport: issue("medium","Missing viewport","Mobile viewport not found","Add a viewport meta tag")
 if doc.alt_missing: issue("medium","Images missing alt attributes",str(doc.alt_missing)+" images","Use descriptive alt text or empty alt for decorative images")
 if p.scheme!="https": issue("high","Insecure URL","HTTP requested","Enable HTTPS")
 if not any(k.lower()=="content-security-policy" for k in headers): issue("low","CSP not detected","No CSP response header","Review and implement a tested Content Security Policy")
 weights={"high":20,"medium":10,"low":4}
 score=max(0,100-sum(weights[i["severity"]] for i in issues))
 return {"url":url,"status":status,"score":score,"score_type":"simple heuristic, not Lighthouse or SEO ranking","duration_ms":round((time.monotonic()-started)*1000),"page":{"title":doc.title.strip(),"h1_count":doc.h1,"images":doc.images},"issues":issues,"truncated":truncated,"limitations":["HTML-only checks","No JavaScript rendering","Not a WCAG or security certification"]}

hits=defaultdict(deque);lock=threading.Lock();semaphore=threading.BoundedSemaphore(3)
class Handler(BaseHTTPRequestHandler):
 def reply(self,code,obj,ctype="application/json"):
  raw=(obj if isinstance(obj,str) else json.dumps(obj)).encode()
  self.send_response(code);self.send_header("Content-Type",ctype+"; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.send_header("X-Content-Type-Options","nosniff");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(raw)
 def do_GET(self):
  if self.path=="/health": return self.reply(200,{"status":"ok"})
  if self.path=="/":
   with open(os.path.join(os.path.dirname(__file__),"index.html"),encoding="utf-8") as f:return self.reply(200,f.read(),"text/html")
  self.reply(404,{"error":"Not found"})
 def do_POST(self):
  if self.path!="/api/scan":return self.reply(404,{"error":"Not found"})
  try:
   n=int(self.headers.get("Content-Length","0"))
   if not 1<=n<=4096: raise ValueError("Request body too large or empty")
   with lock:
    q=hits[self.client_address[0]];now=time.monotonic()
    while q and q[0]<now-60:q.popleft()
    if len(q)>=5:return self.reply(429,{"error":"Rate limit exceeded"})
    q.append(now)
   if not semaphore.acquire(blocking=False):return self.reply(503,{"error":"Scanner busy"})
   try:return self.reply(200,scan(json.loads(self.rfile.read(n)).get("url","")))
   finally:semaphore.release()
  except ValueError as e:self.reply(400,{"error":str(e)})
  except Exception:self.reply(502,{"error":"Unable to scan target website"})
if __name__=="__main__":
 ThreadingHTTPServer((os.getenv("HOST","127.0.0.1"),int(os.getenv("PORT","8000"))),Handler).serve_forever()
