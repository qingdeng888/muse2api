"""Real Chromium dashboard checks with synthetic accounts; no Muse login or external API."""
import argparse,base64,os,json,shutil,socket,signal,subprocess,sys,tempfile,threading,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cdp import CDP

def find_browser():
 env=os.environ.get('MUSE2API_TEST_BROWSER')
 if env and os.path.isfile(env):return env
 for name in ('chromium','google-chrome','chrome','msedge'):
  p=shutil.which(name)
  if p:return p
 for p in (r'C:\Program Files\Google\Chrome\Application\chrome.exe',
           r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
           r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
           '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'):
  if os.path.isfile(p):return p
 return shutil.which('chromium') or shutil.which('google-chrome')

def stop_proc(proc):
 try:
  if hasattr(os,'killpg'):os.killpg(proc.pid,signal.SIGTERM)
  else:proc.terminate()
 except ProcessLookupError:pass
 try:proc.wait(timeout=8)
 except subprocess.TimeoutExpired:
  try:
   if hasattr(os,'killpg'):os.killpg(proc.pid,signal.SIGKILL)
   else:proc.kill()
  except ProcessLookupError:pass

parser=argparse.ArgumentParser();parser.add_argument('--html',default=str(ROOT/'admin.html'));parser.add_argument('--screenshots',type=Path);parser.add_argument('--probe-only',action='store_true');args=parser.parse_args()
html=Path(args.html).read_bytes()
VERSION=json.loads((ROOT/'version.json').read_text(encoding='utf-8'))['version']
now=int(time.time())
accounts=[{'id':'fixture'+str(i).zfill(5),'label':'Fixture-'+str(i),'enabled':True,'ok':True,'essential_ok':True,'cookie_count':12,
 'proxy':None,'note':'会话有效 · 自动保活 (VM: RUNNING)','last_used':now-43200,'expires_at':now+172800,
 'proxy_mode':('bind' if i==0 else 'rotate' if i==1 else 'direct'),
 'proxy_id':('px-fixture' if i==0 else ''),'proxy_server':('socks5://203.0.113.10:1080' if i==0 else None),'proxy_failover':False,
 'quota':{'found':True,'plan':'Free plan','weekly_used_pct':29,'extra_left':'1B tokens left','checked_at':now-10000}} for i in range(8)]
proxies=[{'id':'px-fixture','server':'socks5://203.0.113.10:1080','username':'','has_password':False,'label':'Fixture-Proxy',
 'enabled':True,'created_at':now-86400,'healthy':True,'checking':False,'latency_ms':120,'exit_ip':'203.0.113.9',
 'last_check':now-300,'last_error':'','bindings':1,
 # 已桥接到指定节点：下拉框必须回显该节点，而不是退回到「不桥接」
 'bridge':{'flight':'link::FixtureNode','port':10802,'running':True}},
 {'id':'px-auto','server':'http://198.51.100.20:8080','username':'u','has_password':True,'label':'Auto-Bridge',
 'enabled':True,'created_at':now-80000,'healthy':True,'checking':False,'latency_ms':300,'exit_ip':'198.51.100.20',
 'last_check':now-300,'last_error':'','bindings':0,
 'bridge':{'flight':'AUTO','port':10803,'running':True}}]
events=[]
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  path=urlsplit(self.path).path
  if path in ['/','/admin']:data=html;kind='text/html; charset=utf-8'
  elif path=='/admin/accounts':data={'accounts':accounts,'stats':{'total':8,'healthy':8}};kind='application/json'
  elif path=='/admin/proxies':data={'proxies':proxies};kind='application/json'
  elif path=='/admin/mihomo/status':
   data={'enabled':False,'running':False,'pid':0,'last_error':'','binary_found':False,'binary_path':'',
         'download':{'state':'idle','percent':0,'error':''},'base_port':10801,'api_port':19090,
         'nodes':0,'subscriptions':0,'subscription_list':[],'chains':{},'port_map':{},'work_dir':'/tmp/mihomo'};kind='application/json'
  elif path=='/admin/mihomo/nodes':
   data={'nodes':[{'key':'link::FixtureNode','name':'FixtureNode','type':'vless','server':'203.0.113.1',
                   'port':443,'source':'链接导入','source_id':'link','enabled':True,'direct_port':None,
                   'delay_ms':None,'delay_at':None,'delay_error':''}],'auto_group':'BRIDGE-AUTO'};kind='application/json'
  elif path=='/admin/apikey':data={'api_key':'fixture-only'};kind='application/json'
  elif path in ['/admin/update/check','/admin/repo/status']:
   data={'local_version':VERSION,'remote_version':VERSION,'local_sha':'fixture','remote_sha':'fixture','up_to_date':True,'has_update':False,'recent_commits':[]};kind='application/json'
  else:data={'browser_running':True,'media_count':0,'status':'ok'};kind='application/json'
  body=data if isinstance(data,bytes) else json.dumps(data).encode()
  self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_POST(self):
  body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))) or b'{}')
  events.append({'method':'POST','path':urlsplit(self.path).path,'body':body})
  data=json.dumps({'ok':True,'proxy_reachable':True,'session_ok':True,'exit_ip':'198.51.100.7','workspace_status':'assigned','tested_saved_proxy':False}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
with tempfile.TemporaryDirectory(prefix='muse-layout-',dir=Path.home(),ignore_cleanup_errors=True) as home:
 log=open(Path(home)/'chrome.log','wb')
 proc=subprocess.Popen([find_browser(),'--headless=new','--no-sandbox','--disable-dev-shm-usage','--remote-allow-origins=*',
 '--remote-debugging-port='+str(port),'--user-data-dir='+str(Path(home)/'browser'),'about:blank'],stdout=log,stderr=log,start_new_session=True)
 page=None
 try:
  import requests
  session=requests.Session();session.trust_env=False
  for _ in range(150):
   try:
    tab=next(x for x in session.get(f'http://127.0.0.1:{port}/json/list',timeout=1).json() if x.get('type')=='page')
    page=CDP(tab['webSocketDebuggerUrl'],timeout=15);break
   except (requests.RequestException,StopIteration):time.sleep(.1)
  assert page
  page.send('Page.enable');page.send('Runtime.enable')
  page.send('Page.addScriptToEvaluateOnNewDocument',{'source':"localStorage.setItem('muse2api_lang',localStorage.getItem('muse2api_lang')||'zh');window.__errors=[];window.addEventListener('error',e=>__errors.push(e.message));"})
  page.send('Page.navigate',{'url':f'http://127.0.0.1:{server.server_port}/?key=fixture-only'})
  def wait(expr):
   end=time.monotonic()+15
   while time.monotonic()<end:
    if page.js(expr):return
    time.sleep(.1)
   raise AssertionError('Condition failed: '+expr)
  wait("document.querySelectorAll('#poolBody tr').length===8")
  measure="""(()=>{const m=document.querySelector('main'),sb=document.querySelector('.sidebar'),w=document.querySelector('#poolBody').closest('.tblwrap'),n=document.querySelector('#poolBody td.ellip');return {viewport:innerWidth,mainWidth:m.getBoundingClientRect().width,sbWidth:sb.getBoundingClientRect().width,bodyWidth:document.documentElement.scrollWidth,tableWidth:w.clientWidth,tableScroll:w.scrollWidth,noteDisplay:getComputedStyle(n).display,noteWhiteSpace:getComputedStyle(n).whiteSpace,buttons:document.querySelectorAll('#poolBody tr:first-child button').length}})()"""
  for lang in (['zh'] if args.probe_only else ['zh','en']):
   if lang=='en':
    page.js("localStorage.setItem('muse2api_lang','en');location.reload()");wait("document.querySelectorAll('#poolBody tr').length===8")
   page.js("openPage('accounts')")
   for width in ([1920] if args.probe_only else [2560,1920,1536,1440,1366,1280,768,390,320]):
    page.send('Emulation.setDeviceMetricsOverride',{'width':width,'height':1080,'deviceScaleFactor':1,'mobile':False})
    time.sleep(.15);m=page.js(measure);print(json.dumps({'lang':lang,**m}),flush=True)
    assert m['mainWidth']>=width-m['sbWidth']-24,'Page does not fill the viewport'
    assert m['bodyWidth']<=width+1,'Page overflows the viewport'
    if width>=1280:assert m['tableScroll']<=m['tableWidth']+1,'Desktop account controls need horizontal scrolling'
    assert m['noteDisplay']=='table-cell' and m['noteWhiteSpace']=='normal','Notes must retain table-cell layout and wrap'
    assert m['buttons']==8
    if width==1920 and not args.probe_only and args.screenshots:
     page.js("document.querySelector('#poolBody').scrollIntoView({block:'end'})")
     image=page.send('Page.captureScreenshot',{'format':'png'})
     args.screenshots.mkdir(parents=True,exist_ok=True)
     (args.screenshots/('layout-'+lang+'.png')).write_bytes(base64.b64decode(image['result']['data']))
  if not args.probe_only:
   page.send('Emulation.setDeviceMetricsOverride',{'width':390,'height':844,'deviceScaleFactor':1,'mobile':False})
   page.js("openProxy('fixture00000')")
   wait("$('proxyDialog').open && $('proxySelect').options.length>0")
   page.js("$('proxyMode').value='bind';updateProxyMode();$('proxySelect').value='px-fixture';$('proxySelect').dispatchEvent(new Event('change',{bubbles:true}))")
   assert page.js("!$('proxyTest').disabled && document.querySelector('.proxy-auth')===null")
   page.js("$('proxyTest').click()");wait("$('proxyResult').innerText.includes('198.51.100.7') && !$('proxyTest').disabled")
   assert events[-1]['body'].get('proxy_id')=='px-fixture'
   assert page.js("!accounts[0].proxy && $('proxyDialog').getBoundingClientRect().right<=innerWidth")
   assert all(e['path'].endswith('/proxy/test') for e in events)
   page.js("$('proxyDialog').close()")
   wait("$('proxyMode').value==='direct' && !$('proxySelect').disabled")
   page.js("openPage('proxies')")
   wait("document.querySelectorAll('#pxBody tr[data-pid]').length===2")
   page.js("$('pxSelectAll').click()")
   assert page.js("$('pxBulkCount').textContent==='2' && $('pxSelectAll').checked && $('pxSelectAll').indeterminate===false")
   assert page.js("!$('pxBulkTest').disabled && !$('pxBulkEnable').disabled && !$('pxBulkDisable').disabled && !$('pxBulkDelete').disabled")
   assert page.js("document.querySelector('#pxBody tr').classList.contains('px-selected')")
   page.js("$('pxSelectAll').click()")
   assert page.js("$('pxBulkCount').textContent==='0' && $('pxBulkTest').disabled")
   page.js("openPage('mihomo')")
   wait("$('mhFacts').children.length>0")
   assert page.js("$('mhNodeBody').children.length===1 && $('mhSubBody').children.length===1")
   assert page.js("$('mhRunBadge').textContent.length>0 && document.querySelectorAll('#mhChainBody tr').length>=1")
   # 关键回归：链式封装下拉框必须回显真实绑定（指定节点 / AUTO），不能一律显示「不桥接」
   assert page.js("document.querySelector('#mhChainSel-px-fixture').value==='link::FixtureNode'"), \
       'chained-to-pinned-node row must display that node as selected'
   assert page.js("document.querySelector('#mhChainSel-px-auto').value==='AUTO'"), \
       'auto-escaped row must display AUTO as selected'
   # 切到「不桥接」必须能直接生效（值从节点变空 → onchange 触发 → flight 传 null）
   page.js("window.__chainCalls=[]; mihomoSetChain=(pid,flight)=>{window.__chainCalls.push([pid,flight||null]); return Promise.resolve();}")
   page.js("const s=document.querySelector('#mhChainSel-px-fixture'); s.value=''; s.dispatchEvent(new Event('change'))")
   assert page.js("JSON.stringify(window.__chainCalls)===JSON.stringify([['px-fixture',null]])"), \
       'selecting "no bridge" must send flight=null in one action'
   # 飞行节点多选：全选 → 批量按钮可用 → 取消选择
   page.js("$('mhNodeSelectAll').click()")
   assert page.js("$('mhNodeSelCount').textContent==='1' && !$('mhNodeBulkEnable').disabled && !$('mhNodeBulkDisable').disabled && !$('mhNodeBulkDelete').disabled && !$('mhNodeBulkTest').disabled")
   assert page.js("document.querySelector('#mhNodeBody tr[data-nkey]').classList.contains('px-selected')")
   page.js("clearMhNodeSelection()")
   assert page.js("$('mhNodeSelCount').textContent==='0' && $('mhNodeBulkDelete').disabled")
  if not args.probe_only:
   assert not page.js('window.__errors')
   print('PASS: full-width layout, desktop controls, contained mobile scrolling, Chinese/English and test-without-saving')
 finally:
  if page:
   try:page.send('Browser.close')
   except Exception:pass
   page.close()
  stop_proc(proc)
  time.sleep(.2);log.close();server.shutdown();server.server_close()
