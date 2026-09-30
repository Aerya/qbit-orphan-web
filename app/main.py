from __future__ import annotations

import asyncio, base64, hashlib, hmac, json, os, secrets, sqlite3, time, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

BASE_DIR=Path(__file__).resolve().parent
CONFIG_DIR=Path(os.environ.get('QOW_CONFIG_DIR','/config')); CONFIG_DIR.mkdir(parents=True,exist_ok=True)
SETTINGS_PATH=CONFIG_DIR/'settings.json'; DB_PATH=CONFIG_DIR/'history.sqlite3'; SECRET_PATH=CONFIG_DIR/'session.secret'
BROWSE_ROOT=Path(os.environ.get('QOW_BROWSE_ROOT','/data')).resolve(strict=False)
if not SECRET_PATH.exists(): SECRET_PATH.write_text(secrets.token_hex(32)); os.chmod(SECRET_PATH,0o600)

app=FastAPI(title='Torrent Orphan Web',docs_url=None,redoc_url=None)
app.mount('/static',StaticFiles(directory=str(BASE_DIR/'static')),name='static')
app.add_middleware(SessionMiddleware,secret_key=SECRET_PATH.read_text().strip(),same_site='lax',https_only=False)
templates=Jinja2Templates(directory=str(BASE_DIR/'templates'))
scan_lock=asyncio.Lock(); state={'orphans':{},'last_scan':None,'stats':{},'client_stats':[],'errors':[]}

class DeleteRequest(BaseModel): ids:list[str]
class LoginRequest(BaseModel): username:str; password:str
class ClientModel(BaseModel):
    id:str|None=None; name:str='Client'; type:str='qbittorrent'; url:str=''; webui_url:str=''; username:str=''; password:str=''; api_key:str=''; remote_root:str='/downloads'; local_root:str=''
class SettingsModel(BaseModel):
    clients:list[ClientModel]=Field(default_factory=list)
    exclude_dirs:list[str]=Field(default_factory=lambda:['.Trash-1000','lost+found'])
    exclude_files:list[str]=Field(default_factory=lambda:['.DS_Store'])
    automation:dict[str,Any]=Field(default_factory=dict)
    notifications:dict[str,Any]=Field(default_factory=dict)
    auth:dict[str,Any]=Field(default_factory=dict)

def defaults(): return {'clients':[],'exclude_dirs':['.Trash-1000','lost+found'],'exclude_files':['.DS_Store'],'automation':{'scan_enabled':False,'scan_interval_minutes':360,'delete_enabled':False,'delete_min_age_hours':168,'client_ids':[]},'notifications':{'mode':'off','discord_webhook':'','apprise_urls':'','events':['scan','auto_delete','error']},'auth':{'enabled':False,'username':'admin','password_hash':''}}
def load_settings():
    d=defaults()
    if SETTINGS_PATH.exists():
        try: d.update(json.loads(SETTINGS_PATH.read_text()))
        except Exception: pass
    for k in ('automation','notifications','auth'):
        tmp=defaults()[k].copy(); tmp.update(d.get(k) or {}); d[k]=tmp
    for c in d.get('clients',[]):
        c.setdefault('type','qbittorrent'); c.setdefault('webui_url',''); c.setdefault('remote_root','/downloads'); c.setdefault('local_root','')
        if not c.get('local_root') and c.get('path_mappings'):
            m=c['path_mappings'][0]; c['remote_root']=m.get('remote','/downloads'); c['local_root']=m.get('local','')
        c.pop('path_mappings',None)
    d.pop('scan_roots',None)
    return d

def save_settings(d):
    tmp=SETTINGS_PATH.with_suffix('.tmp'); tmp.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n'); os.chmod(tmp,0o600); tmp.replace(SETTINGS_PATH)

def db():
    con=sqlite3.connect(DB_PATH); con.row_factory=sqlite3.Row
    con.executescript('''
    CREATE TABLE IF NOT EXISTS scans(ts TEXT, client_id TEXT, client_name TEXT, client_type TEXT, torrents INTEGER, referenced_files INTEGER, scanned_files INTEGER, orphan_files INTEGER, orphan_bytes INTEGER);
    CREATE TABLE IF NOT EXISTS deletions(ts TEXT, client_id TEXT, client_name TEXT, files INTEGER, bytes INTEGER, automatic INTEGER);
    CREATE TABLE IF NOT EXISTS orphan_seen(client_id TEXT, path TEXT, first_seen TEXT, last_seen TEXT, PRIMARY KEY(client_id,path));
    ''')
    cols={r['name'] for r in con.execute('PRAGMA table_info(scans)')}
    if 'announced_files' not in cols: con.execute('ALTER TABLE scans ADD COLUMN announced_files INTEGER DEFAULT 0')
    if 'found_files' not in cols: con.execute('ALTER TABLE scans ADD COLUMN found_files INTEGER DEFAULT 0')
    con.commit(); return con

def nowiso(): return datetime.now(timezone.utc).isoformat()
def hash_password(pw,salt=None):
    salt=salt or secrets.token_bytes(16); dk=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,260000); return base64.b64encode(salt+dk).decode()
def verify_password(pw,encoded):
    try:
        raw=base64.b64decode(encoded); salt,expected=raw[:16],raw[16:]; got=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,260000); return hmac.compare_digest(got,expected)
    except Exception: return False

def auth_required(): return bool(load_settings().get('auth',{}).get('enabled'))
@app.middleware('http')
async def auth_middleware(request:Request,call_next):
    if request.url.path.startswith(('/static','/api/auth/','/login')): return await call_next(request)
    if auth_required() and not request.session.get('auth'):
        if request.url.path.startswith('/api/'): return JSONResponse({'detail':'Authentification requise'},status_code=401)
        return RedirectResponse('/login',303)
    return await call_next(request)

@app.get('/login',response_class=HTMLResponse)
async def login_page(request:Request):
    if not auth_required(): return RedirectResponse('/',303)
    return HTMLResponse("""<!doctype html><html><meta charset=utf-8><title>Connexion</title><style>body{background:#111318;color:#eee;font:16px system-ui;display:grid;place-items:center;height:100vh}.b{background:#181b22;border:1px solid #303642;padding:28px;border-radius:14px;width:340px}input,button{width:100%;padding:11px;margin:7px 0;background:#101319;color:#eee;border:1px solid #39404d;border-radius:8px}button{background:#2365a5}</style><div class=b><h2>Torrent Orphan Web</h2><input id=u placeholder=Utilisateur><input id=p type=password placeholder='Mot de passe'><button onclick=l()>Connexion</button><div id=e></div></div><script>async function l(){let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});if(r.ok)location='/';else e.textContent='Connexion refusée'}</script></html>""")
@app.post('/api/auth/login')
async def login(body:LoginRequest,request:Request):
    a=load_settings()['auth']
    if not a.get('enabled') or (body.username==a.get('username') and verify_password(body.password,a.get('password_hash',''))): request.session['auth']=True; return {'ok':True}
    raise HTTPException(401,'Connexion refusée')
@app.post('/api/auth/logout')
async def logout(request:Request): request.session.clear(); return {'ok':True}

async def qbit_session(c):
    url=c.get('url','').strip().rstrip('/'); headers={'Referer':url,'Origin':url}; key=c.get('api_key','').strip()
    if key: headers['Authorization']='Bearer '+key
    cli=httpx.AsyncClient(base_url=url,headers=headers,timeout=30,follow_redirects=True)
    if not key:
        r=await cli.post('/api/v2/auth/login',data={'username':c.get('username',''),'password':c.get('password','')})
        if r.status_code in (401,403) or (r.status_code!=204 and r.text.strip().lower().startswith('fails')): await cli.aclose(); raise RuntimeError(f'authentification refusée ({r.status_code})')
        r.raise_for_status()
    return cli

def map_client_path(raw_path:str,c:dict[str,Any]):
    """Mappe un chemin annoncé par un client vers /data sans jamais autoriser une sortie hors de /data."""
    raw=str(raw_path or '').replace('\\','/').strip()
    if not raw: return None
    remote=str(c.get('remote_root') or '/downloads').replace('\\','/').rstrip('/') or '/'
    local=Path(c.get('local_root') or BROWSE_ROOT).resolve(strict=False)

    # Certains clients voient déjà la même racine que Torrent Orphan Web (normalement /data).
    browse_prefix=BROWSE_ROOT.as_posix().rstrip('/') or '/'
    if raw==browse_prefix or raw.startswith(browse_prefix+'/'):
        candidate=Path(raw).resolve(strict=False)
    elif raw==remote:
        candidate=local
    elif raw.startswith(remote+'/'):
        candidate=(local/raw[len(remote)+1:]).resolve(strict=False)
    else:
        return None

    try: candidate.relative_to(BROWSE_ROOT)
    except ValueError: return None
    return candidate

async def qbit_collect(c):
    cli=await qbit_session(c)
    try:
        tr=await cli.get('/api/v2/torrents/info'); tr.raise_for_status(); torrents=tr.json(); refs=set(); announced=0
        sem=asyncio.Semaphore(20)
        async def one(t):
            nonlocal announced
            async with sem:
                r=await cli.get('/api/v2/torrents/files',params={'hash':t['hash']}); r.raise_for_status(); fs=r.json()
            announced+=len(fs); out=[]; save=str(t.get('save_path','')).replace('\\','/').rstrip('/')
            for f in fs:
                full=(save+'/'+str(f.get('name','')).lstrip('/')).replace('//','/')
                mapped=map_client_path(full,c)
                if mapped is not None: out.append(mapped)
            return out
        for batch in await asyncio.gather(*(one(t) for t in torrents)): refs.update(batch)
        found=sum(1 for x in refs if x.exists() and x.is_file())
        v=await cli.get('/api/v2/app/version')
        return refs,{'torrents':len(torrents),'announced_files':announced,'found_files':found,'referenced_files':len(refs),'version':v.text.strip() if v.is_success else ''}
    finally: await cli.aclose()

def xml_value(v):
    if v is None:return '<nil/>'
    if isinstance(v,int): return f'<i8>{v}</i8>'
    return '<string>'+str(v).replace('&','&amp;').replace('<','&lt;')+'</string>'
def parse_xml_value(el):
    if el is None:return None
    child=next(iter(el),None)
    if child is None:return el.text or ''
    if child.tag in ('string','base64'):return child.text or ''
    if child.tag in ('int','i4','i8'):return int(child.text or 0)
    if child.tag=='array':return [parse_xml_value(v) for v in child.findall('./data/value')]
    if child.tag=='struct':return {m.findtext('name'):parse_xml_value(m.find('value')) for m in child.findall('member')}
    return child.text or ''
async def xmlrpc(url,method,*params):
    body='<?xml version="1.0"?><methodCall><methodName>'+method+'</methodName><params>'+''.join('<param><value>'+xml_value(p)+'</value></param>' for p in params)+'</params></methodCall>'
    async with httpx.AsyncClient(timeout=30) as cli:
        r=await cli.post(url,content=body,headers={'Content-Type':'text/xml'}); r.raise_for_status(); root=ET.fromstring(r.text)
    fault=root.find('.//fault');
    if fault is not None: raise RuntimeError(str(parse_xml_value(fault.find('value'))))
    return parse_xml_value(root.find('.//params/param/value'))
async def rtorrent_collect(c):
    # XML-RPC over HTTP (direct RPC2 or reverse-proxied SCGI endpoint)
    rows=await xmlrpc(c['url'],'d.multicall2','main','d.hash=','d.directory_base=','d.name=','d.size_bytes=')
    refs=set(); announced=0
    for row in rows or []:
        if len(row)<3: continue
        announced+=1
        base=str(row[1]).replace('\\','/').rstrip('/'); name=str(row[2]); full=(base+'/'+name).replace('//','/')
        candidate=map_client_path(full,c) or map_client_path(base,c)
        if candidate is None: continue
        if candidate.exists() and candidate.is_dir():
            for fp in candidate.rglob('*'):
                try:
                    if fp.is_file(): refs.add(fp.resolve(strict=False))
                except OSError: pass
        else:
            refs.add(candidate)
    found=sum(1 for x in refs if x.exists() and x.is_file())
    return refs,{'torrents':len(rows or []),'announced_files':announced,'found_files':found,'referenced_files':len(refs),'version':'rTorrent'}

async def collect_client(c): return await (rtorrent_collect(c) if c.get('type')=='rtorrent' else qbit_collect(c))

async def test_client(c):
    refs,s=await collect_client(c); return {'ok':True,'version':s.get('version',''),'torrents':s['torrents']}

def scan_disk(root,cfg):
    files=[]; root=Path(root).resolve(strict=False); exd=set(cfg['exclude_dirs']); exf=set(cfg['exclude_files'])
    if not root.exists(): raise RuntimeError(f'Dossier introuvable: {root}')
    for base,dirs,names in os.walk(root):
        dirs[:]=[d for d in dirs if d not in exd]
        for n in names:
            if n in exf: continue
            p=Path(base)/n
            try: st=p.stat(); files.append((p.resolve(strict=False),st.st_size,st.st_mtime))
            except OSError: pass
    return files

async def notify(event,title,message):
    cfg=load_settings().get('notifications',{}); events=cfg.get('events',[])
    if cfg.get('mode')=='off' or event not in events:return
    try:
        if cfg.get('mode')=='discord' and cfg.get('discord_webhook'):
            async with httpx.AsyncClient(timeout=15) as c: await c.post(cfg['discord_webhook'],json={'content':f'**{title}**\n{message}'})
        elif cfg.get('mode')=='apprise' and cfg.get('apprise_urls'):
            import apprise
            a=apprise.Apprise(); [a.add(x.strip()) for x in cfg['apprise_urls'].splitlines() if x.strip()]; await asyncio.to_thread(a.notify,title=title,body=message)
    except Exception: pass

async def do_scan(automatic=False):
    async with scan_lock:
        cfg=load_settings(); clients=cfg['clients']
        if not clients: raise RuntimeError('Aucun client configuré')
        results=await asyncio.gather(*(collect_client(c) for c in clients),return_exceptions=True)
        errors=[]; global_refs=set(); per=[]
        for c,r in zip(clients,results):
            if isinstance(r,Exception): errors.append(f"{c.get('name')}: {r}")
            else: global_refs.update(r[0]); per.append((c,r[1]))
        if errors: state['errors']=errors; await notify('error','Torrent Orphan Web',' | '.join(errors)); raise RuntimeError(' | '.join(errors))
        orphans={}; client_stats=[]; con=db(); ts=nowiso(); seen_keys=[]
        for c,s in per:
            disk=scan_disk(c['local_root'],cfg); own=[]
            for p,size,mtime in disk:
                if p not in global_refs:
                    oid=hashlib.sha256((c['id']+'\0'+str(p)).encode()).hexdigest(); row=con.execute('SELECT first_seen FROM orphan_seen WHERE client_id=? AND path=?',(c['id'],str(p))).fetchone(); first=row['first_seen'] if row else ts
                    con.execute('INSERT INTO orphan_seen(client_id,path,first_seen,last_seen) VALUES(?,?,?,?) ON CONFLICT(client_id,path) DO UPDATE SET last_seen=excluded.last_seen',(c['id'],str(p),first,ts)); seen_keys.append((c['id'],str(p)))
                    item={'id':oid,'client_id':c['id'],'client_name':c['name'],'client_type':c.get('type','qbittorrent'),'path':str(p),'relative_path':str(p.relative_to(Path(c['local_root']))),'size':size,'mtime':mtime,'first_seen':first}; orphans[oid]=item; own.append(item)
            webui=(c.get('webui_url') or (c.get('url') if c.get('type','qbittorrent')=='qbittorrent' else ''))
            cs={**s,'client_id':c['id'],'client_name':c['name'],'client_type':c.get('type','qbittorrent'),'webui_url':webui,'scanned_files':len(disk),'orphan_files':len(own),'orphan_bytes':sum(x['size'] for x in own)}; client_stats.append(cs)
            con.execute('INSERT INTO scans(ts,client_id,client_name,client_type,torrents,referenced_files,scanned_files,orphan_files,orphan_bytes,announced_files,found_files) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(ts,c['id'],c['name'],c.get('type','qbittorrent'),s['torrents'],s['referenced_files'],len(disk),len(own),cs['orphan_bytes'],s.get('announced_files',s['referenced_files']),s.get('found_files',0)))
        con.commit(); con.close()
        state.update({'orphans':orphans,'last_scan':ts,'client_stats':client_stats,'errors':[],'stats':{'torrents':sum(x['torrents'] for x in client_stats),'announced_files':sum(x.get('announced_files',0) for x in client_stats),'found_files':sum(x.get('found_files',0) for x in client_stats),'scanned_files':sum(x['scanned_files'] for x in client_stats),'referenced_files':len(global_refs),'orphan_files':len(orphans),'orphan_bytes':sum(x['size'] for x in orphans.values())}})
        await notify('scan','Scan terminé',f"{len(orphans)} orphelin(s), {state['stats']['orphan_bytes']/1024**3:.2f} Gio récupérables")
        return state

def prune_empty_parents(start:Path, stop:Path):
    removed=[]
    stop=stop.resolve(strict=False)
    current=start.resolve(strict=False)
    try:
        current.relative_to(stop)
    except ValueError:
        return removed
    while current != stop:
        try:
            current.rmdir()
        except OSError:
            break
        removed.append(str(current))
        current=current.parent
    return removed

async def delete_ids(ids,automatic=False):
    cfg=load_settings(); # Recollect globally before deletion
    results=await asyncio.gather(*(collect_client(c) for c in cfg['clients']),return_exceptions=True)
    if any(isinstance(x,Exception) for x in results): raise RuntimeError('Suppression annulée : un client est inaccessible')
    refs=set(); [refs.update(x[0]) for x in results]
    deleted=[]; skipped=[]; grouped={}
    for oid in ids:
        item=state['orphans'].get(oid)
        if not item: continue
        p=Path(item['path']).resolve(strict=False)
        if p in refs: skipped.append({'path':str(p),'reason':'désormais référencé'}); continue
        try: size=p.stat().st_size; p.unlink(); deleted.append(item); grouped.setdefault((item['client_id'],item['client_name']),[0,0]); grouped[(item['client_id'],item['client_name'])][0]+=1; grouped[(item['client_id'],item['client_name'])][1]+=size
        except Exception as e: skipped.append({'path':str(p),'reason':str(e)})
    roots={c.get('id'):Path(c.get('local_root','')).resolve(strict=False) for c in cfg['clients'] if c.get('id') and c.get('local_root')}
    removed_dirs=[]
    for item in deleted:
        root=roots.get(item['client_id'])
        if not root:
            continue
        removed_dirs.extend(prune_empty_parents(Path(item['path']).parent,root))
    removed_dirs=list(dict.fromkeys(removed_dirs))

    con=db(); ts=nowiso()
    for (cid,name),(count,bytes_) in grouped.items():
        con.execute('INSERT INTO deletions VALUES(?,?,?,?,?,?)',(ts,cid,name,count,bytes_,1 if automatic else 0))
    con.commit(); con.close()
    for x in deleted:
        state['orphans'].pop(x['id'],None)

    deleted_bytes=sum(x['size'] for x in deleted)
    if deleted:
        await notify(
            'auto_delete' if automatic else 'manual_delete',
            'Suppression terminée',
            f"{len(deleted)} fichier(s) supprimé(s), {deleted_bytes/1024**3:.2f} Gio, {len(removed_dirs)} dossier(s) vide(s) supprimé(s)"
        )
    return {
        'deleted':len(deleted),
        'bytes':deleted_bytes,
        'removed_dirs':len(removed_dirs),
        'removed_dir_paths':removed_dirs,
        'skipped':skipped
    }

@app.get('/',response_class=HTMLResponse)
async def home(request:Request): return templates.TemplateResponse('index.html',{'request':request,'auth_enabled':auth_required()})
@app.get('/api/state')
async def api_state(): return {**state,'orphans':list(state['orphans'].values())}
@app.post('/api/scan')
async def api_scan():
    try:return await do_scan(False)
    except Exception as e: raise HTTPException(500,str(e))
@app.post('/api/delete')
async def api_delete(body:DeleteRequest):
    try:return await delete_ids(body.ids,False)
    except Exception as e: raise HTTPException(500,str(e))
@app.get('/api/settings')
async def get_settings(): return load_settings()
@app.put('/api/settings')
async def put_settings(body:dict[str,Any]):
    old=load_settings(); new=defaults(); new.update(body)
    # Preserve existing password hash unless a new plaintext password was supplied.
    auth=new.get('auth',{}); olda=old.get('auth',{}); plain=auth.pop('password','') if isinstance(auth,dict) else ''
    if plain: auth['password_hash']=hash_password(plain)
    elif not auth.get('password_hash'): auth['password_hash']=olda.get('password_hash','')
    new['auth']=auth; save_settings(new); return {'ok':True,'settings':new}
@app.post('/api/test-client')
async def test_client_api(c:ClientModel):
    try:return await test_client(c.model_dump())
    except Exception as e: raise HTTPException(400,str(e))
@app.get('/api/browse')
async def browse(path:str='/data'):
    p=Path(path).resolve(strict=False)
    try:p.relative_to(BROWSE_ROOT)
    except ValueError: raise HTTPException(403,'Chemin hors de /data')
    if not p.exists() or not p.is_dir(): raise HTTPException(404,'Dossier introuvable')
    dirs=[]
    try:
        for x in sorted(p.iterdir(),key=lambda z:z.name.lower()):
            if x.is_dir(): dirs.append({'name':x.name,'path':str(x)})
    except PermissionError: raise HTTPException(403,'Accès refusé')
    parent=None if p==BROWSE_ROOT else str(p.parent if p.parent.is_relative_to(BROWSE_ROOT) else BROWSE_ROOT)
    return {'path':str(p),'parent':parent,'directories':dirs}
@app.get('/api/history')
async def history(days:int=30):
    con=db(); cutoff=time.time()-days*86400
    scans=[dict(r) for r in con.execute('SELECT * FROM scans ORDER BY ts DESC LIMIT 1000') if datetime.fromisoformat(r['ts']).timestamp()>=cutoff]
    dels=[dict(r) for r in con.execute('SELECT * FROM deletions ORDER BY ts DESC LIMIT 1000') if datetime.fromisoformat(r['ts']).timestamp()>=cutoff]; con.close(); return {'scans':scans,'deletions':dels}
@app.post('/api/notifications/test')
async def test_notify(): await notify('scan','Test Torrent Orphan Web','Les notifications fonctionnent.'); return {'ok':True}

async def scheduler():
    while True:
        await asyncio.sleep(60); cfg=load_settings(); a=cfg.get('automation',{})
        if not a.get('scan_enabled'): continue
        last=state.get('last_scan'); due=not last or (datetime.now(timezone.utc)-datetime.fromisoformat(last)).total_seconds()>=max(5,int(a.get('scan_interval_minutes',360)))*60
        if not due: continue
        try:
            await do_scan(True)
            if a.get('delete_enabled'):
                min_age=float(a.get('delete_min_age_hours',168))*3600; selected=set(a.get('client_ids') or []); now=time.time(); ids=[]
                for oid,x in state['orphans'].items():
                    if selected and x['client_id'] not in selected: continue
                    if now-datetime.fromisoformat(x['first_seen']).timestamp()>=min_age: ids.append(oid)
                if ids: await delete_ids(ids,True)
        except Exception: pass
@app.on_event('startup')
async def startup(): db().close(); asyncio.create_task(scheduler())

if __name__=='__main__':
    import uvicorn; uvicorn.run('app.main:app',host='0.0.0.0',port=8080,reload=False)
