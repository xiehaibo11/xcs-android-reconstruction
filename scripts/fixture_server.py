#!/usr/bin/env python3
"""Loopback-only synthetic contract server. No production accounts or servers.
Use adb reverse tcp:8081 tcp:8081 and tcp:18889 tcp:18889 in isolated emulator.
"""
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import base64,hashlib,json,socketserver,struct,threading,time,io
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image
from prepare_dev_assets import prepare

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'runtime';OUT.mkdir(exist_ok=True)
state={'synthetic':True,'requests':[],'ws_logins':0,'heartbeats':0,'uploads':[],'preview_starts':0,'preview_ends':0,'end_status':200,'late_preview_frames_sent':0}
lock=threading.RLock();clients=[]
prepare()
public=serialization.load_pem_public_key((ROOT/'app/src/main/assets/key/pub_key.pem').read_bytes())
encrypted=base64.b64encode(public.encrypt(json.dumps(['127.0.0.1','~,~'],separators=(',',':')).encode(),padding.PKCS1v15())).decode()
img=Image.new('RGB',(64,64),(35,120,150));buf=io.BytesIO();img.save(buf,'JPEG');jpeg=base64.b64encode(buf.getvalue()).decode()
late_img=Image.new('RGB',(64,64),(80,160,40));late_buf=io.BytesIO();late_img.save(late_buf,'JPEG');late_jpeg=base64.b64encode(late_buf.getvalue()).decode()
device={'id':7,'user_id':1,'create_time':'2026-10-14T00:00:00Z','direction':1,'mj_count':4,'serial_no':'1001','online':1,'version':1.0,'left':0.0,'top':0.0,'right':32.0,'bottom':32.0,'motor':3000,'delay':0.0,'lighting_switch':0,**{k:1 for k in ['cap_brightness','cap_exposure','cap_hue','cap_saturation','cap_contrast','cap_gain','img_rotation','img_min_hreshold','cap_fps','beta','img_add_num','gk_min','gk_max']}}
def save():
 with lock:(OUT/'fixture-observations.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n')
def packet(t,data='',**kwargs):
 p={'types':t,'qos':False,**kwargs}
 if data:p['data_content']=data
 return json.dumps(p,ensure_ascii=False,separators=(',',':'))
def business(t,content):return packet(2,json.dumps({'msg_type':t,'msg_content':content},ensure_ascii=False,separators=(',',':')))
class Http(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):self.handle_request()
 def do_POST(self):self.handle_request()
 def handle_request(self):
  body=self.rfile.read(int(self.headers.get('Content-Length',0)))
  data=json.loads(body) if body else None
  path=self.path.split('?')[0]
  with lock:
   if not path.startswith('/__fixture/'):
    state['requests'].append({'method':self.command,'path':self.path,'json':data,'headers':{k:self.headers.get(k) for k in ['clienttype','clientversion','Authorization','deviceId']}})
  status=200;result={'success':True}
  if path=='/__fixture/reset':
   with lock:
    state.update(requests=[],ws_logins=0,heartbeats=0,uploads=[],preview_starts=0,preview_ends=0,end_status=200,late_preview_frames_sent=0)
   result={'synthetic':True,'reset':True}
  elif path=='/__fixture/status':result=state
  elif path=='/__fixture/end_failure':
   with lock:state['end_status']=500
   result={'synthetic':True}
  elif path=='/api/login/login/distinguish':
   if data!={'username':'fixture-user','password':'fixture-password','devicetype':1}:result={'success':False,'msg':'Synthetic fixture credentials required'}
   else:result={'success':True,'jwt':'fixture-only-token','loginUser':{'id':1,'username':'fixture-user','token':'fixture-inner','timeout':60,'delay':5,'data_send':1},'devices':[device]}
  elif path=='/api/server/get_server_addr':result={'success':True,'msg':encrypted}
  elif path=='/api/app/check_update':result={'success':False,'msg':'No synthetic update'}
  elif path=='/api/mj/get_config':result={'success':True,'list':[{'id':1,'number':1,'name':'合成测试牌','url':'images/other/empty.jpg'}]}
  elif path=='/api/zhuo/device_status_all':result={'success':True,'data':[device]}
  elif path=='/api/config/get_config':result={'success':True,'data':{'config_number':{'east':4,'south':0,'west':0,'north':0},'data_config':{'data_send':1,'timeout':60,'delay':5,'count_type':1,'upload_img_clarity':1},'wifi_config':{'ssid':'fixture-wifi','pwd':'fixture-password'},'lighting_config':{}}}
  elif path=='/api/config/get_default_wifi':result={'success':True,'data':{'ssid':'fixture-wifi','pwd':'fixture-password'}}
  elif path=='/api/config/get_device_wifi_list':result={'success':True,'data':'-40dBm|fixture-wifi'}
  elif path=='/fixture-image':
   raw=jpeg.encode();self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);save();return
  elif path=='/api/zhuo/start_games':threading.Thread(target=self.emit_round,daemon=True).start()
  elif path=='/api/zhuo/add':
   with lock:state['uploads'].append(data)
  elif path.startswith('/api/preview/start_preview/'):
   with lock:state['preview_starts']+=1
   threading.Thread(target=self.emit_preview,daemon=True).start()
  elif path.startswith('/api/preview/end_preview/'):
   with lock:state['preview_ends']+=1;status=state['end_status']
   if status==500:
    result={'success':False,'msg':'Synthetic end failure'}
    threading.Thread(target=self.emit_late_preview,daemon=True).start()
  elif not(path.startswith('/api/')or path=='/account/edit/pwd'):status=404;result={'success':False,'msg':'Unknown synthetic route'}
  raw=json.dumps(result,ensure_ascii=False,separators=(',',':')).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);save()
 def emit_round(self):
  time.sleep(.3)
  with lock:targets=list(clients)
  for c in targets:
   try:
    c.send(business(113,None))
    for i in range(1,5):c.send(business(101,{'serial_number':'1001','mahjong_number':i,'img':'http://127.0.0.1:8081/fixture-image','ai_val':1,'ai_precision':0.9}));time.sleep(.1)
    c.send(business(114,'1001'))
   except OSError:pass
 def emit_preview(self):
  for i in range(5):
   time.sleep(.5)
   with lock:targets=list(clients)
   for c in targets:
    try:c.send(business(102,'7|'+jpeg))
    except OSError:pass
 def emit_late_preview(self):
  time.sleep(1.2)
  with lock:targets=list(clients)
  for c in targets:
   try:
    c.send(business(102,'7|'+late_jpeg))
    with lock:state['late_preview_frames_sent']+=1;state['late_preview_frame_sha256']=hashlib.sha256(late_jpeg.encode()).hexdigest()
   except OSError:pass
  save()
class Ws(socketserver.StreamRequestHandler):
 def send(self,text):
  b=text.encode();header=bytes([0x81,len(b)]) if len(b)<126 else bytes([0x81,126])+struct.pack('!H',len(b))
  with self.write_lock:self.wfile.write(header+b);self.wfile.flush()
 def exact(self,n):
  d=self.rfile.read(n)
  if len(d)!=n:raise EOFError()
  return d
 def handle(self):
  self.write_lock=threading.RLock()
  try:
   self.rfile.readline();headers={}
   while True:
    line=self.rfile.readline().decode().strip()
    if not line:break
    k,v=line.split(':',1);headers[k.lower()]=v.strip()
   accept=base64.b64encode(hashlib.sha1((headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
   self.wfile.write(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n').encode());self.wfile.flush()
   with lock:clients.append(self)
   while True:
    a,b=self.exact(2);n=b&127
    if n==126:n=struct.unpack('!H',self.exact(2))[0]
    elif n==127:n=struct.unpack('!Q',self.exact(8))[0]
    if not b&128:raise ValueError('Client must mask')
    mask=self.exact(4);raw=self.exact(n);raw=bytes(x^mask[i%4]for i,x in enumerate(raw))
    if a&15==8:break
    if a&15!=1:continue
    p=json.loads(raw)
    if p['types']==6:
     with lock:state['ws_logins']+=1
     self.send(packet(50,json.dumps({'code':0,'user_id':'fixture-user','data':''})))
    elif p['types']==1:
     with lock:state['heartbeats']+=1
     self.send(packet(51))
    elif p['types']==3:break
    save()
  except (EOFError,OSError,ValueError):pass
  finally:
   with lock:
    if self in clients:clients.remove(self)
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
if __name__=='__main__':
 save();ws=Server(('127.0.0.1',18889),Ws);threading.Thread(target=ws.serve_forever,daemon=True).start()
 print('Synthetic loopback fixture HTTP 8081 / WS 18889',flush=True)
 ThreadingHTTPServer(('127.0.0.1',8081),Http).serve_forever()
