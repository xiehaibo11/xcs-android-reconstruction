#!/usr/bin/env python3
"""Real loopback-only TCP tests for the reconstructed Java WebSocket transport.
No APK, original native code, business host, credentials, or Internet is used.
"""
import base64
import hashlib
import json
from pathlib import Path
import queue
import socket
import struct
import subprocess
import threading
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'app/src/main/java/com/re/xcs/rebuild'
CLASSES=ROOT/'build/transport-tests'
RESULTS=[]
TRANSCRIPT=[]

def expect(condition, why):
    if not condition: raise AssertionError(why)

def exact(sock, n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part:raise EOFError('Socket closed')
        data+=part
    return data

def handshake(sock, bad=False):
    request=b''
    while not request.endswith(b'\r\n\r\n'):
        request+=exact(sock,1)
        expect(len(request)<32768,'bounded upgrade request')
    lines=request.decode('ascii').split('\r\n');headers=dict(line.split(': ',1) for line in lines[1:] if ': ' in line)
    expect(lines[0].startswith('GET /'),'HTTP GET upgrade')
    expect(headers['Sec-WebSocket-Version']=='13','version 13')
    expect(len(base64.b64decode(headers['Sec-WebSocket-Key']))==16,'16 byte nonce')
    accept=base64.b64encode(hashlib.sha1((headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
    if bad:accept='wrong-accept'
    sock.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n').encode())

def frame(sock, payload, opcode=1, fin=True):
    if isinstance(payload,str):payload=payload.encode()
    size=len(payload);header=bytes([(128 if fin else 0)|opcode])
    header+=bytes([size]) if size<126 else bytes([126])+struct.pack('!H',size) if size<65536 else bytes([127])+struct.pack('!Q',size)
    sock.sendall(header+payload)

def read_frame(sock, timeout=5):
    sock.settimeout(timeout);a,b=exact(sock,2);size=b&127
    expect(bool(b&128),'all client frames must be masked')
    if size==126:size=struct.unpack('!H',exact(sock,2))[0]
    elif size==127:size=struct.unpack('!Q',exact(sock,8))[0]
    mask=exact(sock,4);data=exact(sock,size)
    return a&15,bytes(value^mask[i%4] for i,value in enumerate(data))

def packet(sock, obj):frame(sock,json.dumps(obj,ensure_ascii=False,separators=(',',':')))
def read_packet(sock,timeout=5):
    opcode,data=read_frame(sock,timeout);expect(opcode==1,'protocol packet is text');obj=json.loads(data)
    TRANSCRIPT.append({'direction':'client_to_local_peer','at_monotonic':time.monotonic(),'packet':obj})
    return obj

def listener(port=0):
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',port));s.listen();s.settimeout(6);return s

class Probe:
    def __init__(self, *args):
        self.p=subprocess.Popen(['java','-cp',str(CLASSES),'com.re.xcs.rebuild.net.WsNetworkProbe',*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.events=[];self.incoming=queue.Queue()
        self.ending=False
        def read():
            for line in self.p.stdout:
                item=json.loads(line);self.events.append(item);self.incoming.put(item)
        self.reader=threading.Thread(target=read,daemon=True);self.reader.start()
    def command(self, cmd):
        self.p.stdin.write(cmd+'\n');self.p.stdin.flush()
        if cmd in ('close','logout'):self.ending=True
    def event(self, name, predicate=lambda x:True, timeout=6):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:item=self.incoming.get(timeout=max(.01,end-time.monotonic()))
            except queue.Empty:break
            if item['event']==name and predicate(item):return item
        raise AssertionError('Missing event '+name+'; events='+repr(self.events))
    def finish(self):
        if self.p.poll() is None and not self.ending:self.command('close')
        self.p.wait(timeout=6);self.reader.join(timeout=1)
        errors=self.p.stderr.read();expect(self.p.returncode==0,'Java probe failure: '+errors)
        TRANSCRIPT.append({'probe_events':self.events,'stderr':errors})
    def kill(self):
        if self.p.poll() is None:self.p.kill();self.p.wait()

def case(name, body):
    start=time.monotonic()
    try:body()
    except Exception as e:
        RESULTS.append({'name':name,'status':'FAIL','seconds':time.monotonic()-start,'error':str(e)});raise
    RESULTS.append({'name':name,'status':'PASS','seconds':time.monotonic()-start});print(name+': PASS',flush=True)

def wire_normal():
    with listener() as server:
        probe=Probe('wire','ws://127.0.0.1:'+str(server.getsockname()[1])+'/frames?q=1','normal')
        try:
            conn,_=server.accept()
            with conn:
                handshake(conn)
                expect(read_frame(conn)==(1,b'c'*126),'126-byte client frame')
                expect(read_frame(conn)==(1,b'L'*65536),'65536-byte client frame')
                encoded='识别完整'.encode();frame(conn,encoded[:2],fin=False);frame(conn,b'ping-payload',9);frame(conn,encoded[2:],0)
                expect(read_frame(conn)==(10,b'ping-payload'),'ping interleaved in fragmented text produces identical pong')
                frame(conn,b'R'*65536);frame(conn,struct.pack('!H',1000)+b'done',8)
                expect(read_frame(conn)==(8,struct.pack('!H',1000)+b'done'),'valid close echoed')
            probe.event('wire_pass');probe.finish()
        finally:probe.kill()

def wire_reject(name, payload=None, bad_handshake=False):
    with listener() as server:
        probe=Probe('wire','ws://127.0.0.1:'+str(server.getsockname()[1])+'/',name)
        try:
            conn,_=server.accept()
            with conn:
                handshake(conn,bad_handshake)
                if payload is not None:conn.sendall(payload)
                probe.event('wire_rejected')
            probe.finish()
        finally:probe.kill()

def auth(conn, code=0, qos=False):
    packet(conn,{'types':50,'data_content':json.dumps({'code':code,'user_id':'local-user','data':''}), 'qos':qos,'fp':'auth-fp','from':'server','to':'client'})

def connect_session(server, probe):
    conn,_=server.accept();handshake(conn);login=read_packet(conn)
    expect(login['types']==6 and login['data_content']=='local-test-token' and login['qos'] is False,'token login packet')
    expect(len(login['fp'])==36,'login UUID fingerprint');return conn

def auth_qos_reconnect():
    with listener() as server:
        probe=Probe('session',str(server.getsockname()[1]))
        try:
            with connect_session(server,probe) as conn:
                packet(conn,{'types':50,'data_content':'{"code":0}'})
                probe.event('error',lambda x:'无效认证响应' in x['detail'])
                auth(conn,qos=True);ack=read_packet(conn);hb=read_packet(conn)
                expect(ack['types']==4 and ack['data_content']=='auth-fp' and ack['from']=='client' and ack['to']=='server','QoS authentication ACK route')
                expect(hb['types']==1 and hb['data_content']=='💓','immediate authenticated heartbeat')
                packet(conn,{'types':51})
                business={'types':2,'qos':True,'fp':'same-message','from':'device','to':'client','data_content':'{"msg_type":117,"msg_content":"serial|unknown"}'}
                packet(conn,business);packet(conn,business)
                for _ in range(2):
                    ack=read_packet(conn);expect(ack['types']==4 and ack['data_content']=='same-message','duplicates ACKed')
                probe.event('business');packet(conn,{'types':2,'data_content':'{"msg_type":"not-an-integer"}'})
                probe.event('error',lambda x:'业务消息解析失败' in x['detail'])
                probe.command('repeat_start');probe.event('repeat_start_rejected')
                probe.command('stale_reader');probe.event('stale_reader_ignored')
                probe.command('status');state=probe.event('status')
                expect(state['connected'] and state['authenticated'] and state['business_count']==1,'duplicate suppressed and malformed business preserves transport')
            # Dropped TCP starts an immediate reconnect; connection retains original separate auth flag.
            with connect_session(server,probe) as conn:
                started=time.monotonic();repeat=read_packet(conn,4)
                expect(repeat['types']==6 and repeat['data_content']=='local-test-token','retry sends authentication again while connected but unconfirmed')
                expect(2<=time.monotonic()-started<=4,'3 second reconnect authentication retry')
                auth(conn,code=401,qos=True)
                probe.event('state',lambda x:'认证被拒绝' in x['detail'] and not x['connected'] and x['authenticated'])
                conn.settimeout(2);expect(conn.recv(1)==b'','nonzero auth is not ACKed and closes transport')
            server.settimeout(3.5)
            try:unexpected,_=server.accept();unexpected.close();raise AssertionError('Rejected reconnect kept retrying')
            except socket.timeout:pass
            probe.finish()
        finally:probe.kill()

def server_stop():
    with listener() as server:
        probe=Probe('session',str(server.getsockname()[1]))
        try:
            with connect_session(server,probe) as conn:
                auth(conn);expect(read_packet(conn)['types']==1,'heartbeat before server stop');packet(conn,{'types':54})
                probe.event('state',lambda x:not x['connected'] and not x['authenticated'] and '结束会话' in x['detail'])
                conn.settimeout(2);expect(conn.recv(1)==b'','server stop closes transport')
            server.settimeout(3.5)
            try:unexpected,_=server.accept();unexpected.close();raise AssertionError('Server stop reconnected')
            except socket.timeout:pass
            probe.finish()
        finally:probe.kill()

def heartbeat_timeout():
    with listener() as server:
        probe=Probe('session',str(server.getsockname()[1]))
        try:
            with connect_session(server,probe) as conn:
                auth(conn);first=read_packet(conn);started=time.monotonic()
                expect(first['types']==1,'first heartbeat')
                # Delay ACK enough to prove the receive timestamp refreshes timeout.
                time.sleep(4);packet(conn,{'types':51});acked=time.monotonic()
                second=read_packet(conn,34);second_at=time.monotonic()
                expect(second['types']==1 and second['data_content']=='💓','second application heartbeat')
                expect(27<=second_at-started<=33,'30 second production heartbeat interval')
                probe.event('state',lambda x:'心跳超时' in x['detail'],timeout=14)
                elapsed=time.monotonic()-started
                expect(38<=elapsed<=44 and time.monotonic()-acked>=34,'types=51 refreshes 35 second expiry with 2 second checker')
            with connect_session(server,probe) as conn:
                auth(conn);expect(read_packet(conn)['types']==1,'reconnect auth restarts heartbeat')
                probe.command('logout');logout=read_packet(conn)
                expect(logout['types']==3 and logout['qos'] is False,'logout packet')
                probe.event('state',lambda x:not x['connected'] and not x['authenticated'] and '退出' in x['detail'])
            probe.finish()
            TRANSCRIPT.append({'real_heartbeat_interval_seconds':second_at-started,'real_timeout_seconds':elapsed})
        finally:probe.kill()

def main():
    CLASSES.mkdir(parents=True,exist_ok=True)
    sources=[SOURCE/'core'/name for name in ('JsonCodec.java','Models.java','DartConversions.java','DartIntegers.java','DartDateTime.java','ApiContract.java')]
    sources += [SOURCE/'net/WsWire.java',SOURCE/'net/WsSession.java',HERE/'WsNetworkProbe.java']
    subprocess.run(['javac','-encoding','UTF-8','-d',str(CLASSES),*[str(x) for x in sources]],check=True)
    case('masked client frames, large lengths, fragmented UTF-8, interleaved ping/pong, close handshake',wire_normal)
    bad={
        'masked server frame':b'\x81\x80',
        'server RSV bit':b'\xc1\x00',
        'nonminimal length':b'\x81\x7e\x00\x01x',
        'orphan continuation':b'\x80\x01x',
        'binary message unsupported':b'\x82\x01x',
        'invalid UTF-8':b'\x81\x02\xc3\x28',
        'fragmented control':b'\x09\x00',
        'one-byte close':b'\x88\x01x',
        'reserved close status':b'\x88\x02'+struct.pack('!H',1005),
    }
    for name,payload in bad.items():case(name,lambda n=name,p=payload:wire_reject(n,p))
    case('invalid upgrade accept',lambda:wire_reject('invalid accept',bad_handshake=True))
    case('auth, QoS duplicate ACK/dedupe, malformed business, stale-reader guard, TCP reconnect, auth rejection stop',auth_qos_reconnect)
    case('server types=54 stops session and reconnect',server_stop)
    case('production 30-second heartbeat, 35-second timeout, reconnect, logout',heartbeat_timeout)

if __name__=='__main__':
    error=None
    try:main()
    except Exception as exc:error=repr(exc)
    report={'status':'PASS' if error is None else 'FAIL','error':error,'tests':RESULTS,'transcript':TRANSCRIPT,
            'scope':'Host Java reconstruction over real TCP sockets bound only to 127.0.0.1; no original target binary or business server',
            'rust_concurrency_equivalent':False,'original_source_recovered':False,
            'source_sha256':{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in [SOURCE/'net/WsWire.java',SOURCE/'net/WsSession.java',*[SOURCE/'core'/name for name in ('JsonCodec.java','Models.java','DartConversions.java','DartIntegers.java','DartDateTime.java','ApiContract.java')],HERE/'WsNetworkProbe.java',Path(__file__).resolve()]}}
    (HERE/'network_verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    if error:raise SystemExit(error)
    print('All '+str(len(RESULTS))+' loopback transport scenarios passed.',flush=True)
