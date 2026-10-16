#!/usr/bin/env python3
"""Offline isolated emulation of APK machine-code fragments, never Android/Go startup.
Unicorn comes from an existing local cache. OS/runtime callees are stopped or
explicitly modeled, with all such boundaries recorded. No network/syscalls.
"""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
import hashlib,io,json,random,struct,sys
from pathlib import Path
try:import unicorn
except ImportError:
    candidates=list((Path.home()/'.cache/uv/archive-v0').glob('*/unicorn/__init__.py'))
    if not candidates:raise SystemExit('Local Unicorn package required; this script does not download anything.')
    sys.path.insert(0,str(candidates[0].parents[1]));import unicorn
from unicorn import Uc,UcError,UC_ARCH_ARM64,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from elftools.elf.elffile import ELFFile

OUT=Path(__file__).resolve().parent
APP=_public_app_root()
DATA=0x800000;STACK=0x908000;STOP=0xa00000;CALLBACK=0xa01000;CGO=0xa02000
RESULT={'scope':'Original APK instruction fragments emulated in Unicorn; modeled external/runtime call boundaries, no full target execution',
        'unicorn_version':unicorn.__version__,'unicorn_module':unicorn.__file__,'original_source_recovered':False,
        'syscalls_executed':False,'business_server_contacted':False,'bytealg':{},'runtime':[]}

def check(value,msg):
    if not value:raise AssertionError(msg)

class Machine:
    def __init__(self,abi):
        self.abi=abi;self.width=8 if abi=='arm64-v8a' else 4
        self.lib=APP/'unpacked/lib'/abi/'librsa_bridge.so';self.blob=self.lib.read_bytes();elf=ELFFile(io.BytesIO(self.blob))
        self.uc=Uc(UC_ARCH_ARM64 if self.width==8 else UC_ARCH_ARM,UC_MODE_ARM)
        # Page zero deliberately unmapped, matching the tested Android fault boundary.
        self.uc.mem_map(0x1000,0x5ff000);self.uc.mem_map(DATA,0x50000);self.uc.mem_map(0x900000,0x20000);self.uc.mem_map(STOP,0x10000)
        for seg in elf.iter_segments():
            if seg['p_type']=='PT_LOAD':
                start=seg['p_vaddr'];skip=max(0,0x1000-start);raw=seg.data()[skip:]
                if raw:self.uc.mem_write(start+skip,raw)
        if self.width==8:
            self.sp=UC_ARM64_REG_SP;self.lr=UC_ARM64_REG_LR;self.pc=UC_ARM64_REG_PC
            self.uc.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
        else:self.sp=UC_ARM_REG_SP;self.lr=UC_ARM_REG_LR;self.pc=UC_ARM_REG_PC
        self.coverage=set();self.uc.hook_add(UC_HOOK_BLOCK,lambda u,a,s,d:self.coverage.add(a))
    def write(self,a,value,width=None):self.uc.mem_write(a,int(value%(1<<(8*(width or self.width)))).to_bytes(width or self.width,'little'))
    def read(self,a,width=None):return int.from_bytes(self.uc.mem_read(a,width or self.width),'little')
    def run(self,entry,limit=300000):
        self.uc.reg_write(self.sp,STACK);self.uc.reg_write(self.lr,STOP)
        self.uc.emu_start(entry,STOP,count=limit)
        check(self.uc.reg_read(self.pc)==STOP,'Emulation did not return to bounded sentinel')

def bytealg():
    rng=random.Random(0x584353);lengths=[0,1,2,15,16,17,31,32,33,63,64,65,127,128,129,255,256,257,1023]
    cases=[]
    for align in range(32):
        for n in lengths:
            byte=(align*7+n)%256;other=(byte+1)%256
            absent=bytes([other])*n;all_match=bytes([byte])*n
            variants=[absent,all_match,bytes(rng.randrange(256) for _ in range(n))]
            if n:
                for pos in (0,n//2,n-1):variants.append(absent[:pos]+bytes([byte])+absent[pos+1:])
            for data in variants:cases.append((align,byte,data))
    for byte in range(256):cases.append((byte%32,byte,bytes(range(256))))
    for abi,entries in [('arm64-v8a',[0x5af40,0x5b400,0x5b420]),('armeabi-v7a',[0x200d4,0x20214,0x20228])]:
        m=Machine(abi);w=m.width;count=0;fingerprint=hashlib.sha256()
        for align,byte,data in cases:
            # Matching bytes before/after the intended slice expose masking errors.
            pointer=DATA+0x8000+align;m.uc.mem_write(DATA+0x8000,bytes([byte])*4096)
            if data:m.uc.mem_write(pointer,data)
            for kind,entry in enumerate(entries):
                m.write(STACK+w,pointer);m.write(STACK+2*w,len(data))
                if kind==1:m.write(STACK+3*w,len(data));m.write(STACK+4*w,byte,1);result=STACK+5*w
                else:m.write(STACK+3*w,byte,1);result=STACK+4*w
                m.write(result,0xabababab);m.run(entry)
                value=m.read(result);value=value-(1<<(8*w)) if value>>(8*w-1) else value
                expected=data.count(byte) if kind==0 else data.find(bytes([byte]))
                check(value==expected,f'{abi} {hex(entry)} alignment={align} length={len(data)} byte={byte}: {value}!={expected}')
                fingerprint.update(struct.pack('<IIIIq',kind,align,len(data),byte,value));count+=1
        # Empty string/slice must not dereference a null data pointer.
        for kind,entry in enumerate(entries):
            m.write(STACK+w,0);m.write(STACK+2*w,0)
            byte_slot=STACK+(4 if kind==1 else 3)*w;result=byte_slot+w;m.write(byte_slot,0x41,1);m.run(entry)
            check(m.read(result)==(0 if kind==0 else (1<<(w*8))-1),'empty null-pointer behavior')
        RESULT['bytealg'][abi]={'status':'PASS','cases':count+3,'dataset_inputs':len(cases),'alignments':list(range(32)),
          'lengths':lengths,'all_256_target_bytes':True,'oracle':'Python bytes.count / bytes.find',
          'result_fingerprint_sha256':fingerprint.hexdigest(),'executed_basic_block_starts':[hex(a) for a in sorted(m.coverage)],
          'library_sha256':hashlib.sha256(m.blob).hexdigest()}
        print(abi+': '+str(count+3)+' original-machine-code bytealg cases PASS',flush=True)

def runtime_case(name,entry,setup,stop_at=(),return_stubs=(),expected_fault=None,validate=lambda m,t:None):
    m=Machine('arm64-v8a');trace=[];m.uc.mem_write(CALLBACK,bytes.fromhex('c0035fd6'))
    # Keep real save_g's iscgo-dependent TLS write disabled unless explicitly set.
    m.write(0x3e7d80,0,1);m.uc.reg_write(m.sp,STACK);m.uc.reg_write(m.lr,STOP)
    m.uc.reg_write(UC_ARM64_REG_X29,0x909abc);m.uc.reg_write(UC_ARM64_REG_X3,0x123456);m.uc.reg_write(UC_ARM64_REG_X26,0x778899)
    setup(m)
    body_ranges=[(0xbd980,0xbda70),(0xbdb30,0xbdc70),(0xc00f0,0xc0100),(0xbd310,0xbd350),(0xc17f0,0xc1810),(CALLBACK,CALLBACK+4)]
    observable=set(stop_at)|set(return_stubs)|{CALLBACK,0xc17f0,0xbd310}
    def hook(u,address,size,data):
        if address in observable:
            snapshot={'pc':hex(address),'sp':hex(u.reg_read(m.sp)),'lr':hex(u.reg_read(m.lr)),
              'g':hex(u.reg_read(UC_ARM64_REG_X28)),'context':hex(u.reg_read(UC_ARM64_REG_X26)),
              'r0':hex(u.reg_read(UC_ARM64_REG_X0)),'r1':hex(u.reg_read(UC_ARM64_REG_X1)),
              'r2':hex(u.reg_read(UC_ARM64_REG_X2)),'r3':hex(u.reg_read(UC_ARM64_REG_X3))}
            trace.append(snapshot)
        if address in stop_at:u.emu_stop();return
        if address in return_stubs:
            if address==CGO:m.write(0x410f60,0x805000) # modeled cgo_init may replace stack low
            u.reg_write(m.pc,u.reg_read(m.lr));return
        check(address==STOP or any(a<=address<b for a,b in body_ranges),'Unexpected external execution: '+hex(address))
    m.uc.hook_add(UC_HOOK_CODE,hook)
    fault=None
    try:m.uc.emu_start(entry,STOP,count=2000)
    except UcError as e:fault={'pc':hex(m.uc.reg_read(m.pc)),'error':str(e)}
    if expected_fault is not None:check(fault is not None and int(fault['pc'],16)==expected_fault,'Expected bounded fault at '+hex(expected_fault)+': '+repr(fault))
    else:
        check(fault is None,'Unexpected fault '+repr(fault))
        check(m.uc.reg_read(m.pc) in (STOP,*stop_at),'Instruction budget reached instead of an expected return/stop')
    validate(m,trace)
    RESULT['runtime'].append({'name':name,'entry':hex(entry),'status':'PASS','trace':trace,'fault':fault,
       'stop_boundaries':[hex(x) for x in stop_at],'modeled_returning_callees':[hex(x) for x in return_stubs],
       'executed_basic_block_starts':[hex(a) for a in sorted(m.coverage)]})

G=DATA+0x1000;G0=DATA+0x2000;GS=DATA+0x3000;M=DATA+0x4000;F=DATA+0x5000;G0SP=0x915000
def setup_g(m,current=G):
    for ptr in (G,G0,GS):m.write(ptr+0x30,M)
    m.write(M,G0);m.write(M+0x50,GS);m.write(M+0xc0,G)
    m.write(G0+0x38,G0SP);m.write(G0+0x68,0x914ff8);m.write(F,CALLBACK)
    m.write(STACK+8,F);m.uc.reg_write(UC_ARM64_REG_X28,current)
    m.write(G+0x50,0)

def runtime():
    def check_direct(m,t):
        calls=[x for x in t if int(x['pc'],16)==CALLBACK];check(len(calls)==1,'one function-value tail call')
        check(int(calls[0]['sp'],16)==STACK and int(calls[0]['lr'],16)==STOP,'direct tail call restores caller stack/link')
    for label,current in [('g0',G0),('gsignal',GS)]:runtime_case('systemstack direct '+label,0xbdb30,lambda m,c=current:setup_g(m,c),validate=check_direct)
    def check_switch(m,t):
        calls=[x for x in t if int(x['pc'],16)==CALLBACK];check(len(calls)==1,'one switched callback')
        check(int(calls[0]['g'],16)==G0 and int(calls[0]['sp'],16)==G0SP,'callback executes with g0 stack')
        check(m.uc.reg_read(UC_ARM64_REG_X28)==G and m.uc.reg_read(m.sp)==STACK,'restored curg and stack')
        check(m.read(G+0x38)==0 and m.read(G+0x68)==0,'saved SP/BP cleared after return')
    runtime_case('systemstack current-g switch and restore',0xbdb30,setup_g,validate=check_switch)
    def nonzero_context(m):setup_g(m);m.write(G+0x50,1)
    runtime_case('systemstack rejects nonzero saved context',0xbdb30,nonzero_context,expected_fault=0xc00f4)
    def tls_setup(m):
        setup_g(m);m.write(0x3e7d80,1,1);m.write(0x3e7ee0,0x30)
        m.uc.reg_write(UC_ARM64_REG_TPIDR_EL0,DATA+0x7000)
    def tls_check(m,t):
        check_switch(m,t);check(m.read(DATA+0x7030)==G,'save_g restored curg into modeled TLS slot')
    runtime_case('systemstack restores current-g TLS when iscgo is set',0xbdb30,tls_setup,validate=tls_check)
    def invalid(m):setup_g(m);m.write(M+0xc0,G+0x100)
    runtime_case('systemstack invalid g calls failure then abort',0xbdb30,invalid,return_stubs=(0xc1f30,),expected_fault=0xc00f4)
    def check_morestack(m,t,context):
        check(m.read(G+0x38)==STACK and m.read(G+0x68)==0x909abc,'saved SP/BP')
        check(m.read(G+0x40)==STOP and m.read(G+0x60)==0x123456 and m.read(G+0x50)==context,'saved resume PC/caller LR/context')
        check(m.read(M+8)==STACK and m.read(M+16)==0x123456 and m.read(M+24)==G,'m.morebuf saved')
        check(m.uc.reg_read(UC_ARM64_REG_X28)==G0 and m.uc.reg_read(m.sp)==G0SP-16 and m.read(G0SP-16)==0,'newstack entered on g0 dummy frame')
    runtime_case('morestack saves caller and transfers to newstack',0xbdbe0,setup_g,stop_at=(0xc1f10,),validate=lambda m,t:check_morestack(m,t,0x778899))
    runtime_case('morestack_noctxt zeros closure context',0xbdc60,setup_g,stop_at=(0xc1f10,),validate=lambda m,t:check_morestack(m,t,0))
    def morestack_tls_check(m,t):
        check_morestack(m,t,0x778899);check(m.read(DATA+0x7030)==G0,'save_g publishes g0 to modeled TLS before newstack')
    runtime_case('morestack publishes g0 TLS when iscgo is set',0xbdbe0,tls_setup,stop_at=(0xc1f10,),validate=morestack_tls_check)
    for label,current,stub in [('g0',G0,0xc1e40),('gsignal',GS,0xc1e50)]:
        runtime_case('morestack rejects '+label,0xbdbe0,lambda m,c=current:setup_g(m,c),return_stubs=(stub,),expected_fault=0xc00f4)
    runtime_case('morestack nonreturn sentinel if modeled newstack returns',0xbdbe0,setup_g,return_stubs=(0xc1f10,),expected_fault=0xbdc50)
    runtime_case('abort deliberate null read',0xc00f0,lambda m:None,expected_fault=0xc00f4)
    helpers=(0xc1f00,0xc1ed0,0xc1db0,0xc1e60,0xc1eb0)
    def startup(m,cgo=False):
        m.uc.reg_write(UC_ARM64_REG_X0,2);m.uc.reg_write(UC_ARM64_REG_X1,DATA+0x6000)
        m.write(0x3e01d8,CGO if cgo else 0)
        m.uc.reg_write(UC_ARM64_REG_TPIDR_EL0,DATA+0x7000)
    def startup_check(m,t,cgo=False):
        check(m.read(0x4113c0)==0x410f60 and m.read(0x410f60+0x30)==0x4113c0,'m0/g0 links')
        low=0x805000 if cgo else STACK-48-65536
        check(m.read(0x410f60)==low and m.read(0x410f60+0x10)==low+0x3a0 and m.read(0x410f60+0x18)==low+0x3a0,'startup stack and guards')
        calls=[int(x['pc'],16) for x in t]
        expected=([CGO] if cgo else [])+[0xc17f0,*helpers,0xbda80]
        check(calls==expected,'startup call sequence '+repr(calls))
        if cgo:
            x=t[0];check(int(x['r0'],16)==0x410f60 and int(x['r1'],16)==0xbd350 and int(x['r2'],16)==0x3e7ee0 and int(x['r3'],16)==DATA+0x7000,'Android cgo_init ABI arguments')
    for cgo in (False,True):
        runtime_case('rt0_go initialization '+('with modeled cgo_init' if cgo else 'without cgo_init'),0xbd980,lambda m,c=cgo:startup(m,c),
          stop_at=(0xbda80,),return_stubs=helpers+((CGO,) if cgo else ()),validate=lambda m,t,c=cgo:startup_check(m,t,c))
    runtime_case('rt0_go traps if modeled mstart returns',0xbd980,startup,return_stubs=helpers+(0xbda80,),expected_fault=0xbda5c)
    print(str(len(RESULT['runtime']))+' original-machine-code runtime boundary cases PASS',flush=True)

if __name__=='__main__':
    failure=None
    try:bytealg();runtime()
    except Exception as e:failure=repr(e)
    RESULT['status']='PASS' if failure is None else 'FAIL';RESULT['error']=failure
    RESULT['script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (OUT/'emulation_verification.json').write_text(json.dumps(RESULT,ensure_ascii=False,indent=2)+'\n')
    if failure:raise SystemExit(failure)
