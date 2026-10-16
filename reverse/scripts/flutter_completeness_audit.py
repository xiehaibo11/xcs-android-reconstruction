#!/usr/bin/env python3
"""Reproducible, read-only Dart AOT completeness audit. Never executes target code."""

from _paths import app_root, workspace_root
from pathlib import Path
import argparse, collections, hashlib, json, re, sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

APP = app_root()
OUT = APP / 'analysis/completeness_audit/flutter'
ASM = APP / 'analysis/aot_dump/asm/distinguish'
BINARY = APP / 'unpacked/lib/arm64-v8a/libapp.so'
INDEX = APP / 'analysis/aot_runtime/function_index.json'
SELF = Path(__file__).resolve()
ADDR = re.compile(r'(?<![\w])0x[0-9a-fA-F]+')
HEADER = re.compile(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)')
INSN = re.compile(r'\s*//\s+(0x[0-9a-f]+):\s+(.*)')

def sha(b): return hashlib.sha256(b).hexdigest()
def dump(p, x): p.write_text(json.dumps(x, ensure_ascii=False, indent=2)+'\n')
def rel(p): return str(p.relative_to(APP))
def pointer(p): return '/'+'/'.join(str(x).replace('~','~0').replace('/','~1') for x in p)

# Reviewed small chains, explicitly bounded to the behavior stated here.
SUPPLEMENT = [
 ('key_save_entry','口令保存按钮和传入TextFormField的String回调都调用 _onSave，丢弃其 Future；createState 构造文本控制器/FocusNode，build 绑定回调。String回调的具体框架触发事件未仅凭签名认定。',['0x564e54','0x564e9c','0x486edc','0x48c228','0x48db4c'],['0x48c254','0x48db78','0x487150','0x487224']),
 ('key_validation_navigation','_onSave 对原字符串长度为0提示请输入您的口令；等于6666提示请更换其他口令；其他字符串不trim，UTF8→MD5→Digest.toString→await save_config。widget+0xb=false 调 Get.back，true 调 offAll(LoginPage)，然后保存成功Toast；save_config 不await void async inletPwdDbWrite 的实际写盘。',['0x48c270','0x48c86c','0x48db34','0x48c8bc'],['0x48c2dc','0x48c2fc','0x48c358','0x48c368','0x48c370','0x48c388','0x48c3a0','0x48c3d4','0x48c414','0x48c420','0x48c8a8']),
 ('key_online_route','在线设置的口令入口 Get.to 构造 KeyFormPage，widget+0xb=true；该入口保存后重置到LoginPage。',['0x4af488','0x4af4f4'],['0x4af4d8','0x4af504']),
 ('update_model','AppUpdate.fromJson/toJson 精确字段为 type:int?+7、version:String?+b、update_url:String?+f、ota_url:String?+13；fromJson直接cast，不比较本地版本；包装toJson只转发。',['0x4928b8','0x492a98','0x492ac8'],['0x4928e4','0x49293c','0x49299c','0x4929f8','0x492a50','0x492a58','0x492a60','0x492a68','0x492b00','0x492b18','0x492b30','0x492b4c']),
 ('update_create_build','Update createState 将 double 进度+13设0.0；build 将该进度传FAProgressBar，始终加入升级中说明和手动下载按钮，未按OtaEvent.status隐藏或显示按钮。',['0x56598c','0x4b4658'],['0x5659a8','0x4b484c','0x4b4868','0x4b4968','0x4b4998','0x4b4a38']),
 ('update_ota_entry','Update.initState 执行 OtaUpdate.execute(widget.AppUpdate.ota_url??硬编码APK URL)，监听OtaEvent；listen返回订阅未保存State。init的同步异常路径调用EasyLoading.show含异常文本；不等同于处理异步stream错误。',['0x52c9d0'],['0x52ca28','0x52ca38','0x52ca40','0x52ca64','0x52caa4']),
 ('update_progress_event','onData52d00c→setState52d090，读取event+0xb(value)，null时0，再double.parse写state+0x13。页面没有读取status+7，任何可达非数字value可抛FormatException；监听未传本地onError/onDone。',['0x52d00c','0x52d090'],['0x52d074','0x52d0d0','0x52d0e4','0x52d0ec']),
 ('update_manual_download','手动下载回调读取 State.widget.AppUpdate.update_url??空字符串，Uri.parse后launchUrl，返回Future未await也不检查bool。这里使用update_url，与自动OTA的ota_url不同。',['0x4b505c'],['0x4b509c','0x4b50b4','0x4b50bc']),
 ('log_singleton','LogService.instance 读取静态0xcd8，null才创建并保存单例；_internal创建空RxList<Log>存+1b，并初始化Getx生命周期。',['0x4938ec','0x493948'],['0x493904','0x493920','0x493928','0x493988','0x493990']),
 ('log_append','addLogTextRed/Black 取getTimeStr()，插入全角冒号和空格后拼入调用参数；新建Log，+7=color，+b=文本，向RxList+1b append。Red颜色对象值0xfff44336，Black值0xff000000。这两个方法无文件或网络写入。',['0x493418','0x4af73c'],['0x493440','0x493460','0x4934a4','0x4934ac','0x4934b8','0x4af764','0x4af784','0x4af7c8','0x4af7d0','0x4af7dc']),
 ('log_timestamp','getTimeStr 用本地DateTime当前微秒获取_parts，顺序取数组索引8/7/5/4/3/2，以 /、/、空格、:、: 拼接；_numToStr 的未标记整数小于10补0，否则toString。未把_parts索引仅凭本方法升级成语义年/月字段。',['0x493500','0x493820'],['0x493530','0x49356c','0x4935d4','0x493648','0x4936bc','0x493730','0x4937a4','0x493838','0x493888']),
 ('user_exit_pwd_entry','用户菜单修改密码按钮经4aa1d8 Get.to(EditPwdPage)，退出按钮4a83b0先发起wsLogout Future再立即offAll(LoginPage)，不await注销结果；该退出回调不写Dart JWT，不删除本地登录配置。',['0x4a8140','0x4aa1d8','0x4a83b0'],['0x4a824c','0x4a82a4','0x4aa210','0x4aa21c','0x4a83c8','0x4a83fc'])
]

def category(m):
    p=m['source'];sig=m['signature']
    if '/model/' in p:
        return 'model_serialization' if 'fromJson' in sig or 'toJson' in sig else 'model_constructor_or_method'
    if '/src/rust/' in p:return 'generated_bridge_or_api'
    if '[closure]' in sig:return 'exported_closure_in_'+('page' if '/pages/' in p else 'widget' if '/widgets/' in p else 'service_or_common')
    if re.search(r'\bbuild\(',sig):return 'widget_build'
    if re.search(r'\b(?:createState|initState|dispose)\(',sig):return 'widget_lifecycle'
    if '/service/' in p:return 'service_method'
    return 'other_exported_method'
def walk(x, p=()):
    yield p, x
    if isinstance(x, dict):
        for k,v in x.items(): yield from walk(v,p+(k,))
    elif isinstance(x,list):
        for k,v in enumerate(x): yield from walk(v,p+(k,))

def load_methods():
    records=[]; files=[]
    for p in sorted(ASM.rglob('*.dart')):
        b=p.read_bytes(); ls=b.decode().splitlines(); cls='::'; file_methods=[]
        for i,l in enumerate(ls):
            cm=re.match(r'class (\S+)',l)
            if cm: cls=cm[1]
            m=HEADER.search(l)
            if not m: continue
            end=next(j for j in range(i+1,len(ls)) if ls[j]=='  }')
            body='\n'.join(ls[i-1:end+1])+'\n'
            addresses=sorted({int(z[1],16) for t in ls[i:end+1] if (z:=INSN.match(t))})
            a=int(m[1],16); ds=int(m[2],16); last=addresses[-1]+4
            records.append(dict(address=hex(a),declared_size=ds,exported_body_size=last-a,
                source=rel(p),source_sha256=sha(b),source_start_line=i,source_end_line=end+1,
                signature=ls[i-1].strip(),class_name=cls,body_sha256=sha(body.encode()),
                exported_address_holes=[hex(x) for x in range(a,last,4) if x not in addresses],
                declared_tail_not_in_this_body=[hex(x) for x in range(a,a+ds,4) if x not in addresses],
                _body=body,_lines=ls[i-1:end+1]))
            file_methods.append(hex(a))
        files.append(dict(source=rel(p),source_sha256=sha(b),method_count=len(file_methods),methods=file_methods))
    return records,files

def build():
    OUT.mkdir(parents=True,exist_ok=True); ev=OUT/'uncovered_methods'; ev.mkdir(exist_ok=True)
    raw=OUT/'raw_methods'; raw.mkdir(exist_ok=True)
    full=OUT/'complete_methods'; full.mkdir(exist_ok=True)
    methods,files=load_methods(); by={x['address']:x for x in methods}; idx=json.loads(INDEX.read_text())
    original=BINARY.read_bytes()
    with BINARY.open('rb') as f:
        elf=ELFFile(f); sections=[(int(s['sh_addr']),int(s['sh_size']),int(s['sh_offset']),s.name) for s in elf.iter_sections() if s['sh_type']!='SHT_NOBITS']
    def resolve(a,n=4):
        s=next(s for s in sections if s[0]<=a and a+n<=s[0]+s[1]); off=s[2]+a-s[0]
        return original[off:off+n],off,s[3]
    def owner(a):
        if hex(a) in by:return hex(a)
        return next((m['address'] for m in methods if int(m['address'],16)<=a<int(m['address'],16)+m['exported_body_size']),None)
    inputs={str(BINARY):sha(original),str(INDEX):sha(INDEX.read_bytes()),str(SELF):sha(SELF.read_bytes())}
    for f in files:inputs[str(APP/f['source'])]=f['source_sha256']
    all_json=[]; semantics=collections.defaultdict(list); refs=collections.defaultdict(list); snippet_refs=collections.defaultdict(list)
    excluded={'aot_dump','completeness_audit','native','deep_flutter','flutter','open_source'}
    for p in sorted((APP/'analysis').rglob('*.json')):
        if set(p.relative_to(APP).parts)&excluded:continue
        if p.name in ['function_index.json','direct_call_verification.json','analysis_status.json']:continue
        try:d=json.loads(p.read_text())
        except (ValueError,UnicodeError):continue
        inputs[str(p)]=sha(p.read_bytes());all_json.append(p)
        for jp,x in walk(d):
            if isinstance(x,str):
                for t in ADDR.findall(x):
                    h=hex(int(t,16))
                    if h in by:
                        refs[h].append(dict(artifact=rel(p),json_pointer=pointer(jp),kind='address_reference_only'))
            if not isinstance(x,dict):continue
            # Explicit, bounded claim associations. Never promote file-only metadata.
            claim=any(k in x for k in ['conclusion','statement']) and any(k in x for k in ['id','status','certainty'])
            endpoint='http_method' in x and ('path_template' in x or 'path' in x)
            msg='msg_type' in x and 'processing_order' in x
            login=p.name=='dart_login_evidence.json' and len(jp)==1 and 'excerpts' in x
            model=p.name=='payload_models.json' and ('fields' in x or 'item_fields' in x) and any(k in x for k in ['fromJson_address','evidence','service_address','source_address'])
            if not (claim or endpoint or msg or login or model):continue
            found=set()
            # Addresses listed explicitly as methods, or instruction evidence within this claim.
            for sp,z in walk(x):
                if not isinstance(z,str):continue
                key=str(sp[-1]) if sp else ''
                context='/'.join(str(t) for t in sp)
                allowed=key in ['address','function_address','elf_virtual_address','method_address','fromJson_address','source_address','service_address'] or any(k in context for k in ['method_evidence','methods','instruction_evidence','instruction_points']) or (model and 'evidence' in context)
                if not allowed:continue
                for t in ADDR.findall(z):
                    a=int(t,16); own=owner(a)
                    if own:found.add(own)
            for a in found:
                semantics[a].append(dict(artifact=rel(p),json_pointer=pointer(jp),
                    association='supports_explicit_partial_claim' if claim else 'endpoint_contract' if endpoint else 'message_dispatch_claim' if msg else 'explicit_partial_model_schema' if model else 'login_evidence_group',
                    claim_id=x.get('id',jp[-1] if jp else None),
                    summary=x.get('conclusion',x.get('statement',x.get('path_template',x.get('semantic_label',str(jp[-1]) if jp else ''))))))
    # Match complete excerpt text, not merely its header or source filename.
    for p in sorted((APP/'analysis').rglob('*')):
        if not p.is_file() or set(p.relative_to(APP).parts)&{'aot_dump','completeness_audit'} or p.suffix not in ['.txt','.dart','.asm']:continue
        if p.stat().st_size>12_000_000:continue
        try:txt=p.read_text()
        except UnicodeError:continue
        if '// ** addr:' not in txt:continue
        for h in set(t[0] for t in HEADER.findall(txt)):
            if h in by and by[h]['_body'] in txt:
                snippet_refs[h].append(dict(path=rel(p),sha256=sha(p.read_bytes()),match='exact_complete_method_source_text'))
                inputs[str(p)]=sha(p.read_bytes())
    prior_semantic_count=sum(bool(semantics[a]) for a in by)
    newclaims=[]
    for cid,conclusion,addresses,points in SUPPLEMENT:
        claim=dict(id=cid,conclusion=conclusion,certainty='confirmed_bounded_static_behavior',methods=addresses,instruction_evidence=[])
        for address in addresses:
            if address not in by:raise ValueError('supplement method absent '+address)
            semantics[address].append(dict(artifact=rel(OUT/'supplemental_flows.json'),json_pointer='/claims/'+str(len(newclaims)),association='new_bounded_partial_claim',claim_id=cid,summary=conclusion))
        for point in points:
            own=owner(int(point,16));m=by[own];li=next((i,l) for i,l in enumerate((APP/m['source']).read_text().splitlines(),1) if re.match(r'\s*// '+point+':',l))
            b,off,s=resolve(int(point,16));claim['instruction_evidence'].append(dict(method=own,source=m['source'],source_sha256=m['source_sha256'],line=li[0],text=li[1].strip(),binary=str(BINARY),elf_va=point,file_offset=off,section=s,bytes_le=b.hex()))
        newclaims.append(claim)
    supp=OUT/'supplement_methods';supp.mkdir(exist_ok=True)
    for a in {a for c in newclaims for a in c['methods']}:(supp/(a[2:]+'.asm.txt')).write_text(by[a]['_body'])
    uncovered={a for a in by if not semantics[a]}
    for p in ev.glob('*.asm.txt'):
        if '0x'+p.name.split('.')[0] not in uncovered:p.unlink()
    ppfile=APP/'analysis/aot_dump/pp.txt';inputs[str(ppfile)]=sha(ppfile.read_bytes());pprefs=[]
    for li,l in enumerate(ppfile.read_text().splitlines(),1):
        if 'package:distinguish' in l:
            for a in re.findall(r'\((0x[0-9a-f]+)\)',l):pprefs.append(dict(address=a,line=li,text=l,exported=a in by))
    calls=[]; indirect=[]; callbacks=[]; http=[]; literals=[]; dispatch=[]; fields=[]; entry=[]; failures=[]; span=[]; models=[]
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for m in methods:
        a=int(m['address'],16); n=m['exported_body_size']; b,off,section=resolve(a,n)
        fullfile=full/(m['address'][2:]+'.asm.txt');fullfile.write_text(m['_body'])
        declared,_,_=resolve(a,m['declared_size'])
        m.update(elf_section=section,elf_file_offset=off,exported_body_sha256=sha(b),declared_span_sha256=sha(declared),
            complete_excerpt=rel(fullfile),complete_excerpt_sha256=sha(fullfile.read_bytes()),
            existing_complete_excerpts=snippet_refs[m['address']],semantic_associations=semantics[m['address']],
            existing_json_address_references=refs[m['address']],semantic_coverage='partial_claims_present_not_whole_method_proof' if semantics[m['address']] else 'no_explicit_semantic_association_found',
            full_method_behavior_exhaustively_reviewed=False)
        m['inventory_category']=category(m)
        m['category_basis']='explicit source directory / method signature only; not inferred business behavior'
        rawfile=raw/(m['address'][2:]+'.raw.txt')
        lines=['binary: '+str(BINARY),'ELF VA: '+m['address'],'section: '+section,'file offset: '+hex(off),'body size: '+hex(n),'body sha256: '+sha(b),'declared size: '+hex(m['declared_size']),'']
        decoded=list(md.disasm(b,a))
        if len(decoded)*4!=n:failures.append(dict(kind='raw_decode_incomplete',method=m['address']))
        raw_by={i.address:i for i in decoded}
        for i in decoded:lines.append(f'{i.address:#x}: {i.bytes.hex()}  {i.mnemonic} {i.op_str}')
        rawfile.write_text('\n'.join(lines)+'\n');m['raw_disassembly']=rel(rawfile);m['raw_disassembly_sha256']=sha(rawfile.read_bytes())
        owncalls=[]
        for li,l in enumerate(m['_lines'],m['source_start_line']):
            z=INSN.match(l)
            if not z:continue
            ca=int(z[1],16); text=z[2]
            bm=re.match(r'bl\s+#(0x[0-9a-f]+)(?:\s+;\s*(.*))?',text)
            if bm:
                target=int(bm[1],16);rb,ro,rs=resolve(ca);word=int.from_bytes(rb,'little');imm=word&0x3ffffff;imm=imm-0x4000000 if imm&0x2000000 else imm;actual=ca+imm*4
                good=(word&0xfc000000==0x94000000 and actual==target)
                c=dict(owner=m['address'],binary=str(BINARY),elf_va=hex(ca),file_offset=ro,section=rs,bytes_le=rb.hex(),word_hex=hex(word),target_elf=hex(actual),target_asm=hex(target),label=bm[2] or '',source=m['source'],line=li,verified=good)
                calls.append(c);owncalls.append(c)
                if not good:failures.append(c)
                if 'HttpClient::get' in c['label'] or 'HttpClient::post' in c['label']:http.append(c)
            if re.match(r'(?:blr|br)\s+',text):
                ri=raw_by[ca];r=dict(owner=m['address'],elf_va=hex(ca),source=m['source'],line=li,asm=text,bytes_le=ri.bytes.hex(),raw_mnemonic=ri.mnemonic,raw_operands=ri.op_str,
                    closure_status='indirect_call_target_not_generically_resolved_by_this_audit')
                indirect.append(r)
            cm=re.search(r'(?:AnonymousClosure|Closure):\s*\((0x[0-9a-f]+)\)',text)
            if cm:
                target=hex(int(cm[1],16));callbacks.append(dict(owner=m['address'],target=target,source=m['source'],line=li,annotation=text,
                    target_exported_business_method=target in by,target_has_partial_semantic_claim=bool(semantics[target])))
            lm=re.search(r'"((?:[^"\\]|\\.)*)"',text)
            if lm and '/api/' in lm[1]:literals.append(dict(owner=m['address'],elf_va=hex(ca),source=m['source'],line=li,literal=lm[1]))
            if 'LoadField:' in text or 'StoreField:' in text or 'StaticField(' in text:
                fields.append(dict(owner=m['address'],elf_va=hex(ca),source=m['source'],line=li,operation=text,
                    reviewed_field_identity='not_inferred_from_offset_alone'))
        m['direct_call_count']=len(owncalls)
        if not semantics[m['address']]:
            p=ev/(m['address'][2:]+'.asm.txt');p.write_text(m['_body']);m['uncovered_full_excerpt']=rel(p);m['uncovered_full_excerpt_sha256']=sha(p.read_bytes())
        if m['declared_tail_not_in_this_body']:
            tail=m['declared_tail_not_in_this_body'];overlaps=sorted((h for h in by if int(tail[0],16)<=int(h,16)<a+m['declared_size']),key=lambda h:int(h,16));nextmethod=overlaps[0] if overlaps else None
            span.append(dict(method=m['address'],signature=m['signature'],declared_size=m['declared_size'],exported_body_size=n,
                extra_bytes=len(tail)*4,first_extra=tail[0],first_extra_is_business_entry=tail[0] in by,following_exported_method=nextmethod,overlapping_exported_methods=overlaps,bytes_before_following_business_entry=int(nextmethod,16)-int(tail[0],16) if nextmethod else None,
                conclusion='declared span overlaps independently exported next business method; one wrapper first crosses a 12-byte allocation-stub entry. Not missing exported instructions.'))
        if re.search(r'\b(?:build|initState|dispose|on[A-Z]\w*|save\w*|start\w*|end\w*|reset\w*|restart\w*|logout|login)\(',m['signature']):
            entry.append(dict(method=m['address'],signature=m['signature'],source=m['source'],has_partial_semantic_claim=bool(semantics[m['address']]),
                classification='name-based entry candidate; anonymous closures separately inventoried'))
        if 'msg_type' in m['_body'] or m['address']=='0x527460':
            dispatch.append(dict(method=m['address'],source=m['source'],signature=m['signature'],
                note='Dart receiver main dispatch; raw comparisons are retained in complete body/raw disassembly',
                reviewed_msg_type_set=[101,102,113,114,115,116,117] if m['address']=='0x527460' else None))
        if '/model/' in m['source']:
            keys=[]
            for li,l in enumerate(m['_lines'],m['source_start_line']):
                z=INSN.match(l)
                if z and re.match(r'r\d+ = "',z[2]):
                    for k in re.findall(r'"((?:[^"\\]|\\.)*)"',z[2]):keys.append(dict(value=k,elf_va=z[1],line=li))
            models.append(dict(method=m['address'],source=m['source'],signature=m['signature'],literal_key_candidates=keys,
                field_operations=[f for f in fields if f['owner']==m['address']],semantic_associations=m['semantic_associations'],
                complete_field_semantics='not_established_by_literal_extraction; independent per-field dataflow review required'))
        del m['_body'];del m['_lines']
    index_by={x['address']:x for x in idx['functions']}
    for m in methods:
        im=index_by.get(m['address'])
        if not im or im['path']!=m['source'] or int(im['size'],16)!=m['declared_size']:failures.append(dict(kind='inventory_mismatch',method=m['address']))
        elif im['direct_calls']!=[dict(address=c['elf_va'],target=c['target_asm'],label=c['label'],line=c['line']) for c in calls if c['owner']==m['address']]:failures.append(dict(kind='direct_call_index_mismatch',method=m['address']))
    if set(by)!=set(index_by):failures.append(dict(kind='inventory_address_set_mismatch'))
    endpoint=json.loads((APP/'analysis/http_endpoints_all.json').read_text())
    known_service_addresses={hex(int(x['address'],16)) for x in endpoint['endpoints'] if x.get('address')}
    for h in http:h['owner_in_22_endpoint_catalog']=h['owner'] in known_service_addresses
    for s in span:
        s['first_extra_direct_target_labels']=sorted({c['label'] for c in calls if c['target_elf']==s['first_extra']})
    rootmodels=APP/'analysis/completeness_audit/models/model_field_contracts.json'
    modelref=dict(path=rel(rootmodels),integration='independent per-key/offset/type-test contract inventory; not promoted into exhaustive model semantic coverage')
    if rootmodels.is_file():
        inputs[str(rootmodels)]=sha(rootmodels.read_bytes());modelref['sha256']=inputs[str(rootmodels)];modeldoc=json.loads(rootmodels.read_text())
        modelref['observed_counts']={k:modeldoc[k] for k in ['model_file_count','model_method_count','json_method_count','distinct_class_key_contracts','json_key_occurrences']}
        for mi,mm in enumerate(modeldoc['methods']):
            if mm['address'] in by:by[mm['address']]['independent_model_field_inventory']=dict(artifact=rel(rootmodels),sha256=inputs[str(rootmodels)],json_pointer='/methods/'+str(mi),association='observed key/type-test/field-read contract only; not exhaustive business semantics',key_occurrences=len(mm['keys']))
    byfile=[]
    for f in files:
        ms=[by[a] for a in f['methods']];f.update(partial_claim_methods=sum(bool(m['semantic_associations']) for m in ms),existing_complete_excerpt_methods=sum(bool(m['existing_complete_excerpts']) for m in ms),no_explicit_semantic_association_methods=[m['address'] for m in ms if not m['semantic_associations']]);byfile.append(f)
    counts=dict(business_files=len(files),files_with_methods=sum(bool(f['method_count']) for f in files),business_methods=len(methods),raw_body_instruction_words=sum(m['exported_body_size']//4 for m in methods),declared_size_overlap_methods=len(span),raw_direct_bl=len(calls),raw_direct_bl_failures=sum(not x['verified'] for x in calls),
        methods_with_existing_complete_excerpt=sum(bool(m['existing_complete_excerpts']) for m in methods),methods_supporting_explicit_partial_claims=sum(bool(m['semantic_associations']) for m in methods),methods_without_explicit_semantic_association=sum(not m['semantic_associations'] for m in methods),
        complete_business_method_excerpts_written=len(methods),methods_with_independent_model_field_inventory=sum('independent_model_field_inventory' in m for m in methods),business_http_get_post_calls=len(http),endpoint_literal_occurrences=len(literals),distinct_api_literal_values=len({x['literal'] for x in literals}),indirect_call_sites=len(indirect),closure_allocation_references=len(callbacks),distinct_closure_targets=len({x['target'] for x in callbacks}),closure_refs_without_partial_semantic_claim=sum(x['target_exported_business_method'] and not x['target_has_partial_semantic_claim'] for x in callbacks),distinct_business_closure_targets_without_partial_claim=len({x['target'] for x in callbacks if x['target_exported_business_method'] and not x['target_has_partial_semantic_claim']}),entry_name_candidates=len(entry),field_operation_occurrences=len(fields),prior_analysis_json_scanned=len(all_json),prior_partial_semantic_association_methods=prior_semantic_count,new_bounded_claims=len(newclaims),new_bounded_claim_methods=len({a for c in newclaims for a in c['methods']}),supplement_support_methods=5,pp_business_code_references=len(pprefs),pp_unique_business_code_addresses=len({r['address'] for r in pprefs}),pp_unexported_code_references=sum(not r['exported'] for r in pprefs))
    inventory=dict(scope='All package:distinguish business functions exported by Blutter; static audit, no target execution/server traffic.',counts=counts,
        coverage_rules=['An explicit claim association proves only the stated behavior, not exhaustive method semantics.','An exact complete excerpt proves extraction, not explanation.','A source file hash/reference, function inventory or address-only mention is never counted as semantic coverage.','Original source removed/inlined/unreachable methods are outside the exported snapshot inventory; 612 is not a proof of original source completeness.'],
        files=byfile,methods=methods,declared_span_anomalies=span,errors=failures)
    dump(OUT/'method_coverage.json',inventory)
    dump(OUT/'direct_calls.json',dict(scope='Every business direct BL re-decoded from original ELF',calls=calls))
    dump(OUT/'model_serialization_audit.json',dict(models=models,field_type_status='key/offset/type completeness requires per-field review; this inventory does not infer JSON mapping from nearby literals.'))
    dump(OUT/'pp_code_references.json',dict(source=rel(ppfile),source_sha256=sha(ppfile.read_bytes()),references=pprefs))
    log_callers=[c for c in calls if c['target_elf'] in ['0x493418','0x4af73c']]
    finite=[dict(scope='53 exported distinguish business files',query=q,matches=[dict(source=f['source'],line=i,text=l.strip()) for f in files for i,l in enumerate((APP/f['source']).read_text().splitlines(),1) if q in l]) for q in ['/inlet_pwd.conf','inletPwdDbWrite','6666']]
    dump(OUT/'supplemental_flows.json',dict(claims=newclaims,log_append_direct_callers=log_callers,finite_phrase_usage_scan=finite,
        finite_boundaries=['No complete original source recovery is claimed.','The inlet_pwd filename/write-helper/reserved literal scan finds only the reviewed writer/use sites; it does not prove that external code never reads the file.','Update page has 6 exported methods, no self-defined dispose; this does not prove Flutter framework/plugin performs no cleanup.','Update onData ignores status and parses value; nonnumeric errors are conditional static error paths, not observed failures.']))
    supportdir=OUT/'support_methods';supportdir.mkdir(exist_ok=True);supports=[]
    for source,selected in [('analysis/aot_dump/asm/ota_update/ota_update.dart',['0x52cac4','0x52cca8','0x52cd8c','0x52ce84']),('analysis/aot_dump/asm/flutter/src/material/text_form_field.dart',['0x4873e0'])]:
        p=APP/source;inputs[str(p)]=sha(p.read_bytes());ls=p.read_text().splitlines()
        for a in selected:
            h=next(i for i,l in enumerate(ls) if '// ** addr: '+a+',' in l);end=next(j for j in range(h+1,len(ls)) if ls[j]=='  }');body='\n'.join(ls[h-1:end+1])+'\n'
            addresses=sorted({int(z[1],16) for l in ls[h:end+1] if (z:=INSN.match(l))});size=addresses[-1]+4-int(a,16);b,off,s=resolve(int(a,16),size)
            sf=supportdir/(a[2:]+'.asm.txt');sf.write_text(body)
            rf=supportdir/(a[2:]+'.raw.txt');rf.write_text('\n'.join(f'{i.address:#x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in md.disasm(b,int(a,16)))+'\n')
            supports.append(dict(address=a,source=source,source_sha256=sha(p.read_bytes()),source_start_line=h,source_end_line=end+1,full_excerpt=rel(sf),full_excerpt_sha256=sha(sf.read_bytes()),raw_disassembly=rel(rf),raw_disassembly_sha256=sha(rf.read_bytes()),binary=str(BINARY),elf_va=a,elf_file_offset=off,elf_section=s,exported_body_size=size,exported_body_sha256=sha(b)))
    objfile=APP/'analysis/aot_dump/objs.txt';inputs[str(objfile)]=sha(objfile.read_bytes());objlines=objfile.read_text().splitlines();objpoints=[]
    for pattern,count in [('Obj!MaterialColor@74fe21 : {',5),('Obj!Color@74f321 : {',3)]:
        i=objlines.index(pattern);objpoints.append(dict(source=rel(objfile),source_sha256=sha(objfile.read_bytes()),start_line=i+1,end_line=i+count,text='\n'.join(objlines[i:i+count])))
    dump(OUT/'supplement_support.json',dict(methods=supports,object_points=objpoints,
        ota_value_dataflow='OtaUpdate._toOtaEvent assigns list[0] parsed enum to +7, list[1] to +b; page only consumes +b. PlatformException branch converts code/message to this same shape. execute default argument map contains url, androidProviderAuthority=null, filename=null, checksum=null, headers=jsonEncode(empty map).',
        limits=['Dart plugin protocol has been reviewed to establish event fields and entry arguments; Android download/permission/install implementation is outside this five-method support scope.']))
    dump(OUT/'surface_inventory.json',dict(http_calls=http,api_literal_occurrences=literals,dispatch=dispatch,entry_name_candidates=entry,closure_allocation_references=callbacks,indirect_call_sites=indirect,field_operation_inventory=fields,
        limits=['Name-based candidates do not prove UI reachability.','Generic dynamic calls require receiver/CID dataflow; their presence does not mean all prior analyses left them unresolved.','Callback allocation proves a code reference, not whether an asynchronous result is awaited or successfully delivered.']))
    gaps=[]
    for m in methods:
        if m['semantic_associations']:continue
        gaps.append(dict(method=m['address'],signature=m['signature'],source=m['source'],source_sha256=m['source_sha256'],source_start_line=m['source_start_line'],source_end_line=m['source_end_line'],category=m['inventory_category'],complete_excerpt=m['complete_excerpt'],complete_excerpt_sha256=m['complete_excerpt_sha256'],uncovered_excerpt=m['uncovered_full_excerpt'],raw_disassembly=m['raw_disassembly'],raw_body_sha256=m['exported_body_sha256'],independent_model_field_inventory=m.get('independent_model_field_inventory'),direct_calls=[dict(elf_va=c['elf_va'],target_elf=c['target_elf'],label=c['label'],bytes_le=c['bytes_le'],line=c['line']) for c in calls if c['owner']==m['address']],incoming_direct_calls=[dict(owner=c['owner'],elf_va=c['elf_va'],line=c['line']) for c in calls if c['target_elf']==m['address']],closure_references=[c for c in callbacks if c['owner']==m['address'] or c['target']==m['address']],indirect_calls=[c for c in indirect if c['owner']==m['address']],review_status='no explicit partial semantic association found under stated evidence rule; not a proof no human ever reviewed this method'))
    dump(OUT/'semantic_gaps.json',dict(scope='Evidence-based gaps after bounded supplements; all exported methods also have their complete body archived.',counts=dict(methods=len(gaps),by_inventory_category=dict(sorted(collections.Counter(x['category'] for x in gaps).items())),entry_name_candidates_without_partial_claim=sum(not x['has_partial_semantic_claim'] for x in entry),callback_reference_occurrences_without_partial_claim=counts['closure_refs_without_partial_semantic_claim'],distinct_business_callback_targets_without_partial_claim=counts['distinct_business_closure_targets_without_partial_claim']),unassociated_methods=gaps,callback_review=dict(status='inventory_and_explicit_claim_crosscheck_only',allocation_references=callbacks,indirect_call_sites=indirect,limitation='An indirect site or allocation without a matching claim is a review candidate. This audit does not assert every such target is unresolved by every prior report.'),model_contract_cross_reference=modelref,known_bounded_unknowns=[dict(id='inlet_password_read_gate',status='not_closed',scope='53 exported distinguish files finite filename/helper/reserved-literal scan',reason='Only writer/local UI validation/navigation found; actual file read/authentication gate not recovered.'),dict(id='msg117_first_list_item',status='sender_schema_unknown',reason='Dart recipient usage is recovered in prior protocol analysis; first-list-element server definition cannot be established from receiving code alone.'),dict(id='all_model_semantics',status='observation_inventory_not_business_definition',reason='Parent model artifact enumerates all observed keys, slots and type tests; business meaning, dynamic conversions and server schema remain bounded by available dataflow.'),dict(id='callbacks_and_dynamic_targets',status='requires_per_receiver_and_async_lifetime_review',reason='Complete allocation/BR/BLR inventory and current exact claim links retained; generic target/lifetime closure not established by source-name or code-reference counts.'),dict(id='original_pre_aot_source',status='not_recoverable_by_inventory_claim',reason='Tree-shaken, inlined and aliased source methods cannot be inferred complete from the exported snapshot.'),dict(id='backend_and_runtime',status='out_of_static_scope',reason='No backend, APK execution or live device interaction occurred; real responses and timing remain untested.')] ))
    manifest=dict(input_hashes=inputs,generator=str(SELF),generator_sha256=sha(SELF.read_bytes()),outputs={str(p):sha(p.read_bytes()) for p in sorted(OUT.rglob('*')) if p.is_file() and p.name not in ['evidence_manifest.json','verification.json']})
    dump(OUT/'evidence_manifest.json',manifest)
    report=['Dart AOT 业务层完整性审计','仅静态审查：未执行目标 APK/Dart/业务库，未联系业务服务器。','',f"业务文件 {counts['business_files']}，含方法文件 {counts['files_with_methods']}，方法 {counts['business_methods']}。",f"全部直接 BL {len(calls)} 条，原 ELF 不匹配 {counts['raw_direct_bl_failures']} 条；有效导出机器指令 {counts['raw_body_instruction_words']} 条。",f"跨度问题实测 {len(span)} 个：声明 size 超出包装 body，侵入后继独立方法，未当作代码缺失。",f"已有完整方法摘录 {counts['methods_with_existing_complete_excerpt']} 个；支持明确局部语义声明的方法 {counts['methods_supporting_explicit_partial_claims']} 个；未找到明确语义关联 {counts['methods_without_explicit_semantic_association']} 个。",'这些数字绝不等价于已完整解释的方法数。已有声明也可能仅覆盖其部分分支；审计没有宣称任何方法已穷尽所有行为。','',f"GET/POST 直接调用 {len(http)} 条；/api/ 字面量出现 {len(literals)} 次（{counts['distinct_api_literal_values']} 个不同值）；间接调用 {len(indirect)} 处；Closure 引用 {len(callbacks)} 处。",'全部612方法全文另存 complete_methods/，未关联方法全文位于 uncovered_methods/，全部612方法原始机器码反汇编位于 raw_methods/。原先未关联的方法即使因本轮补链改变分类，全文仍完整保留。','', '逐文件缺口（没有明确语义关联，不等于已证明是关键缺陷）：']
    for f in files:
        if f['no_explicit_semantic_association_methods']:report.append(f"{f['source']}: {len(f['no_explicit_semantic_association_methods'])}/{f['method_count']}；"+', '.join(f['no_explicit_semantic_association_methods']))
    report+=['','边界：模型字段操作已全量导出，父任务的38个模型方法观察契约另存 models/model_field_contracts.json，并在每个方法上交叉引用；该清单观察key/type-test/field-read，不等价于所有字段的业务定义、动态调用目标或服务端真实Schema都已恢复。所有间接调用被列为需核对，不直接断言旧工件全部未闭合。动态URL、请求参数与服务端真实Schema不因22端点已建目录而自动完整。','13个声明跨度异常中，12个紧接下一业务entry；0x52bbb0先跨入12字节AllocateOnlineConfigStub(0x52bbe0)，随后侵入DataConfig.fromJson(0x52bbec)。全部实际包装body均连续完整。']
    report+=['','本轮补齐的有限行为链：']+[c['id']+'：'+c['conclusion'] for c in newclaims]
    report+=['','明确保留的实质范围缺口：','1. 仍有 '+str(counts['methods_without_explicit_semantic_association'])+' 个方法没有上述明确语义关联；逐一列入JSON并附全文。UI build/closure 不因看似简单而自动算已解释。','2. '+str(len(indirect))+' 个间接调用需具体receiver/CID/closure流核对；统一库存不是对全部target的解析。','3. 各模型字段已保留全文/字面量/操作，但完整字段语义与未解类型由父任务 models/model_field_contracts.json 独立补充，本工件不将所有key视为已解释。','4. msg117 的首列表项服务端定义仍未恢复；现有 receiver 取值/后续状态不能代替发送端Schema。','5. inlet_pwd.conf 只找到写入链，读取/口令验证/访问控制的实际用途未闭合。','6. 原始源代码中被tree-shaking删除、内联、共享entry别名的方法无法由612导出库存证明完整。','7. 服务端Schema、运行时网络成功、真实时序和设备协议行为仍不由静态Dart方法导出确定。']
    pseudo='''以下为有限行为重建，未执行目标代码；真实字段名缺失时使用offset。

KeyForm._onSave() async {
  focus?.unfocus();
  final text = controller.text; // 原文本，无trim
  if (text.isEmpty) { showError("请输入您的口令"); return; }
  if (text == "6666") { showError("请更换其他口令"); return; }
  await save_config(md5.convert(utf8.encode(text)).toString());
  // save_config内部调用void async inletPwdDbWrite，不等待实际写盘
  if (widget.field_b == true) offAll(() => LoginPage()); else Get.back();
  showToast("保存成功");
}

Update.createState() => State(progress_field13: 0.0);
Update.initState() {
  try {
    OtaUpdate().execute(widget.appUpdate.ota_url ?? APK_FALLBACK_URL)
      .listen((event) => setState(() {
        progress_field13 = double.parse(event.field_b ?? "0");
      })); // 不保存subscription；不读取event.status；没有本地onError
  } catch (error) { show("Failed to make OTA update. Details: $error"); }
}
Update.build() {
  // 固定包含FAProgressBar(progress_field13)、升级说明、手动下载按钮
}
Update.manualDownload() {
  launchUrl(Uri.parse(widget.appUpdate.update_url ?? "")); // 不消费Future
}

LogService.instance() => static_cd8 ??= LogService._internal();
LogService._internal() { field1b = <Log>[].obs; initializeGetxLifecycle(); }
LogService.addLogTextRed(message) {
  field1b.add(Log(field7: color0xfff44336, field_b: getTimeStr()+"： "+message));
}
LogService.addLogTextBlack(message) {
  field1b.add(Log(field7: color0xff000000, field_b: getTimeStr()+"： "+message));
}
getTimeStr() {
  final p = DateTime.now()._parts();
  return fmt(p[8])+"/"+fmt(p[7])+"/"+fmt(p[5])+" "+fmt(p[4])+":"+fmt(p[3])+":"+fmt(p[2]);
}
fmt(int x) => x < 10 ? "0"+x.toString() : x.toString();

Main.exitTap() { wsLogout(); offAll(LoginPage()); } // 两个Future都不await
Main.changePasswordTap() { Get.to(EditPwdPage()); }
'''
    (OUT/'补链重建伪代码.txt').write_text(pseudo)
    (OUT/'中文审计说明.txt').write_text('\n'.join(report)+'\n')
    # Include final prose after generation, maintaining deterministic output manifest.
    for p in [OUT/'中文审计说明.txt',OUT/'补链重建伪代码.txt']:manifest['outputs'][str(p)]=sha(p.read_bytes())
    dump(OUT/'evidence_manifest.json',manifest)
    return verify()

def verify():
    manifest=json.loads((OUT/'evidence_manifest.json').read_text());errors=[]
    for group in ['input_hashes','outputs']:
        for p,h in manifest[group].items():
            path=Path(p)
            if not path.is_file():errors.append(dict(path=p,error='missing'))
            elif sha(path.read_bytes())!=h:errors.append(dict(path=p,error='sha256_mismatch'))
    d=json.loads((OUT/'method_coverage.json').read_text())
    errors+=d['errors']
    original=BINARY.read_bytes()
    with BINARY.open('rb') as f:
        elf=ELFFile(f); sections=[(int(s['sh_addr']),int(s['sh_size']),int(s['sh_offset']),s.name) for s in elf.iter_sections() if s['sh_type']!='SHT_NOBITS']
    def resolve(a,n=4):
        s=next(s for s in sections if s[0]<=a and a+n<=s[0]+s[1]); off=s[2]+a-s[0]
        return original[off:off+n],off,s[3]
    fresh,files=load_methods();fresh_by={m['address']:m for m in fresh};indexed={m['address']:m for m in json.loads(INDEX.read_text())['functions']}
    stored_by={m['address']:m for m in d['methods']}
    if set(stored_by)!=set(fresh_by) or set(stored_by)!=set(indexed):errors.append(dict(error='recomputed_inventory_address_set_mismatch'))
    raw_calls={}; checked_words=0;excerpt_count=0
    for a,m in stored_by.items():
        actual=fresh_by.get(a);ind=indexed.get(a)
        if not actual or not ind:continue
        for key in ['source','source_sha256','source_start_line','source_end_line','signature','declared_size','exported_body_size','body_sha256','exported_address_holes','declared_tail_not_in_this_body']:
            if m[key]!=actual[key]:errors.append(dict(method=a,error='recomputed_export_mismatch',field=key))
        if ind['path']!=m['source'] or ind['line']!=m['source_start_line']+1 or int(ind['size'],16)!=m['declared_size'] or ind['signature']!=m['signature']:errors.append(dict(method=a,error='recomputed_function_index_mismatch'))
        if actual['exported_address_holes']:errors.append(dict(method=a,error='exported_body_address_holes'))
        if (APP/m['complete_excerpt']).read_bytes()!=actual['_body'].encode():errors.append(dict(method=a,error='complete_excerpt_source_range_mismatch'))
        excerpt_count+=1
        b,off,s=resolve(int(a,16),actual['exported_body_size']);declared,_,_=resolve(int(a,16),actual['declared_size'])
        if sha(b)!=m['exported_body_sha256'] or sha(declared)!=m['declared_span_sha256'] or off!=m['elf_file_offset'] or s!=m['elf_section']:errors.append(dict(method=a,error='recomputed_elf_span_mismatch'))
        checked_words+=len(b)//4
        for offset in range(0,len(b),4):
            word=int.from_bytes(b[offset:offset+4],'little');va=int(a,16)+offset
            if word&0xfc000000!=0x94000000:continue
            imm=word&0x3ffffff;imm=imm-0x4000000 if imm&0x2000000 else imm
            raw_calls[(a,hex(va))]=hex(va+imm*4)
    calls=json.loads((OUT/'direct_calls.json').read_text())['calls'];stored_calls={(c['owner'],c['elf_va']):c['target_elf'] for c in calls}
    if raw_calls!=stored_calls or len(calls)!=len(stored_calls):errors.append(dict(error='recomputed_raw_bl_inventory_mismatch'))
    for c in calls:
        b,off,s=resolve(int(c['elf_va'],16))
        if c['bytes_le']!=b.hex() or c['file_offset']!=off or c['section']!=s or c['target_elf']!=c['target_asm']:errors.append(dict(method=c['owner'],elf_va=c['elf_va'],error='recomputed_direct_call_mismatch'))
    support=json.loads((OUT/'supplement_support.json').read_text())['methods']
    for m in support:
        ls=(APP/m['source']).read_text().splitlines();body='\n'.join(ls[m['source_start_line']-1:m['source_end_line']])+'\n';b,off,s=resolve(int(m['address'],16),m['exported_body_size'])
        if (APP/m['full_excerpt']).read_text()!=body or sha(b)!=m['exported_body_sha256'] or off!=m['elf_file_offset'] or s!=m['elf_section']:errors.append(dict(method=m['address'],error='recomputed_support_method_mismatch'))
        excerpt_count+=1
    points=[p for c in json.loads((OUT/'supplemental_flows.json').read_text())['claims'] for p in c['instruction_evidence']]
    for p in points:
        b,off,s=resolve(int(p['elf_va'],16));line=(APP/p['source']).read_text().splitlines()[p['line']-1].strip()
        if b.hex()!=p['bytes_le'] or off!=p['file_offset'] or s!=p['section'] or line!=p['text']:errors.append(dict(elf_va=p['elf_va'],error='recomputed_claim_instruction_mismatch'))
    result=dict(status='PASS' if not errors else 'FAIL',checked_input_files=len(manifest['input_hashes']),checked_output_files=len(manifest['outputs']),counts=d['counts'],errors=errors,
        independently_recomputed=dict(exported_business_methods=len(fresh),business_files=len(files),exact_complete_excerpt_ranges=excerpt_count,business_machine_words=checked_words,direct_bl=len(raw_calls),supplement_support_methods=len(support),supplement_claim_instruction_points=len(points)),
        note='PASS validates inventory/export spans/raw BL/hash reproducibility, not whole-program semantic completeness.')
    dump(OUT/'verification.json',result);print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if not errors else 1

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--verify',action='store_true');args=ap.parse_args();sys.exit(verify() if args.verify else build())
