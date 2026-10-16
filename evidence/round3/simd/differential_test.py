#!/usr/bin/env python3
"""Compile real C/Java replacements; compare against original ARM64 instructions.
All data is synthetic. No application, account, backend or OS runtime is invoked.
"""
import ctypes,gzip,hashlib,importlib.util,io,json,random,struct,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
APP=next(p for p in HERE.parents if (p/'unpacked/lib').is_dir())
BUILD=HERE/'build';BUILD.mkdir(exist_ok=True)
JAVA=APP/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java'
JDK=Path('/opt/homebrew/opt/openjdk@21/bin')
spec=importlib.util.spec_from_file_location('round2_emulator',APP/'analysis/reconstruction_round2/native/emulate_native_gaps.py')
emu=importlib.util.module_from_spec(spec);spec.loader.exec_module(emu)
from unicorn import UcError,UC_HOOK_MEM_READ,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X8

def run(cmd,**kwargs):
    r=subprocess.run([str(x) for x in cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,**kwargs)
    return r.stdout
def sha(data):return hashlib.sha256(data).hexdigest()
def check(ok,why):
    if not ok:raise AssertionError(why)

def compile_all():
    outputs=[]
    for backend,extra in [('neon',[]),('scalar',['-DXCS_FORCE_SCALAR'])]:
        lib=BUILD/f'libgo_byte_{backend}.dylib'
        run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror',*extra,'-dynamiclib',HERE/'go_byte_primitives.c','-o',lib])
        exe=BUILD/f'boundaries_{backend}'
        run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',*extra,HERE/'go_byte_primitives.c',HERE/'native_boundaries.c','-o',exe])
        outputs.append(json.loads(run([exe])))
    run([JDK/'javac','--release','8','-d',BUILD,JAVA,HERE/'GoBytePrimitivesProbe.java'])
    return outputs

def cases():
    rng=random.Random(0x53494d4433)
    lengths=[0,1,2,3,7,15,16,17,30,31,32,33,47,63,64,65,95,96,97,127,128,129,255,256,257,511,512,513,1023,1024,1025,4095,4096,4097]
    out=[]
    for alignment in range(32):
        for n in lengths:
            target=(alignment*19+n)%256;other=(target+1)%256
            absent=bytes([other])*n
            variants=[absent,bytes([target])*n,bytes(rng.randrange(256) for _ in range(n))]
            if n:
                for position in (0,n//2,n-1):variants.append(absent[:position]+bytes([target])+absent[position+1:])
            for data in variants:out.append((alignment,target,data))
    # Every target byte at every alignment, matching in every SIMD lane.
    for target in range(256):
        for alignment in range(32):out.append((alignment,target,bytes(range(256))+bytes([target])))
    for alignment in range(32):
        for lane in range(32):
            target=(alignment+lane)%256;p=64+lane
            data=bytearray([(target+1)%256]*129);data[p]=target
            out.append((alignment,target,bytes(data)))
    for _ in range(512):
        n=rng.randrange(2049);out.append((rng.randrange(32),rng.randrange(256),bytes(rng.randrange(256) for _ in range(n))))
    return out,lengths

def native_library(path):
    lib=ctypes.CDLL(str(path));lib.xcs_byte_backend.restype=ctypes.c_char_p
    for n in ('xcs_count_slice','xcs_index_slice','xcs_index_padded_slice'):
        fn=getattr(lib,n);fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p];fn.restype=ctypes.c_int
    return lib

def original(m,entry,pointer,length,target,result=0x909000):
    for reg,value in [(UC_ARM64_REG_X0,pointer),(UC_ARM64_REG_X1,target),(UC_ARM64_REG_X2,length),(UC_ARM64_REG_X8,result)]:m.uc.reg_write(reg,value)
    m.run(entry)
    n=m.read(result)
    return n-(1<<64) if n>>63 else n

def memory_boundaries():
    m=emu.Machine('arm64-v8a');reads=[]
    m.uc.hook_add(UC_HOOK_MEM_READ,lambda u,access,address,size,value,data:reads.append((address,size)))
    witnesses=[];checks=0
    for entry in (0x5ae90,0x5b310):
        for alignment in range(32):
            for n in (0,1,2,15,16,17,31,32,33,63,64,65,95,96,97,127,128,129):
                p=emu.DATA+0x10000+alignment;m.uc.mem_write(emu.DATA+0x10000,b'\x11'*256);reads.clear()
                actual=original(m,entry,p,n,0x22)
                check(actual==(0 if entry==0x5ae90 else -1),'absent memory oracle')
                accessed={a+i for a,size in reads for i in range(size)}
                expected=set(range(p,p+n)) if entry==0x5ae90 or not n else set(range(p&~31,(p+n+31)&~31))
                check(accessed==expected,f'read footprint {hex(entry)} align={alignment}, n={n}')
                checks+=1
                if alignment==1 and n in (0,1,32,33):
                    witnesses.append({'entry':hex(entry),'alignment':alignment,'length':n,'logical_start':hex(p),'logical_end_exclusive':hex(p+n),'reads':[{'address':hex(a),'size':s} for a,s in reads]})
    faults=[]
    for entry in (0x5ae90,0x5b310):
        check(original(m,entry,0,0,0x22)==(0 if entry==0x5ae90 else -1),'null empty');checks+=1
        for p,n,result,label in [(0,1,0x909000,'null nonempty data'),(0,0,0,'null result slot')]:
            try:original(m,entry,p,n,0x22,result)
            except UcError as e:faults.append({'entry':hex(entry),'case':label,'fault_pc':hex(m.uc.reg_read(m.pc)),'error':str(e)});checks+=1
            else:raise AssertionError('missing expected invalid-pointer fault')
    # Valid slices ending/starting at a mapped page boundary; adjacent pages unmapped.
    page=0x880000;m.uc.mem_map(page,4096);m.uc.mem_write(page,b'\x11'*4096)
    for n in (1,2,15,16,17,31,32,33,63,64,65,127,128,129,4096):
        for p in (page,page+4096-n):
            for entry in (0x5ae90,0x5b310):
                check(original(m,entry,p,n,0x22)==(0 if entry==0x5ae90 else -1),'page boundary');checks+=1
    return {'status':'PASS','checks':checks,'read_footprint_cases':1152,'witnesses':witnesses,'invalid_pointer_faults':faults,
      'count_reads_exact_logical_range':True,'index_absent_reads_aligned_32_byte_cover':True,
      'valid_page_boundary_slices_do_not_cross_unmapped_adjacent_pages':True}

def main():
    sanitizer=compile_all();dataset,lengths=cases();print('Compiled C NEON/scalar and Java; sanitizer checks PASS',flush=True)
    libraries=[native_library(BUILD/f'libgo_byte_{kind}.dylib') for kind in ('neon','scalar')]
    m=emu.Machine('arm64-v8a');pcs=set();m.uc.hook_add(UC_HOOK_CODE,lambda u,a,s,d:pcs.add(a))
    original_reads=0;native_checks=0;fingerprint=hashlib.sha256();input_hash=hashlib.sha256()
    java_input=io.BytesIO();java_input.write(struct.pack('>I',len(dataset)));expected_results=[]
    original_fixture=io.BytesIO();original_fixture.write(b'XCSSIMD3'+struct.pack('>I',len(dataset)))
    for k,(alignment,target,data) in enumerate(dataset):
        off=32+alignment;storage=bytes([target])*off+data+bytes([target])*32;size=len(storage)
        expected=(data.count(target),data.find(bytes([target])));expected_results.append(expected)
        input_hash.update(struct.pack('<III',alignment,target,len(data))+data)
        java_input.write(struct.pack('>IIII',size,off,len(data),target)+storage)
        base=emu.DATA+0x10000;m.uc.mem_write(base,storage)
        observed=(original(m,0x5ae90,base+off,len(data),target),original(m,0x5b310,base+off,len(data),target));original_reads+=2
        check(observed==expected,f'original machine mismatch case={k}')
        original_fixture.write(struct.pack('>IIII',size,off,len(data),target)+storage+struct.pack('>qq',*observed))
        # Align the real C storage exactly, so all 32 logical alignments are real.
        allocation=ctypes.create_string_buffer(size+32);address=(ctypes.addressof(allocation)+31)&~31
        ctypes.memmove(address,storage,size)
        for lib in libraries:
            count=ctypes.c_uint64();index=ctypes.c_int64();padded=ctypes.c_int64()
            check(lib.xcs_count_slice(address,size,off,len(data),target,ctypes.byref(count))==0,'C count status')
            check(lib.xcs_index_slice(address,size,off,len(data),target,ctypes.byref(index))==0,'C index status')
            check(lib.xcs_index_padded_slice(address,size,off,len(data),target,ctypes.byref(padded))==0,'C padded status')
            check((count.value,index.value,padded.value)==(*expected,expected[1]),f'C mismatch case={k}')
            native_checks+=3
        fingerprint.update(struct.pack('<qq',*observed))
    print(f'{len(dataset)} inputs: original ARM64 and compiled C differential PASS',flush=True)
    raw=run([JDK/'java','-cp',BUILD,'GoBytePrimitivesProbe'],input=java_input.getvalue())
    total,java_boundaries=struct.unpack_from('>II',raw);check(total==len(dataset),'Java case count')
    check(len(raw)==8+8*total,'Java result framing')
    for k,expected in enumerate(expected_results):check(struct.unpack_from('>ii',raw,8+8*k)==expected,f'Java mismatch case={k}')
    memory=memory_boundaries()
    fixture=gzip.compress(original_fixture.getvalue(),compresslevel=9,mtime=0)
    (HERE/'original_arm64_cases.bin.gz').write_bytes(fixture)
    report={'status':'PASS','original_source_recovered':False,'business_server_contacted':False,
      'dataset_inputs':len(dataset),'original_arm64_function_executions':original_reads,'compiled_c_result_checks':native_checks,
      'java_result_checks':len(dataset)*4,'java_boundary_checks':java_boundaries,'sanitizer_runs':sanitizer,'memory_boundaries':memory,
      'backend_names':[lib.xcs_byte_backend().decode() for lib in libraries],
      'dataset_sha256':input_hash.hexdigest(),'original_result_sha256':fingerprint.hexdigest(),
      'original_fixture_file':'original_arm64_cases.bin.gz','original_fixture_sha256':sha(fixture),'original_fixture_uncompressed_bytes':len(original_fixture.getvalue()),
      'lengths':lengths,'all_256_target_bytes_at_all_32_alignments':True,'all_32_simd_match_lanes_at_all_32_alignments':True,
      'original_executed_instructions':[hex(a) for a in sorted(pcs)],
      'tested_original_architecture':'APK arm64-v8a, little endian','c_host_architecture':'macOS arm64; NEON and forced portable-C backends',
      'java_class_sha256':sha(JAVA.read_bytes()),'c_source_sha256':sha((HERE/'go_byte_primitives.c').read_bytes()),
      'test_script_sha256':sha(Path(__file__).read_bytes()),'original_library_sha256':sha(m.blob),
      'limits':['Synthetic single-threaded fragment execution; no full runtime/JNI/business invocation.','Java uses bounded byte-array reads, not SIMD instructions.','Checked C/Java argument errors are explicit reconstruction API contracts, not the original Go caller ABI.']}
    (HERE/'differential_verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','dataset_inputs','original_arm64_function_executions','compiled_c_result_checks','java_result_checks','java_boundary_checks')}),flush=True)

if __name__=='__main__':main()
