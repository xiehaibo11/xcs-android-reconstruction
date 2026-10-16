#include "pch.h"
#include "DartApp.h"
#include <fstream>
// Original snapshot metadata only; no target function invocation.
int main(int argc,char**argv){
  if(argc!=3)return 2;DartApp app(argv[1]);app.EnterScope();app.LoadInfo();std::ofstream out(argv[2]);
  for(auto address:{0x2ed154,0x2eb3ac,0x2eb520,0x2ebda4,0x2edd6c}){
    auto* fn=static_cast<DartFunction*>(app.GetFunction(address));if(!fn)return 3;
    const auto& f=dart::Function::Handle(fn->Ptr());
    out<<"FUNCTION\t0x"<<std::hex<<address<<std::dec<<"\t"<<fn->FullName()<<"\tnative="<<f.is_native();
    if(f.is_native())out<<"\tnative_name="<<dart::String::Handle(f.native_name()).ToCString();out<<"\n";
  }
  auto& pool=app.GetObjectPool();
  for(auto offset:{0xbe8,0xbf8,0xc90,0xc98}){
    auto index=dart::ObjectPool::IndexFromOffset(offset);
    out<<"POOL\t0x"<<std::hex<<offset<<"\t0x"<<pool.RawValueAt(index)<<std::dec<<"\n";
  }
  app.ExitScope();return 0;
}
