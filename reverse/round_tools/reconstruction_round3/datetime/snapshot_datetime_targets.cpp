#include "pch.h"
#include "DartApp.h"
#include "vm/class_table.h"
#include <fstream>
// Snapshot metadata only. Never invokes target Dart code.
int main(int argc,char**argv){
 if(argc!=3)return 2;DartApp app(argv[1]);app.EnterScope();app.LoadInfo();std::ofstream out(argv[2]);
 auto group=dart::IsolateGroup::Current();
 for(int cid=0;cid<group->class_table()->NumCids();cid++){
  auto cls=app.GetClass(cid);if(!cls||cls->FullNameWithPackage()!="[dart:core] DateTime")continue;
  for(auto fn:cls->Functions())out<<"FN\t0x"<<std::hex<<fn->Address()<<"\t0x"<<fn->Size()<<std::dec<<"\t"<<fn->FullName()<<"\n";
 }
 for(int i=0;i<app.GetObjectPool().Length();i++){
  if(app.GetObjectPool().TypeAt(i)!=dart::ObjectPool::EntryType::kTaggedObject)continue;
  auto& obj=dart::Object::Handle(app.GetObjectPool().ObjectAt(i));
  if(obj.IsString()) {auto& s=dart::String::Cast(obj);std::string str=s.ToCString();if(str.find("([+-]?")!=std::string::npos||str=="Time out of range"||str=="Invalid date format")out<<"POOL\t0x"<<std::hex<<dart::ObjectPool::OffsetFromIndex(i)<<std::dec<<"\t"<<str<<"\n";}
 }
 app.ExitScope();return 0;
}
