#include "pch.h"
#include "DartApp.h"
#include "vm/dispatch_table.h"
#include "vm/class_table.h"
#include <fstream>
#include <cstring>
#include <cstdint>
#include <iomanip>

// Reads the input snapshot. Numeric results call the locally built Dart 3.5.2 VM
// reference implementation; this is NOT execution of the APK native engine.
int main(int argc,char**argv) {
  if(argc!=4)return 2;
  DartApp app(argv[1]); app.EnterScope(); app.LoadInfo();
  std::ofstream out(argv[3]);
  auto group=dart::IsolateGroup::Current();
  auto table=group->dispatch_table();
  out << "BUILD\tcompressed_pointers\t" << (sizeof(dart::CompressedObjectPtr)==4)
      << "\tSmiMin\t" << dart::Smi::kMinValue << "\tSmiMax\t" << dart::Smi::kMaxValue
      << "\tMintBits\t" << dart::Mint::kBits << "\n";
  for(int cid:{59,60,61,4688}) {
    auto cls=app.GetClass(cid);auto address=table->ArrayOrigin()[0x6d49+cid]-app.base();
    auto* fn=static_cast<DartFunction*>(app.GetFunction(address));
    const auto& f=dart::Function::Handle(fn->Ptr());
    out<<"GDT\t"<<cid<<"\t"<<cls->FullNameWithPackage()<<"\t0x"<<std::hex<<address<<std::dec
       <<"\t"<<fn->FullName()<<"\tnative="<<f.is_native();
    if(f.is_native())out<<"\tnative_name="<<dart::String::Handle(f.native_name()).ToCString();
    out<<"\n";
  }
  {
    auto* fn=static_cast<DartFunction*>(app.GetFunction(0x2ebc94));
    const auto& f=dart::Function::Handle(fn->Ptr());
    out<<"NATIVE_FACTORY\t0x2ebc94\t"<<fn->FullName()<<"\tnative="<<f.is_native()
       <<"\tnative_name="<<dart::String::Handle(f.native_name()).ToCString()<<"\n";
  }
  // Enumerate int declarations, including inherited implementation holders.
  for(int cid=0;cid<group->class_table()->NumCids();cid++) {
    auto* cls=app.GetClass(cid); if(!cls)continue;
    for(auto* method:cls->Functions()) {
      if(method->FullName().find("[dart:core]")==0 &&
          (method->Name().find("toDouble")!=std::string::npos||method->Name().find("doubleFromInteger")!=std::string::npos)) {
        const auto& f=dart::Function::Handle(method->Ptr());
        out<<"DOUBLE_METHOD\t"<<cid<<"\t0x"<<std::hex<<method->Address()<<std::dec
           <<"\t"<<method->FullName()<<"\tnative="<<f.is_native();
        if(f.is_native())out<<"\tnative_name="<<dart::String::Handle(f.native_name()).ToCString();
        out<<"\n";
      }
    }
  }
  std::ifstream input(argv[2]); int64_t value;
  while(input>>value) {
    const auto& integer=dart::Integer::Handle(dart::Integer::New(value));
    const auto& instance=dart::Instance::Handle(integer.ptr());
    const auto* text=instance.ToCString();
    const double dv=integer.AsDoubleValue();uint64_t bits;std::memcpy(&bits,&dv,8);
    out<<"VALUE\t"<<value<<"\t"<<instance.GetClassId()<<"\t"<<text<<"\t"<<std::hex<<std::setw(16)<<std::setfill('0')<<bits<<std::dec<<"\n";
  }
  app.ExitScope(); return 0;
}
