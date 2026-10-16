#include "pch.h"
#include "DartApp.h"
#include "vm/dispatch_table.h"
#include "vm/class_table.h"
#include <fstream>

// Read original snapshot metadata only; never invoke a target Dart method.
int main(int argc,char** argv){
    if(argc!=3)return 2;
    DartApp app(argv[1]);app.EnterScope();app.LoadInfo();std::ofstream out(argv[2]);
    auto group=dart::IsolateGroup::Current();auto table=group->dispatch_table();
    out<<"TABLE\t"<<table->length()<<"\torigin\t"<<dart::DispatchTable::kOriginElement<<"\n";
    for(int cid=0;cid<group->class_table()->NumCids();cid++){
        auto cls=app.GetClass(cid);if(!cls)continue;
        auto name=cls->FullNameWithPackage();
        if(name.find("String")!=std::string::npos || cid==59 || cid==60 || cid==61){
            for(int offset: {0,0x6d49}){
                auto slot=dart::DispatchTable::kOriginElement+offset+cid;if(slot>=table->length())continue;
                auto address=table->ArrayOrigin()[offset+cid]-app.base();auto fn=app.GetFunction(address);
                out<<"GDT\t"<<cid<<"\t"<<name<<"\t"<<offset<<"\t0x"<<std::hex<<address<<std::dec<<"\t"<<(fn?fn->FullName():"unknown")<<"\n";
            }
        }
    }
    for(unsigned long long address: {0x674170ULL,0x673f8cULL,0x6747ccULL,0x674930ULL,0x6f2a58ULL,0x6f79a8ULL}){
        auto fn=app.GetFunction(address);if(fn)out<<"FUNCTION\t0x"<<std::hex<<address<<std::dec<<"\t"<<fn->Size()<<"\t"<<fn->FullName()<<"\n";
    }
    app.ExitScope();return 0;
}
