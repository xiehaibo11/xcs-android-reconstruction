#include "pch.h"
#include "DartApp.h"
#include "vm/dispatch_table.h"
#include "vm/class_table.h"
#include <fstream>

// Metadata inspection only: no Dart invocation, target entrypoint or business I/O.
int main(int argc,char**argv) {
    if(argc!=3)return 2;
    DartApp app(argv[1]);app.EnterScope();app.LoadInfo();
    std::ofstream out(argv[2]);
    auto& pool=app.GetObjectPool();
    auto index=dart::ObjectPool::IndexFromOffset(0x10840);
    auto& object=dart::Object::Handle(pool.ObjectAt(index));
    if(!object.IsUnlinkedCall())return 3;
    auto& call=dart::UnlinkedCall::Cast(object);
    out<<"UNLINKED\t0x10840\t"<<dart::String::Handle(call.target_name()).ToCString()
       <<"\t"<<dart::Array::Handle(call.arguments_descriptor()).ToCString()<<"\n";
    auto group=dart::IsolateGroup::Current();
    auto table=group->dispatch_table();
    out<<"TABLE\t"<<table->length()<<"\torigin\t"<<dart::DispatchTable::kOriginElement<<"\n";
    for(int cid=0;cid<group->class_table()->NumCids();cid++) {
        auto cls=app.GetClass(cid);if(!cls)continue;
        auto slot=dart::DispatchTable::kOriginElement+0x6d49+cid;
        if(slot>=table->length())continue;
        auto entry=table->ArrayOrigin()[0x6d49+cid];
        auto address=entry-app.base();auto fn=app.GetFunction(address);
        out<<"GDT\t"<<cid<<"\t"<<cls->FullNameWithPackage()<<"\t0x"<<std::hex<<address<<std::dec
           <<"\t"<<(fn?fn->FullName():"unknown")<<"\n";
        if(cid==59||cid==60||cid==61||cid==62||cid==93||cid==94) {
            for(auto method:cls->Functions()) {
                if(method->Name().find("toDouble")!=std::string::npos)
                    out<<"NUMERIC\t"<<cid<<"\t"<<cls->FullNameWithPackage()<<"\t0x"<<std::hex<<method->Address()<<std::dec<<"\t"<<method->FullName()<<"\n";
            }
        }
    }
    app.ExitScope();return 0;
}
