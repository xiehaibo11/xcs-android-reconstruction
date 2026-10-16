package com.re.xcs.rebuild.core;
import java.util.*;

/** Cross-component behavior checks; reference-oracle suites are in sibling directories. */
public final class Round3IntegrationTest {
    static int checks;
    static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
    static void fails(Runnable run,Class<? extends Throwable> type,String message){try{run.run();}catch(Throwable e){check(type.isInstance(e),message+": "+e);return;}throw new AssertionError("Expected failure: "+message);}
    public static void main(String[] args){
        TimeZone before=TimeZone.getDefault();TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try{
            Models.Record device=Models.read("Devices",ApiContract.map("create_time","2020-01-42T00:00:00.1234567Z","version",Long.MAX_VALUE));
            DartDateTime created=(DartDateTime)device.get("create_time");
            check(device.unresolved.isEmpty(),"Devices former DateTime gap removed for supported fields");
            check(created.isUtc()&&created.toIso8601String().equals("2020-02-11T00:00:00.123456Z"),"Date normalization and fractional truncation");
            check(device.get("version").equals((double)Long.MAX_VALUE),"Mint version converted");
            Map<String,Object> output=device.toJson();
            check(output.get("create_time").equals(created.toIso8601String()),"Serializer emits ISO String");
            Models.Record reread=Models.read("Devices",JsonCodec.object(JsonCodec.parse(JsonCodec.stringify(output))));
            check(reread.get("create_time").equals(created),"Device model JSON roundtrip");
            check(reread.get("version").equals(device.get("version")),"Double version survives model roundtrip");
            Models.Record local=Models.read("Devices",ApiContract.map("create_time","2026-01-01","version",0));
            check(!((DartDateTime)local.get("create_time")).isUtc(),"No suffix remains local even in UTC zone");
            check(local.toJson().get("create_time").equals("2026-01-01T00:00:00.000"),"Local ISO omits Z");
            check(Models.read("Message",ApiContract.map("msg_content",created)).toJson().get("msg_content").equals("2020-02-11 00:00:00.123456Z"),"DateTime dynamic selector differs from ISO");
            check(DartConversions.messageContentString(Arrays.asList(created,Long.MIN_VALUE)).equals("[2020-02-11 00:00:00.123456Z, -9223372036854775808]"),"Nested dynamic receiver conversion");
            long[] bounds={Long.MIN_VALUE,-(1L<<30)-1,-(1L<<30),(1L<<30)-1,1L<<30,1L<<53,(1L<<53)+1,Long.MAX_VALUE};
            for(long value:bounds){Models.Record message=Models.read("Message",ApiContract.map("msg_content",value));check(message.unresolved.isEmpty()&&message.toJson().get("msg_content").equals(Long.toString(value)),"Smi/Mint Message model: "+value);}
            check(DartConversions.toDouble((1L<<53)+1)==9007199254740992.0,"Mantissa precision loss preserved");
            List<Object> numbers=JsonCodec.array(JsonCodec.parse("[9223372036854775807,9223372036854775808,1e309]"));
            check(numbers.get(0).equals(Long.MAX_VALUE)&&numbers.get(1) instanceof Double,"JSON int overflow preserves VM receiver class selection");
            check(DartConversions.messageContentString(numbers.get(1)).equals("9223372036854776000.0"),"Overflow JSON number dispatches through Double formatting");
            check(Models.read("Message",ApiContract.map("msg_content",numbers.get(2))).toJson().get("msg_content").equals("Infinity"),"Nonfinite decoded Double can become Message text");
            fails(()->Models.read("Devices",ApiContract.map("create_time","bad","version","bad","top",1)),DartDateTime.FormatException.class,"Date conversion executes before later fields");
            fails(()->Models.read("Devices",ApiContract.map("create_time","2026-01-01","version","bad")),IllegalArgumentException.class,"Unsupported version rejected");
            fails(()->Models.read("Devices",ApiContract.map("create_time",null,"version",1)),IllegalArgumentException.class,"Date requires string");
            fails(()->Models.read("Devices",ApiContract.map("create_time",1,"version",1)),IllegalArgumentException.class,"Date numeric type rejected");
            fails(()->DartConversions.toDouble(new java.math.BigInteger("1")),IllegalArgumentException.class,"Unrecovered BigInt receiver rejected");
            check(!Models.read("Message",ApiContract.map("msg_content",new Object())).unresolved.isEmpty(),"Custom receiver gap remains explicit");
            List<Object> cycle=new ArrayList<>();cycle.add(cycle);check(!Models.read("Message",ApiContract.map("msg_content",cycle)).unresolved.isEmpty(),"Cyclic collection gap remains explicit");
            check(!Models.read("MjConfig",ApiContract.map("id",1)).unresolved.isEmpty(),"Unrecovered MjConfig factory not relabeled complete");
            byte[] data={0,1,(byte)255,1,0};check(GoBytePrimitives.count(data,1,3,1)==2,"Compiled Go count primitive");
            check(GoBytePrimitives.indexOf(data,1,3,255)==1,"Go index is slice relative");
            check(GoBytePrimitives.indexOf(data,1,3,0)==-1,"Go index ignores matching bytes outside slice");
        }finally{TimeZone.setDefault(before);}
        System.out.println("PASS "+checks+" round3 integration assertions");
    }
}
