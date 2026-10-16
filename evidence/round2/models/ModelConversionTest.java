package com.re.xcs.rebuild.core;
import java.io.*;
import java.util.*;
public final class ModelConversionTest {
    static int checks;
    static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    static void fails(Runnable body){boolean threw=false;try{body.run();}catch(RuntimeException expected){threw=true;}check(threw,"unsupported receiver rejected");}
    public static void main(String[] args)throws Exception{
        if(args.length>0&&args[0].equals("doubles")){BufferedReader in=new BufferedReader(new InputStreamReader(System.in));for(String s;(s=in.readLine())!=null;)System.out.println(DartConversions.doubleString(Double.longBitsToDouble(Long.parseUnsignedLong(s,16))));return;}
        check(DartConversions.toDouble(2).equals(2.0),"integer conversion");check(DartConversions.toDouble(2.5).equals(2.5),"double identity");
        check(Double.doubleToRawLongBits(DartConversions.toDouble(-0.0))==Double.doubleToRawLongBits(-0.0),"negative zero");
        fails(()->DartConversions.toDouble(null));fails(()->DartConversions.toDouble("2.0"));fails(()->DartConversions.toDouble(true));
        Models.Record device=Models.read("Devices",ApiContract.map("create_time","2026-01-01","version",3));check(device.get("version").equals(3.0)&&device.get("create_time") instanceof DartDateTime&&device.unresolved.isEmpty(),"round3 parsed DateTime and version integrated");
        fails(()->Models.read("Devices",ApiContract.map("create_time","2026-01-01")));
        for(Object value:Arrays.asList(null,"文本",true,false,14,-1,1.5,0.0,-0.0)){
            Models.Record m=Models.read("Message",ApiContract.map("msg_type",101,"msg_content",value));check(m.unresolved.isEmpty(),"known receiver supported");check(Objects.equals(m.toJson().get("msg_content"),DartConversions.messageContentString(value)),"content serialized as text/null");
        }
        check(DartConversions.messageContentString(Arrays.asList("a",true,null,2)).equals("[a, true, null, 2]"),"list uses Dart display, not JSON");
        check(DartConversions.messageContentString(ApiContract.map("x",Arrays.asList(1,2))).equals("{x: [1, 2]}"),"map separators");
        check(DartConversions.doubleString(1e20).equals("100000000000000000000.0"),"plain threshold");check(DartConversions.doubleString(1e21).equals("1e+21"),"exponent threshold");
        check(DartConversions.doubleString(1e-6).equals("0.000001"),"small plain threshold");check(DartConversions.doubleString(1e-7).equals("1e-7"),"small exponent threshold");
        check(DartConversions.doubleString(Double.NaN).equals("NaN"),"NaN");check(DartConversions.doubleString(Double.NEGATIVE_INFINITY).equals("-Infinity"),"infinity");
        check(DartConversions.messageContentString(1L<<40).equals("1099511627776"),"Mint native signed decimal");fails(()->DartConversions.messageContentString(new Object()));
        List<Object> cyclic=new ArrayList<>();cyclic.add(cyclic);fails(()->DartConversions.messageContentString(cyclic));
        check(Models.read("Message",ApiContract.map("msg_content",1L<<40)).toJson().get("msg_content").equals("1099511627776"),"Mint model serializer integrated");
        System.out.println("PASS "+checks+" model conversion assertions");
    }
}
