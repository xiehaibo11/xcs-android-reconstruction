package com.re.xcs.rebuild.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class NumericJsonTest {
    private static int assertions;
    private static void check(boolean condition,String text){assertions++;if(!condition)throw new AssertionError(text);}
    private static void reject(Runnable run,String text){try{run.run();}catch(IllegalArgumentException expected){assertions++;return;}throw new AssertionError(text);}
    private static Object unwrap(String mode,Object v){if(mode.equals("array"))return ((List<?>)v).get(0);if(mode.equals("object"))return ((Map<?,?>)v).get("n");return v;}
    public static void main(String[] args)throws Exception{
        check(JsonCodec.parse("-0").equals(0L),"integer negative zero");
        check(Double.doubleToRawLongBits((Double)JsonCodec.parse("-0.0"))==Long.MIN_VALUE,"double negative zero");
        check(JsonCodec.parse("9007199254740993").equals(9007199254740993L),"int precision above2^53");
        check(JsonCodec.parse("9223372036854775807").equals(Long.MAX_VALUE),"signed64 max");
        check(JsonCodec.parse("-9223372036854775808").equals(Long.MIN_VALUE),"signed64 min");
        check(Double.doubleToRawLongBits((Double)JsonCodec.parse("9223372036854775808"))==0x43e0000000000000L,"max+1 double");
        check(Double.doubleToRawLongBits((Double)JsonCodec.parse("-9223372036854775809"))==0xc3e0000000000000L,"min-1 double");
        check(JsonCodec.parse("1e309").equals(Double.POSITIVE_INFINITY),"positive infinity parse");
        check(JsonCodec.parse("-1e309").equals(Double.NEGATIVE_INFINITY),"negative infinity parse");
        check(Double.doubleToRawLongBits((Double)JsonCodec.parse("-1e-400"))==Long.MIN_VALUE,"underflow sign");
        for(double n:new double[]{Double.NaN,Double.POSITIVE_INFINITY,Double.NEGATIVE_INFINITY}){
            reject(()->JsonCodec.stringify(n),"nonfinite scalar encode");
            reject(()->JsonCodec.stringify(Arrays.asList(n)),"nonfinite list encode");
            Map<String,Object> value=new LinkedHashMap<>();value.put("n",n);
            reject(()->JsonCodec.stringify(value),"nonfinite map encode");
        }
        check(JsonCodec.stringify(Long.MIN_VALUE).equals("-9223372036854775808"),"signed64 encode exact");
        check(JsonCodec.stringify(Long.MAX_VALUE).equals("9223372036854775807"),"signed64 encode exact max");
        for(String invalid:new String[]{"+1","01","1.","1e","1e+","NaN","Infinity","1 2"})reject(()->JsonCodec.parse(invalid),"malformed number");
        int cases=0,integers=0,doubles=0,errors=0,nonfinite=0;
        try(BufferedReader reader=Files.newBufferedReader(Paths.get(args[0]),StandardCharsets.UTF_8)){
            String row;
            while((row=reader.readLine())!=null){
                String[] p=row.split("\t",-1);String source=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);cases++;
                for(boolean strict:new boolean[]{false,true}){
                    Object value;
                    try{value=unwrap(p[0],strict?JsonCodec.parseStrict(source):JsonCodec.parse(source));}
                    catch(IllegalArgumentException e){if(p[2].equals("error"))continue;throw new AssertionError("Unexpected rejection row "+cases+" "+source,e);}
                    if(p[2].equals("error"))throw new AssertionError("Malformed accepted row "+cases+" "+source);
                    if(p[2].equals("int")){
                        if(!(value instanceof Long)||!value.equals(Long.valueOf(p[3])))throw new AssertionError("Int mismatch row "+cases+" "+source+" -> "+value);
                    }else{
                        if(!(value instanceof Double)||Double.doubleToRawLongBits((Double)value)!=Long.parseUnsignedLong(p[3],16))throw new AssertionError("Double mismatch row "+cases+" "+source+" -> "+value+" expectedBits="+p[3]);
                        if(((Double)value).isInfinite()!=p[4].equals("nonfinite"))throw new AssertionError("Finiteness mismatch");
                    }
                }
                if(p[2].equals("int"))integers++;else if(p[2].equals("double")){doubles++;if(p[4].equals("nonfinite"))nonfinite++;}else errors++;
            }
        }
        if(cases==0)throw new AssertionError("Empty reference fixture");
        System.out.println("{\"status\":\"PASS\",\"boundary_assertions\":"+assertions+",\"differential_cases\":"+cases+",\"parser_modes_checked\":2,\"integer_cases\":"+integers+",\"double_cases\":"+doubles+",\"malformed_cases\":"+errors+",\"nonfinite_cases\":"+nonfinite+",\"differences\":0}");
    }
}
