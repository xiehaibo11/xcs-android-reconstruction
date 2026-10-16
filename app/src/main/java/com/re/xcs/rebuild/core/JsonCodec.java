package com.re.xcs.rebuild.core;

import java.util.*;

/** Executable reconstruction utility, not recovered original Dart source. */
public final class JsonCodec {
    private JsonCodec() {}
    public static Object parse(String input) {
        Parser p = new Parser(input, false);
        Object value = p.value(); p.ws();
        if (p.at != input.length()) throw p.error("Trailing JSON input");
        return value;
    }
    /** Reconstruction hardening: rejects all duplicate keys, including unknown ones. */
    public static Object parseStrict(String input) { Parser p=new Parser(input,true); Object v=p.value();p.ws();if(p.at!=input.length())throw p.error("Trailing JSON input");return v;}
    @SuppressWarnings("unchecked")
    public static Map<String,Object> object(Object value) {
        if (!(value instanceof Map)) throw new IllegalArgumentException("Expected JSON object");
        for (Object k : ((Map<?,?>)value).keySet()) if (!(k instanceof String)) throw new IllegalArgumentException("Non-string key");
        return (Map<String,Object>)value;
    }
    @SuppressWarnings("unchecked")
    public static List<Object> array(Object value) {
        if (!(value instanceof List)) throw new IllegalArgumentException("Expected JSON array");
        return (List<Object>)value;
    }
    public static String stringify(Object value) { StringBuilder b=new StringBuilder(); write(value,b); return b.toString(); }
    private static void write(Object v,StringBuilder b) {
        if(v==null){b.append("null");return;}
        if(v instanceof String){quote((String)v,b);return;}
        if(v instanceof Boolean){b.append(v);return;}
        if(v instanceof Number){
            double d=((Number)v).doubleValue();
            if(Double.isNaN(d)||Double.isInfinite(d)) throw new IllegalArgumentException("Non-finite JSON number");
            b.append(v);return;
        }
        if(v instanceof Map){boolean first=true;b.append('{');for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){
            if(!(e.getKey() instanceof String))throw new IllegalArgumentException("Non-string key");
            if(!first)b.append(',');first=false;quote((String)e.getKey(),b);b.append(':');write(e.getValue(),b);
        }b.append('}');return;}
        if(v instanceof Iterable){boolean first=true;b.append('[');for(Object e:(Iterable<?>)v){if(!first)b.append(',');first=false;write(e,b);}b.append(']');return;}
        throw new IllegalArgumentException("Unsupported JSON value: "+v.getClass().getName());
    }
    private static void quote(String s,StringBuilder b){b.append('"');for(int i=0;i<s.length();i++){char c=s.charAt(i);switch(c){
        case '"':b.append("\\\"");break;case '\\':b.append("\\\\");break;case '\b':b.append("\\b");break;case '\f':b.append("\\f");break;case '\n':b.append("\\n");break;case '\r':b.append("\\r");break;case '\t':b.append("\\t");break;
        default:if(c<32)b.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else b.append(c);
    }}b.append('"');}
    private static final class Parser{
        final String s;final boolean rejectDuplicates;int at;Parser(String s,boolean rejectDuplicates){if(s==null)throw new NullPointerException("json");this.s=s;this.rejectDuplicates=rejectDuplicates;}
        IllegalArgumentException error(String why){return new IllegalArgumentException(why+" at offset "+at);}
        void ws(){while(at<s.length()&&(s.charAt(at)==' '||s.charAt(at)=='\n'||s.charAt(at)=='\r'||s.charAt(at)=='\t'))at++;}
        Object value(){ws();if(at==s.length())throw error("Missing value");char c=s.charAt(at);
            if(c=='"')return string();if(c=='{')return object();if(c=='[')return array();
            if(s.startsWith("true",at)){at+=4;return Boolean.TRUE;}if(s.startsWith("false",at)){at+=5;return Boolean.FALSE;}if(s.startsWith("null",at)){at+=4;return null;}
            return number();
        }
        Map<String,Object> object(){at++;Map<String,Object> m=new LinkedHashMap<>();ws();if(take('}'))return m;
            do{ws();if(at==s.length()||s.charAt(at)!='"')throw error("Expected key");String k=string();if(rejectDuplicates&&m.containsKey(k))throw error("Duplicate key");ws();if(!take(':'))throw error("Expected colon");m.put(k,value());ws();if(take('}'))return m;}while(take(','));throw error("Expected comma or object end");}
        List<Object> array(){at++;List<Object> a=new ArrayList<>();ws();if(take(']'))return a;
            do{a.add(value());ws();if(take(']'))return a;}while(take(','));throw error("Expected comma or array end");}
        boolean take(char c){if(at<s.length()&&s.charAt(at)==c){at++;return true;}return false;}
        String string(){at++;StringBuilder b=new StringBuilder();while(at<s.length()){char c=s.charAt(at++);if(c=='"')return b.toString();if(c<32)throw error("Control character");
            if(c!='\\'){b.append(c);continue;}if(at==s.length())throw error("Unfinished escape");c=s.charAt(at++);switch(c){
                case '"':case '\\':case '/':b.append(c);break;case 'b':b.append('\b');break;case 'f':b.append('\f');break;case 'n':b.append('\n');break;case 'r':b.append('\r');break;case 't':b.append('\t');break;
                case 'u':if(at+4>s.length())throw error("Short Unicode escape");try{b.append((char)Integer.parseInt(s.substring(at,at+4),16));}catch(NumberFormatException e){throw error("Invalid Unicode escape");}at+=4;break;
                default:throw error("Invalid escape");
            }}throw error("Unterminated string");}
        Number number(){int start=at;take('-');if(take('0')){if(at<s.length()&&Character.isDigit(s.charAt(at)))throw error("Leading zero");}
            else{int digits=at;while(at<s.length()&&s.charAt(at)>='0'&&s.charAt(at)<='9')at++;if(digits==at)throw error("Expected number");}
            boolean decimal=false;if(take('.')){decimal=true;int d=at;while(at<s.length()&&s.charAt(at)>='0'&&s.charAt(at)<='9')at++;if(d==at)throw error("Missing fraction");}
            if(at<s.length()&&(s.charAt(at)=='e'||s.charAt(at)=='E')){decimal=true;at++;if(!take('+'))take('-');int d=at;while(at<s.length()&&s.charAt(at)>='0'&&s.charAt(at)<='9')at++;if(d==at)throw error("Missing exponent");}
            try{return dartNumber(s.substring(start,at),decimal,at<s.length());}catch(NumberFormatException e){throw error("Invalid numeric literal");}
        }
        /** Numeric fast path adapted from Dart SDK 3.5.2 convert_patch.dart.
         * Copyright (c) 2014, the Dart project authors. All rights reserved. BSD license is retained in
         * evidence/round3/numeric_json/DART_LICENSE.txt.
         * Dart jsonDecode has separate completed-token and end-of-chunk paths.
         * Signed64 integers stay integers; larger literals become double, including
         * infinities. A delimiter permits its numeric fast path, including exponent
         * >400 shortcuts. See evidence/round3/numeric_json for reference cases.
         */
        private strictfp Number dartNumber(String token,boolean decimal,boolean terminated){
            if(!decimal){
                try{return Long.valueOf(token);}catch(NumberFormatException overflow){return Double.valueOf(token);}
            }
            if(!terminated)return Double.valueOf(token); // finishChunkNumber -> buffer.parseDouble
            int p=0,sign=1;if(token.charAt(p)=='-'){sign=-1;p++;}
            long integer=0;double mantissa=0.0;boolean floating=false;int count=0;
            while(p<token.length()&&token.charAt(p)>='0'&&token.charAt(p)<='9'){
                int digit=token.charAt(p++)-'0';
                if(count>=18){int high=digit>>3;if(sign<0)high&=digit;
                    if(count==19||integer-high < -922337203685477580L){floating=true;mantissa=9223372036854775808.0;}}
                integer=10*integer-digit;count++;
            }
            if(p<token.length()&&token.charAt(p)=='.'){
                if(!floating){floating=true;mantissa=integer==0?0.0:-(double)integer;}
                integer=0;p++;
                while(p<token.length()&&token.charAt(p)>='0'&&token.charAt(p)<='9'){
                    mantissa=10.0*mantissa+(token.charAt(p++)-'0');integer--;
                }
            }
            if(p<token.length()){
                if(!floating){floating=true;mantissa=integer==0?0.0:-(double)integer;integer=0;}
                p++;int exponentSign=1;if(token.charAt(p)=='+'||token.charAt(p)=='-'){
                    if(token.charAt(p)=='-')exponentSign=-1;p++;
                }
                long exponent=0;boolean overflow=false;
                while(p<token.length()){exponent=10*exponent+(token.charAt(p++)-'0');if(exponent>400)overflow=true;}
                if(overflow){
                    if(mantissa==0.0||exponentSign<0)return sign<0?-0.0:0.0;
                    return sign<0?Double.NEGATIVE_INFINITY:Double.POSITIVE_INFINITY;
                }
                integer+=exponentSign*exponent;
            }
            if(mantissa<9007199254740992.0&&integer>=-22&&integer<=22){
                double signed=mantissa*sign;
                if(integer<0)return signed/POWERS_OF_TEN[(int)-integer];
                if(integer==0)return signed;
                return signed*POWERS_OF_TEN[(int)integer];
            }
            return Double.valueOf(token);
        }
        private static final double[] POWERS_OF_TEN={1.0,1e1,1e2,1e3,1e4,1e5,1e6,1e7,1e8,1e9,1e10,1e11,1e12,1e13,1e14,1e15,1e16,1e17,1e18,1e19,1e20,1e21,1e22};
    }
}
