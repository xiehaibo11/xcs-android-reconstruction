package com.re.xcs.rebuild.core;

import java.math.*;
import java.util.*;

/** Confirmed dynamic targets; bounded Java implementation, not recovered Dart source. */
public final class DartConversions {
    private DartConversions() {}
    public static Double toDouble(Object value) {
        if(DartIntegers.isInteger(value))return DartIntegers.toDouble(value);
        if(value instanceof Double)return (Double)value;
        throw new IllegalArgumentException("Devices.version.toDouble requires a non-null int or double");
    }
    public static String messageContentString(Object value) {
        if(value==null)return null; // Message.toJson branches around the dynamic call for null.
        return stringify(value,new IdentityHashMap<Object,Boolean>());
    }
    private static String stringify(Object value,IdentityHashMap<Object,Boolean> active) {
        if(value==null)return "null";
        if(value instanceof String)return (String)value;
        if(value instanceof Boolean)return ((Boolean)value)?"true":"false";
        if(DartIntegers.isInteger(value))return DartIntegers.toDartString(value);
        if(value instanceof Double)return doubleString((Double)value);
        if(value instanceof DartDateTime)return value.toString(); // Original CID4688 selector -> 0x5715ac.
        if(value instanceof List||value instanceof Map){
            if(active.put(value,Boolean.TRUE)!=null)throw new UnsupportedOperationException("Cyclic Dart collection formatting not reconstructed");
            try {
                StringBuilder b=new StringBuilder(value instanceof Map?"{":"[");boolean first=true;
                if(value instanceof Map)for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()){
                    if(!first)b.append(", ");first=false;b.append(stringify(entry.getKey(),active)).append(": ").append(stringify(entry.getValue(),active));
                }else for(Object element:(List<?>)value){if(!first)b.append(", ");first=false;b.append(stringify(element,active));}
                return b.append(value instanceof Map?"}":"]").toString();
            }finally{active.remove(value);}
        }
        throw new UnsupportedOperationException("Unrecovered custom msg_content.toString receiver");
    }
    /** Shortest decimal which round-trips, then Dart VM 3.5.2 display thresholds (-6,21).
     * Differentially checked against its local double-conversion source; see round2/models.
     */
    public static String doubleString(double value) {
        if(Double.isNaN(value))return "NaN";
        if(Double.isInfinite(value))return value<0?"-Infinity":"Infinity";
        boolean negative=Double.doubleToRawLongBits(value)<0;
        if(value==0)return negative?"-0.0":"0.0";
        double magnitude=Math.abs(value);BigDecimal exact=new BigDecimal(magnitude),best=null;
        for(int digits=1;digits<=17&&best==null;digits++){
            BigDecimal rounded=exact.round(new MathContext(digits,RoundingMode.HALF_EVEN));
            BigDecimal unit=BigDecimal.ONE.scaleByPowerOfTen(rounded.precision()-rounded.scale()-digits);
            for(int delta=-1;delta<=1;delta++){
                BigDecimal candidate=rounded.add(unit.multiply(BigDecimal.valueOf(delta)));
                if(candidate.signum()<=0||Double.doubleToRawLongBits(candidate.doubleValue())!=Double.doubleToRawLongBits(magnitude))continue;
                BigDecimal distance=candidate.subtract(exact).abs();
                if(best==null||distance.compareTo(best.subtract(exact).abs())<0||distance.compareTo(best.subtract(exact).abs())==0&&!candidate.unscaledValue().abs().testBit(0))best=candidate;
            }
        }
        if(best==null)throw new IllegalStateException("No shortest double representation");
        best=best.stripTrailingZeros();String digits=best.unscaledValue().toString();int exponent=digits.length()-best.scale()-1;
        String text;
        if(exponent>=-6&&exponent<21){text=best.toPlainString();if(text.indexOf('.')<0)text+=".0";}
        else{text=digits.substring(0,1)+(digits.length()==1?"":"."+digits.substring(1))+"e"+(exponent>=0?"+":"")+exponent;}
        return negative?"-"+text:text;
    }
}
