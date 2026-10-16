package com.re.xcs.rebuild.core;

import java.time.LocalDate;
import java.util.Objects;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Executable reconstruction of the observed Dart 3.5.2 VM DateTime parse/format path.
 * See evidence/round3/datetime. System timezone rules remain supplied by the host,
 * exactly as the Dart VM delegates offsets to its OS; matching tzdata is required.
 * This is newly written Java, not recovered original application source. */
public final class DartDateTime {
    public static final long MAX_MICROSECONDS_SINCE_EPOCH=8640000000000000000L;
    private static final long SECOND=1000000L,MINUTE=60*SECOND,HOUR=60*MINUTE,DAY=24*HOUR;
    private static final int[][] DAYS_UNTIL_MONTH={{0,31,59,90,120,151,181,212,243,273,304,334},{0,31,60,91,121,152,182,213,244,274,305,335}};
    // Java's $ also accepts a trailing newline; Dart's non-multiline ECMAScript $ does not.
    private static final Pattern PARSE=Pattern.compile("^([+-]?\\d{4,6})-?(\\d\\d)-?(\\d\\d)(?:[ T](\\d\\d)(?::?(\\d\\d)(?::?(\\d\\d)(?:[.,](\\d+))?)?)?( ?[zZ]| ?([-+])(\\d\\d)(?::?(\\d\\d))?)?)?\\z");
    private final long value;
    private final boolean utc;
    // DateTime._withValue validates microsecond, which eagerly fills the VM parts cache.
    private final Parts parts;

    public static final class FormatException extends IllegalArgumentException {
        public final String reason;
        public final String source;
        private FormatException(String reason,String source){super(reason);this.reason=reason;this.source=source;}
    }
    /** Dart _withValue's separate RangeError reached by the wrapped minimum-int edge. */
    public static final class RangeError extends IllegalArgumentException {
        public final String argumentName="millisecondsSinceEpoch";
        private RangeError(){super("millisecondsSinceEpoch outside Dart DateTime range");}
    }
    /** Original native DateTime offset guard rejects a seconds value outside signed-32-bit magnitude. */
    public static final class ArgumentError extends IllegalArgumentException {
        public final long seconds;
        private ArgumentError(long seconds){super("Timezone seconds outside Dart native range");this.seconds=seconds;}
    }
    private DartDateTime(long value,boolean utc,TimeZone zone){this.value=value;this.utc=utc;this.parts=new Parts(value+(utc?0:offsetSeconds(value,zone)*SECOND));}

    /** Parse using the device's current local timezone for inputs without a suffix. */
    public static DartDateTime parse(String input){return parse(input,TimeZone.getDefault());}
    /** Deterministic timezone injection for offline reference tests; explicit input offsets override it. */
    public static DartDateTime parse(String input,TimeZone localZone){
        Objects.requireNonNull(input,"formattedString");Objects.requireNonNull(localZone,"localZone");
        Matcher match=PARSE.matcher(input);
        if(!match.find())throw new FormatException("Invalid date format",input);
        int year=Integer.parseInt(match.group(1)),month=Integer.parseInt(match.group(2)),day=Integer.parseInt(match.group(3));
        int hour=number(match.group(4)),minute=number(match.group(5)),second=number(match.group(6));
        String fraction=match.group(7);int micros=0;
        for(int i=0;i<6;i++)micros=micros*10+(fraction!=null&&i<fraction.length()?fraction.charAt(i)^0x30:0);
        boolean utc=match.group(8)!=null;
        if(match.group(9)!=null)minute-=(match.group(9).equals("-")?-1:1)*(60*number(match.group(10))+number(match.group(11)));
        int zeroMonth=month-1;year+=Math.floorDiv(zeroMonth,12);zeroMonth=Math.floorMod(zeroMonth,12);
        long days=(long)day-1+DAYS_UNTIL_MONTH[leap(year)?1:0][zeroMonth]+dayFromYear(year);
        // ARM64 0x491a18..0x491a6c uses wrapping 64-bit MUL/ADD, without overflow traps.
        // Large six-digit years may wrap back into the allowed epoch range; preserve that behavior.
        long value=days*DAY+hour*HOUR+minute*MINUTE+second*SECOND+micros;
        TimeZone zone=(TimeZone)localZone.clone();
        if(!utc){
            if(Math.abs(value)>MAX_MICROSECONDS_SINCE_EPOCH+DAY)throw new FormatException("Time out of range",input);
            value-=localOffset(value,zone);
        }
        if(Math.abs(value)>MAX_MICROSECONDS_SINCE_EPOCH)throw new FormatException("Time out of range",input);
        // Equivalent to _withValue's independent range validation, including the minimum-long edge.
        if(value < -MAX_MICROSECONDS_SINCE_EPOCH || value > MAX_MICROSECONDS_SINCE_EPOCH)throw new RangeError();
        return new DartDateTime(value,utc,zone);
    }
    public boolean isUtc(){return utc;}
    public long microsecondsSinceEpoch(){return value;}
    public long millisecondsSinceEpoch(){return Math.floorDiv(value,1000);}
    public int year(){return parts.year;}
    public int month(){return parts.month;}
    public int day(){return parts.day;}
    public int hour(){return parts.hour;}
    public int minute(){return parts.minute;}
    public int second(){return parts.second;}
    public int millisecond(){return parts.millisecond;}
    public int microsecond(){return parts.microsecond;}
    public String toIso8601String(){return format(true);}
    @Override public String toString(){return format(false);}
    @Override public boolean equals(Object other){return other instanceof DartDateTime&&((DartDateTime)other).value==value&&((DartDateTime)other).utc==utc;}
    @Override public int hashCode(){return (int)((value^(value>>30))&0x3fffffff);}

    private String format(boolean iso){
        int y=parts.year;String year=(iso&&(y < -9999||y>9999))?(y<0?"-":"+")+digits(Math.abs(y),6):(y<0?"-":"")+digits(Math.abs(y),4);
        return year+"-"+digits(parts.month,2)+"-"+digits(parts.day,2)+(iso?"T":" ")+digits(parts.hour,2)+":"+digits(parts.minute,2)+":"+digits(parts.second,2)+"."+digits(parts.millisecond,3)+(parts.microsecond==0?"":digits(parts.microsecond,3))+(utc?"Z":"");
    }
    private static String digits(int n,int width){String s=Integer.toString(n);StringBuilder result=new StringBuilder();for(int i=s.length();i<width;i++)result.append('0');return result.append(s).toString();}
    private static int number(String s){return s==null?0:Integer.parseInt(s);}
    private static boolean leap(int year){return year%4==0&&(year%16==0||year%100!=0);}
    private static long dayFromYear(int year){return 365L*(year-1970)+Math.floorDiv(year-1969,4)-Math.floorDiv(year-1901,100)+Math.floorDiv(year-1601,400);}
    private static int equivalentYear(int year){int weekday=(int)Math.floorMod(dayFromYear(year)+4,7);int recent=(leap(year)?1956:1967)+weekday*12;return 2008+Math.floorMod(recent-2008,28);}
    private static long equivalentSeconds(long micros){
        long seconds=(micros-(micros<0?SECOND-1:0))/SECOND; // VM floor helper uses wrapping subtraction.
        if(Math.abs(seconds)>0x7fffffffL){int year=yearsFromSeconds(seconds);seconds+=(dayFromYear(equivalentYear(year))-dayFromYear(year))*86400;}
        return seconds;
    }
    private static int yearsFromSeconds(long seconds){
        long days=seconds/86400;
        if(days>0&&days<45290)return 1970+(int)((4*days+2)/1461);
        long micros=seconds*SECOND;
        long floored=(micros-(micros<0?DAY-1:0))/DAY;
        return LocalDate.ofEpochDay(floored).getYear();
    }
    private static long offsetSeconds(long micros,TimeZone zone){long seconds=equivalentSeconds(micros);if(Math.abs(seconds)>0x7fffffffL)throw new ArgumentError(seconds);return zone.getOffset(seconds*1000)/1000;}
    private static long localOffset(long micros,TimeZone zone){
        long offset=offsetSeconds(micros,zone)*SECOND;
        if(offset!=0){long offset2=offsetSeconds(micros-offset,zone)*SECOND;if(offset2!=offset){long offset3=offsetSeconds(micros-offset2,zone)*SECOND;return Math.min(offset2,offset3);}offset=offset2;}
        long offset4=offsetSeconds(micros-offset-2*HOUR,zone)*SECOND;
        if(offset4>offset){if(offset4==offset+2*HOUR)return offset4;long offset5=offsetSeconds(micros-offset4,zone)*SECOND;if(offset5==offset4)return offset4;}
        return offset;
    }
    private static final class Parts {
        final int year,month,day,hour,minute,second,millisecond,microsecond;
        Parts(long micros){LocalDate date=LocalDate.ofEpochDay(Math.floorDiv(micros,DAY));year=date.getYear();month=date.getMonthValue();day=date.getDayOfMonth();hour=(int)Math.floorMod(Math.floorDiv(micros,HOUR),24);minute=(int)Math.floorMod(Math.floorDiv(micros,MINUTE),60);second=(int)Math.floorMod(Math.floorDiv(micros,SECOND),60);millisecond=(int)Math.floorMod(Math.floorDiv(micros,1000),1000);microsecond=(int)Math.floorMod(micros,1000);}
    }
}
