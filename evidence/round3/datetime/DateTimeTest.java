package com.re.xcs.rebuild.core;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.*;
public final class DateTimeTest {
 private static int count;
 private static final TimeZone UTC=TimeZone.getTimeZone("UTC");
 private static void eq(Object expected,Object actual,String note){count++;if(!Objects.equals(expected,actual))throw new AssertionError(note+": expected="+expected+" actual="+actual);}
 private static DartDateTime parse(String input){return DartDateTime.parse(input,UTC);}
 private static void iso(String input,String output){eq(output,parse(input).toIso8601String(),input);}
 private static void bad(String input,String reason){try{parse(input);throw new AssertionError("accepted invalid "+input);}catch(DartDateTime.FormatException e){eq(reason,e.reason,input);eq(input,e.source,"error source");}}
 public static void main(String[] args)throws Exception{
  if(args.length>0&&args[0].equals("oracle")){TimeZone zone=TimeZone.getTimeZone(args[1]);BufferedReader in=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String s;while((s=in.readLine())!=null){String input=new String(Base64.getDecoder().decode(s),StandardCharsets.UTF_8);try{DartDateTime d=DartDateTime.parse(input,zone);System.out.println("ok\t"+d.microsecondsSinceEpoch()+"\t"+d.millisecondsSinceEpoch()+"\t"+d.toIso8601String()+"\t"+d.toString()+"\t"+d.isUtc());}catch(DartDateTime.FormatException e){System.out.println("error\tFormatException\t"+e.reason);}catch(DartDateTime.RangeError e){System.out.println("error\tRangeError\tother");}catch(DartDateTime.ArgumentError e){System.out.println("error\tArgumentError\tother");}}return;}
  iso("1970-01-01T00:00:00Z","1970-01-01T00:00:00.000Z");
  eq(0L,parse("1970-01-01T00:00:00Z").microsecondsSinceEpoch(),"epoch");
  iso("2020-01-42","2020-02-11T00:00:00.000");
  iso("2020-00-00T99:99:99Z","2019-12-04T04:40:39.000Z");
  iso("2020-13-01T24:00:60Z","2021-01-02T00:01:00.000Z");
  iso("2000-02-29","2000-02-29T00:00:00.000");
  iso("1900-02-29","1900-03-01T00:00:00.000");
  iso("0000-02-29","0000-02-29T00:00:00.000");
  iso("-0001-01-01","-0001-01-01T00:00:00.000");
  iso("+010000-01-01T00Z","+010000-01-01T00:00:00.000Z");
  eq("10000-01-01 00:00:00.000Z",parse("+010000-01-01T00Z").toString(),"toString expanded positive year");
  eq("-10000-01-01 00:00:00.000Z",parse("-010000-01-01T00Z").toString(),"toString expanded negative year");
  iso("20200102T030405,123456789+08:30","2020-01-01T18:34:05.123456Z");
  iso("2020-01-02 03:04:05.1 z","2020-01-02T03:04:05.100Z");
  iso("2020-01-02 03:04:05.000001-02","2020-01-02T05:04:05.000001Z");
  iso("2020-01-02 03+99:99","2019-12-28T22:21:00.000Z");
  eq(-1L,parse("1969-12-31T23:59:59.999999Z").microsecondsSinceEpoch(),"negative microsecond");
  eq(-1L,parse("1969-12-31T23:59:59.999999Z").millisecondsSinceEpoch(),"negative milliseconds floors");
  eq(999,parse("1969-12-31T23:59:59.999999Z").microsecond(),"negative microsecond remainder");
  iso("+275760-09-13T00:00:00Z","+275760-09-13T00:00:00.000Z");
  iso("-271821-04-20T00:00:00Z","-271821-04-20T00:00:00.000Z");
  eq(DartDateTime.MAX_MICROSECONDS_SINCE_EPOCH,parse("+275760-09-13T00:00:00Z").microsecondsSinceEpoch(),"max range");
  eq(-DartDateTime.MAX_MICROSECONDS_SINCE_EPOCH,parse("-271821-04-20T00:00:00Z").microsecondsSinceEpoch(),"min range");
  bad("+275760-09-13T00:00:00.000001Z","Time out of range");bad("-271821-04-19T23:59:59.999999Z","Time out of range");
  for(String x:new String[]{"","2020-01-01Z","2020-1-01","2020-01-01t12:00"," 2020-01-01","2020-01-01 ","2020-01-01\n","2020-01-01\r\n","2020-01-01T12:34.5","２０２０-01-01","2020-01-01T12:00:00.","2020-01-01T12+8","2020-01-01T12:00:00+00:00Z"})bad(x,"Invalid date format");
  TimeZone la=TimeZone.getTimeZone("America/Los_Angeles");
  DartDateTime gap=DartDateTime.parse("2024-03-10T02:30:00",la);eq("2024-03-10T03:30:00.000",gap.toIso8601String(),"DST gap chooses earlier offset");eq(parse("2024-03-10T10:30:00Z").microsecondsSinceEpoch(),gap.microsecondsSinceEpoch(),"gap UTC");
  DartDateTime overlap=DartDateTime.parse("2024-11-03T01:30:00",la);eq(parse("2024-11-03T08:30:00Z").microsecondsSinceEpoch(),overlap.microsecondsSinceEpoch(),"overlap earliest instant");
  eq(false,parse("1970-01-01").isUtc(),"suffix-free is local even UTC timezone");eq(true,parse("1970-01-01T00+00").isUtc(),"explicit zero offset is UTC");eq(false,parse("1970-01-01").equals(parse("1970-01-01T00Z")),"isUtc participates in equality");
  TimeZone old=TimeZone.getDefault();try{TimeZone.setDefault(UTC);DartDateTime cached=DartDateTime.parse("2020-01-01");TimeZone.setDefault(la);eq("2020-01-01T00:00:00.000",cached.toIso8601String(),"constructor parts cache");}finally{TimeZone.setDefault(old);}
  try{parse("-290308-12-21T19:59:05.224192Z");throw new AssertionError("minimum long was accepted");}catch(DartDateTime.RangeError e){eq("millisecondsSinceEpoch",e.argumentName,"minimum long reaches constructor RangeError");}
  try{DartDateTime.parse("-290308-12-21T19:59:05.224192",la);throw new AssertionError("minimum long local was accepted");}catch(DartDateTime.ArgumentError e){eq(-18444944491255L,e.seconds,"minimum long local native offset guard");}
  System.out.println("PASS "+count+" DateTime assertions");
  if(args.length==2&&args[0].equals("fixtures"))replayFixtures(args[1]);
 }
 private static List<String> lines(ZipFile zip,String entry)throws IOException{List<String> out=new ArrayList<>();try(BufferedReader reader=new BufferedReader(new InputStreamReader(zip.getInputStream(zip.getEntry(entry)),StandardCharsets.UTF_8))){String s;while((s=reader.readLine())!=null)out.add(s);}return out;}
 private static String describe(String input,TimeZone zone){try{DartDateTime d=DartDateTime.parse(input,zone);return "ok\t"+d.microsecondsSinceEpoch()+"\t"+d.millisecondsSinceEpoch()+"\t"+d.toIso8601String()+"\t"+d.toString()+"\t"+d.isUtc();}catch(DartDateTime.FormatException e){return "error\tFormatException\t"+e.reason;}catch(DartDateTime.RangeError e){return "error\tRangeError\tother";}catch(DartDateTime.ArgumentError e){return "error\tArgumentError\tother";}}
 private static void replayFixtures(String file)throws IOException{
  int comparisons=0;try(ZipFile zip=new ZipFile(file)){List<String> inputs=lines(zip,"inputs.base64.txt");for(String zone:lines(zip,"zones.txt")){List<String> expected=lines(zip,"oracle-"+zone.replace('/','_')+".tsv");if(expected.size()!=inputs.size())throw new AssertionError("Fixture length mismatch");TimeZone tz=TimeZone.getTimeZone(zone);for(int i=0;i<inputs.size();i++){String input=new String(Base64.getDecoder().decode(inputs.get(i)),StandardCharsets.UTF_8);String actual=describe(input,tz);if(!actual.equals(expected.get(i)))throw new AssertionError("Reference fixture mismatch zone="+zone+" case="+i+" input="+input+" expected="+expected.get(i)+" actual="+actual);comparisons++;}}}
  System.out.println("PASS "+comparisons+" saved Dart 3.5.2 reference comparisons (host timezone database)");
 }

}
