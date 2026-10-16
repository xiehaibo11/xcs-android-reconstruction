package com.re.xcs.rebuild.core;

import java.io.*;
import java.math.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicLong;

public final class MintConversionTest {
    private static int assertions;
    private static void check(boolean ok, String why) {
        assertions++;
        if (!ok) throw new AssertionError(why);
    }
    private static void bits(long integer, long expected) {
        check(Double.doubleToRawLongBits(DartIntegers.toDouble(integer)) == expected, "toDouble " + integer);
    }
    public static void main(String[] args) throws Exception {
        long[] edges = {Long.MIN_VALUE, Long.MIN_VALUE + 1, -(1L<<53)-1,
            -(1L<<30)-1, -(1L<<30), -(1L<<30)+1, -1, 0, 1,
            (1L<<30)-1, 1L<<30, (1L<<30)+1, (1L<<53)-1, 1L<<53,
            (1L<<53)+1, (1L<<53)+2, (1L<<53)+3, Long.MAX_VALUE-1, Long.MAX_VALUE};
        String[] expected = {"-9223372036854775808", "-9223372036854775807", "-9007199254740993",
            "-1073741825", "-1073741824", "-1073741823", "-1", "0", "1", "1073741823",
            "1073741824", "1073741825", "9007199254740991", "9007199254740992", "9007199254740993",
            "9007199254740994", "9007199254740995", "9223372036854775806", "9223372036854775807"};
        for(int i=0;i<edges.length;i++) check(expected[i].equals(DartIntegers.toDartString(edges[i])), "integer decimal boundary " + i);
        check(DartIntegers.snapshotClassId(-(1L<<30)) == 59, "negative Smi edge");
        check(DartIntegers.snapshotClassId(-(1L<<30)-1) == 60, "negative Mint edge");
        check(DartIntegers.snapshotClassId((1L<<30)-1) == 59, "positive Smi edge");
        check(DartIntegers.snapshotClassId(1L<<30) == 60, "positive Mint edge");
        check("127".equals(DartIntegers.toDartString((byte)127)), "Byte");
        check("-32768".equals(DartIntegers.toDartString((short)-32768)), "Short");
        check("2147483647".equals(DartIntegers.toDartString(Integer.MAX_VALUE)), "Integer");
        bits(0,0L);
        bits(1,0x3ff0000000000000L);
        bits(-1,0xbff0000000000000L);
        bits((1L<<53)-1,0x433fffffffffffffL);
        bits((1L<<53)+1,0x4340000000000000L);
        bits((1L<<53)+2,0x4340000000000001L);
        bits((1L<<53)+3,0x4340000000000002L);
        bits(-(1L<<53)-1,0xc340000000000000L);
        bits(Long.MIN_VALUE,0xc3e0000000000000L);
        bits(Long.MAX_VALUE,0x43e0000000000000L);
        Object[] unsupported = {null,"123",true,1.0,1.0f,BigInteger.ONE,BigDecimal.ONE,new AtomicLong(1)};
        for(Object x:unsupported) {
            boolean stringRejected=false,doubleRejected=false;
            try { DartIntegers.toDartString(x); } catch (IllegalArgumentException e) { stringRejected=true; }
            try { DartIntegers.toDouble(x); } catch (IllegalArgumentException e) { doubleRejected=true; }
            check(stringRejected,"unsupported toString receiver");
            check(doubleRejected,"unsupported integer-to-double receiver");
        }
        int cases=0,smi=0,mint=0;
        if(args.length!=1)throw new IllegalArgumentException("Expected captured VM reference TSV");
        try(BufferedReader reader=Files.newBufferedReader(Paths.get(args[0]),StandardCharsets.UTF_8)) {
            String line;
            while((line=reader.readLine())!=null) {
                String[] p=line.split("\t");if(!p[0].equals("VALUE"))continue;
                long n=Long.parseLong(p[1]);int cid=Integer.parseInt(p[2]);long dv=Long.parseUnsignedLong(p[4],16);
                if(DartIntegers.snapshotClassId(n)!=cid)throw new AssertionError("CID mismatch " + n);
                if(!DartIntegers.toDartString(n).equals(p[3]))throw new AssertionError("decimal mismatch " + n);
                if(Double.doubleToRawLongBits(DartIntegers.toDouble(n))!=dv)throw new AssertionError("toDouble mismatch " + n);
                cases++;if(cid==59)smi++;else if(cid==60)mint++;else throw new AssertionError("unexpected CID");
            }
        }
        if(cases==0)throw new AssertionError("No oracle cases");
        System.out.println("{\"status\":\"PASS\",\"boundary_assertions\":"+assertions+
            ",\"differential_cases\":"+cases+",\"smi_cases\":"+smi+",\"mint_cases\":"+mint+",\"differences\":0}");
    }
}
