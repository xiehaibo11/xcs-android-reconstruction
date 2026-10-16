import com.re.xcs.rebuild.core.GoBytePrimitives;
import java.io.*;
import java.nio.file.*;
import java.util.zip.GZIPInputStream;

/** Runs against recorded original-ARM64 results; no original APK/Unicorn needed. */
public final class PortablePrimitiveTest {
    public static void main(String[] args) throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("fixture.gz temporary-raw-fixture");
        try(InputStream zipped=new GZIPInputStream(Files.newInputStream(Paths.get(args[0])))) {
            Files.copy(zipped,Paths.get(args[1]),StandardCopyOption.REPLACE_EXISTING);
        }
        int boundaryChecks=GoBytePrimitivesProbe.runBoundaryChecks();
        int cases;
        try(DataInputStream in=new DataInputStream(new BufferedInputStream(Files.newInputStream(Paths.get(args[1]))))) {
            byte[] magic=new byte[8];in.readFully(magic);
            if(!new String(magic,"US-ASCII").equals("XCSSIMD3"))throw new AssertionError("fixture format");
            cases=in.readInt();
            for(int i=0;i<cases;i++) {
                int size=in.readInt(),off=in.readInt(),len=in.readInt(),target=in.readInt();
                byte[] data=new byte[size];in.readFully(data);
                long count=in.readLong(),index=in.readLong();
                if(GoBytePrimitives.count(data,off,len,target)!=count || GoBytePrimitives.indexOf(data,off,len,target)!=index
                    || GoBytePrimitives.count(data,off,len,(byte)target)!=count || GoBytePrimitives.indexOf(data,off,len,(byte)target)!=index)
                    throw new AssertionError("original machine-code fixture mismatch at case "+i);
            }
            if(in.read()!=-1)throw new AssertionError("trailing fixture bytes");
        }
        System.out.println("{\"java_status\":\"PASS\",\"fixture_inputs\":"+cases+",\"result_checks\":"+(cases*4)+",\"boundary_checks\":"+boundaryChecks+"}");
    }
}
