import com.re.xcs.rebuild.core.GoBytePrimitives;
import java.io.*;

/** Synthetic host-JVM probe. No Android, accounts or network. */
public final class GoBytePrimitivesProbe {
    private static int checks;
    private static void expect(Class<? extends Throwable> kind, Runnable action) {
        try {action.run();} catch (Throwable e) {
            if (kind.isInstance(e)) {checks++;return;}
            throw new AssertionError("wrong boundary exception",e);
        }
        throw new AssertionError("expected boundary exception");
    }
    public static int runBoundaryChecks() {
        checks=0;
        if (GoBytePrimitives.count(null,0,0,0)!=0 || GoBytePrimitives.indexOf(null,0,0,0)!=-1)
            throw new AssertionError("nil empty");
        checks+=2;
        byte[] a=new byte[8];
        int[][] bad={{-1,0},{0,-1},{9,0},{8,1},{7,2},{Integer.MAX_VALUE,1},{1,Integer.MAX_VALUE},{Integer.MIN_VALUE,Integer.MAX_VALUE}};
        for (int[] b:bad) {
            expect(IndexOutOfBoundsException.class,()->GoBytePrimitives.count(a,b[0],b[1],0));
            expect(IndexOutOfBoundsException.class,()->GoBytePrimitives.indexOf(a,b[0],b[1],0));
        }
        for(int target:new int[]{-1,256,Integer.MIN_VALUE,Integer.MAX_VALUE}) {
            expect(IllegalArgumentException.class,()->GoBytePrimitives.count(a,0,0,target));
            expect(IllegalArgumentException.class,()->GoBytePrimitives.indexOf(a,0,0,target));
        }
        for(int[] b:new int[][]{{0,1},{1,0},{-1,0},{0,-1}}) {
            expect(NullPointerException.class,()->GoBytePrimitives.count(null,b[0],b[1],0));
            expect(NullPointerException.class,()->GoBytePrimitives.indexOf(null,b[0],b[1],0));
        }
        if(GoBytePrimitives.count(a,8,0,0)!=0 || GoBytePrimitives.indexOf(a,8,0,0)!=-1)
            throw new AssertionError("empty at end");
        checks+=2;
        return checks;
    }
    public static void main(String[] args) throws Exception {
        runBoundaryChecks();
        DataInputStream in=new DataInputStream(new BufferedInputStream(System.in));
        DataOutputStream out=new DataOutputStream(new BufferedOutputStream(System.out));
        int cases=in.readInt();
        out.writeInt(cases);out.writeInt(checks);
        for(int k=0;k<cases;k++) {
            int size=in.readInt(),off=in.readInt(),len=in.readInt(),target=in.readInt();
            byte[] bytes=new byte[size];in.readFully(bytes);
            int count=GoBytePrimitives.count(bytes,off,len,target);
            int index=GoBytePrimitives.indexOf(bytes,off,len,target);
            if(count!=GoBytePrimitives.count(bytes,off,len,(byte)target)
                || index!=GoBytePrimitives.indexOf(bytes,off,len,(byte)target))
                throw new AssertionError("byte/int overload mismatch");
            out.writeInt(count);out.writeInt(index);
        }
        out.flush();
    }
}
