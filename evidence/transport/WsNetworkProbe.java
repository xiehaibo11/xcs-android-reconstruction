package com.re.xcs.rebuild.net;
import com.re.xcs.rebuild.core.JsonCodec;
import java.net.URI;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Host-only test peer. Never part of the APK. */
public final class WsNetworkProbe {
  static synchronized void emit(String event,Object... pairs) {
    Map<String,Object> data=new LinkedHashMap<>();data.put("event",event);data.put("at",System.currentTimeMillis());
    for(int i=0;i<pairs.length;i+=2)data.put((String)pairs[i],pairs[i+1]);
    System.out.println(JsonCodec.stringify(data));System.out.flush();
  }
  public static void main(String[] args)throws Exception {
    if(args[0].equals("wire")) {
      String mode=args[2];
      try(WsWire wire=new WsWire(new URI(args[1]))) {
        if(mode.equals("normal")) {
          wire.sendText("c".repeat(126));wire.sendText("L".repeat(65536));
          if(!"识别完整".equals(wire.receiveText()))throw new AssertionError("fragmented UTF-8 text");
          String large=wire.receiveText();if(large.length()!=65536||!large.equals("R".repeat(65536)))throw new AssertionError("64-bit frame length");
          if(wire.receiveText()!=null)throw new AssertionError("close return");
          emit("wire_pass");return;
        }
        wire.receiveText();throw new AssertionError("Expected protocol rejection: "+mode);
      } catch(IOException e) {
        if(mode.equals("normal"))throw e;
        emit("wire_rejected","reason",e.getMessage());return;
      }
    }
    AtomicInteger businessCount=new AtomicInteger();
    WsSession session=new WsSession(new WsSession.Listener(){
      public void state(boolean c,boolean a,String d){emit("state","connected",c,"authenticated",a,"detail",d);}
      public void business(Map<String,Object> m){businessCount.incrementAndGet();emit("business","message",m);}
      public void error(String m){emit("error","detail",m);}
    },Integer.parseInt(args[1]));
    session.start("127.0.0.1","local-test-token");
    try(BufferedReader commands=new BufferedReader(new InputStreamReader(System.in))) {
      for(String command=commands.readLine();command!=null;command=commands.readLine()) {
        if(command.equals("status"))emit("status","connected",session.isConnected(),"authenticated",session.isAuthenticated(),"business_count",businessCount.get());
        else if(command.equals("repeat_start")) {
          try{session.start("127.0.0.1","replacement-token");throw new AssertionError("Repeated start accepted");}
          catch(IllegalStateException expected){emit("repeat_start_rejected");}
        } else if(command.equals("stale_reader")) {
          // Supplemental direct regression assertion; real network tests are separate.
          Field generation=WsSession.class.getDeclaredField("generation");generation.setAccessible(true);
          Method receive=WsSession.class.getDeclaredMethod("receive",String.class,long.class);receive.setAccessible(true);
          int before=businessCount.get();
          receive.invoke(session,"{\"types\":2,\"data_content\":\"{\\\"msg_type\\\":117}\"}",generation.getLong(session)-1);
          if(before!=businessCount.get())throw new AssertionError("Obsolete reader dispatched business");
          emit("stale_reader_ignored");
        } else if(command.equals("logout")){session.logout();emit("finished");return;}
        else if(command.equals("close")){session.close();emit("finished");return;}
      }
    } finally {session.close();}
  }
}
