package com.re.xcs.rebuild.net;

import com.re.xcs.rebuild.core.JsonCodec;
import com.re.xcs.rebuild.core.ApiContract;
import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;

/** Executable protocol reconstruction. See evidence/transport_contract.json.
 * Serializes state transitions; does not claim reproduction of Rust async races.
 */
public final class WsSession implements Closeable {
    public interface Listener {
        void state(boolean connected, boolean authenticated, String detail);
        void business(Map<String,Object> message);
        void error(String message);
    }
    private final Listener listener;
    private final int port;
    private final ScheduledExecutorService timers=Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService connections=Executors.newCachedThreadPool();
    private volatile WsWire wire;
    private URI uri; private String jwt="";
    private boolean connected,authenticated,monitor,connecting,reconnecting;
    private volatile boolean stopped;
    private long generation,lastHeartbeat;
    private ScheduledFuture<?> heartbeat,checker,retry,qosCleanup;
    private final Map<String,Long> received=new HashMap<>();
    public WsSession(Listener listener){this(listener,18889);}
    /** Package-private port injection for host loopback tests; production always uses 18889. */
    WsSession(Listener listener,int testPort){if(testPort<1||testPort>65535)throw new IllegalArgumentException("Invalid port");this.listener=listener;this.port=testPort;}
    public synchronized boolean isConnected(){return connected;}
    public synchronized boolean isAuthenticated(){return authenticated;}
    public synchronized void start(String host,String token){
        if(stopped)throw new IllegalStateException("Session closed");
        if(uri!=null)throw new IllegalStateException("Session already started; create a new session to change hosts");
        this.uri=URI.create("ws://"+host+":"+port+"/");this.jwt=token;connect();
    }
    private synchronized void connect(){
        if(connecting||connected||stopped)return;connecting=true;final long epoch=++generation;
        connections.submit(()->{
            WsWire candidate=null;
            try{
                candidate=new WsWire(uri);
                synchronized(this){
                    if(stopped||epoch!=generation){candidate.close();return;}
                    wire=candidate;connected=true;connecting=false;
                    listener.state(true,authenticated,"连接已建立，等待认证");
                    send(6,jwt,"","",false,UUID.randomUUID().toString());
                }
                for(String text=candidate.receiveText();text!=null;text=candidate.receiveText()) receive(text,epoch);
            }catch(Exception e){synchronized(this){if(!stopped&&epoch==generation)listener.error("WebSocket: "+e.getMessage());}}
            finally{
                if(candidate!=null)try{candidate.close();}catch(IOException ignored){/* socket already closed */}
                synchronized(this){
                    if(epoch==generation&&!stopped){connecting=false;connected=false;wire=null;stopHeartbeat();listener.state(false,authenticated,"连接断开");if(monitor){monitor=false;beginRetry();}}
                }
            }
        });
    }
    private synchronized void beginRetry(){
        if(stopped)return;reconnecting=true;
        if(retry!=null)retry.cancel(false);
        retry=timers.scheduleAtFixedRate(()->{synchronized(this){if(stopped)return;if(!connected)connect();else try{send(6,jwt,"","",false,UUID.randomUUID().toString());}catch(IOException e){listener.error(e.getMessage());}}},0,3,TimeUnit.SECONDS);
    }
    @SuppressWarnings("unchecked")
    private synchronized void receive(String text,long epoch)throws IOException{
        // Reconstruction policy: discard an obsolete reader after replacement.
        // This does not claim equivalence to the original Rust task scheduling.
        if(stopped||!connected||epoch!=generation)return;
        final Map<String,Object> m;
        try {m=JsonCodec.object(JsonCodec.parseStrict(text));}catch(RuntimeException e){throw new IOException("Invalid outer protocol: "+e.getMessage(),e);}
        int type=integer(m,"types",0);String data=string(m,"data_content"),from=string(m,"from"),to=string(m,"to"),fp=string(m,"fp");
        Object qosValue=m.getOrDefault("qos",Boolean.FALSE);if(!(qosValue instanceof Boolean))throw new IOException("qos must be bool");boolean qos=(Boolean)qosValue;
        Integer loginCode=null;
        if(type==50){
            try{
                Object parsed=JsonCodec.parseStrict(data);
                if(parsed instanceof List){List<Object>a=JsonCodec.array(parsed);if(a.size()!=3)throw new IOException("Login tuple length");parsed=ApiContract.map("code",a.get(0),"user_id",a.get(1),"data",a.get(2));}
                Map<String,Object> a=JsonCodec.object(parsed);
                if(!a.containsKey("code")||!(a.get("user_id")instanceof String)||!(a.get("data")instanceof String))throw new IOException("Missing login response fields");
                loginCode=integer(a,"code",0);
            }catch(Exception e){listener.error("无效认证响应: "+e.getMessage());return;}
        }
        if(qos&&!(type==50&&loginCode!=0)){
            boolean duplicate=received.containsKey(fp);received.put(fp,now());
            send(4,fp,to,from,false,UUID.randomUUID().toString());
            if(duplicate)return;
        }
        switch(type){
            case 50:
                if(retry!=null){retry.cancel(false);retry=null;}reconnecting=false;
                if(loginCode==0){authenticated=true;connected=true;monitor=true;startHeartbeat();listener.state(true,true,"认证成功");}
                else{connected=false;listener.state(false,authenticated,"认证被拒绝，code="+loginCode);if(wire!=null)wire.close();}
                break;
            case 51:lastHeartbeat=now();break;
            case 2:
                try{Map<String,Object> business=JsonCodec.object(JsonCodec.parse(data));int msg=integer(business,"msg_type",-1);if(msg==101||msg==102||msg>=113&&msg<=117)listener.business(business);}
                catch(RuntimeException|IOException e){listener.error("业务消息解析失败: "+e.getMessage());}break;
            case 52:listener.error("服务端错误 types=52；载荷含义尚未完整恢复");break;
            case 54:stopSession(false);listener.state(false,false,"服务端结束会话");break;
            // No outgoing QoS=true business caller has been recovered in this UI.
            // ACK receive tracking has no entries here; not a recovered full QoS sender.
            case 4:break;
            default:break;
        }
    }
    private static int integer(Map<String,Object> m,String key,int fallback)throws IOException{Object v=m.getOrDefault(key,fallback);if(!(v instanceof Byte||v instanceof Short||v instanceof Integer||v instanceof Long))throw new IOException(key+" must be i32");long n=((Number)v).longValue();if(n<Integer.MIN_VALUE||n>Integer.MAX_VALUE)throw new IOException(key+" outside i32");return (int)n;}
    private static String string(Map<String,Object>m,String key)throws IOException{Object v=m.getOrDefault(key,"");if(!(v instanceof String))throw new IOException(key+" must be String");return(String)v;}
    public static String packet(int type,String data,String from,String to,boolean qos,String fp){Map<String,Object>m=new LinkedHashMap<>();m.put("types",type);if(!data.isEmpty())m.put("data_content",data);if(!from.isEmpty())m.put("from",from);if(!to.isEmpty())m.put("to",to);if(!fp.isEmpty())m.put("fp",fp);m.put("qos",qos);return JsonCodec.stringify(m);}
    private void send(int t,String d,String f,String to,boolean q,String fp)throws IOException{if(wire==null)throw new IOException("No transport");wire.sendText(packet(t,d,f,to,q,fp));}
    private static long now(){return System.currentTimeMillis()/1000;}
    private synchronized void startHeartbeat(){
        stopHeartbeat();
        heartbeat=timers.scheduleAtFixedRate(()->{synchronized(this){if(!connected||stopped)return;try{send(1,"💓","","",false,UUID.randomUUID().toString());if(lastHeartbeat==0)lastHeartbeat=now();}catch(IOException e){listener.error(e.getMessage());}}},0,30,TimeUnit.SECONDS);
        checker=timers.scheduleAtFixedRate(()->{synchronized(this){if(lastHeartbeat!=0&&now()-lastHeartbeat>=35){stopHeartbeat();if(monitor){monitor=false;connected=false;WsWire old=wire;generation++;connecting=false;wire=null;if(old!=null)try{old.close();}catch(IOException ignored){}beginRetry();listener.state(false,authenticated,"心跳超时，正在重连");}}}},2,2,TimeUnit.SECONDS);
        qosCleanup=timers.scheduleAtFixedRate(()->{synchronized(this){long time=now();received.entrySet().removeIf(e->time-e.getValue()>59);}},0,60,TimeUnit.SECONDS);
    }
    private void stopHeartbeat(){if(heartbeat!=null)heartbeat.cancel(false);if(checker!=null)checker.cancel(false);if(qosCleanup!=null)qosCleanup.cancel(false);lastHeartbeat=0;}
    private synchronized void stopSession(boolean clearJwt){
        stopped=true;generation++;connected=false;authenticated=false;monitor=false;connecting=false;reconnecting=false;stopHeartbeat();if(retry!=null)retry.cancel(false);if(clearJwt)jwt="";
        if(wire!=null)try{wire.close();}catch(IOException ignored){}wire=null;received.clear();timers.shutdownNow();connections.shutdownNow();
    }
    public synchronized void logout(){if(connected)try{send(3,"","","",false,UUID.randomUUID().toString());}catch(IOException e){listener.error(e.getMessage());}stopSession(true);listener.state(false,false,"已退出连接");}
    @Override public void close(){stopSession(false);}
}
