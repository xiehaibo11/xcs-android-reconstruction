package com.re.xcs.rebuild;

import android.app.Instrumentation;
import android.content.Context;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Bundle;
import com.re.xcs.rebuild.core.*;
import com.re.xcs.rebuild.net.WsSession;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** Opt-in read-only integration test. Credentials arrive through an ephemeral adb-forwarded socket. */
public final class LiveLoginChecks extends Instrumentation {
    private String asset(String name)throws IOException {try(InputStream in=getTargetContext().getAssets().open(name);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1)out.write(b,0,n);return new String(out.toByteArray(),StandardCharsets.UTF_8);}}
    @Override public void onCreate(Bundle arguments){super.onCreate(arguments);start();}
    @Override public void onStart(){
        Map<String,Object> report=new LinkedHashMap<>();List<Object> requests=new ArrayList<>();List<String> checks=new ArrayList<>();
        report.put("requests",requests);report.put("checks",checks);report.put("credentials_saved",false);report.put("raw_responses_saved",false);report.put("device_mutation_requests_allowed",false);
        SessionState session=new SessionState();WsSession socket=null;
        try(LocalServerSocket secrets=new LocalServerSocket("xcs-rebuild-live-credentials")){
            Bundle ready=new Bundle();ready.putString("stream","READY_FOR_EPHEMERAL_CREDENTIALS\n");sendStatus(0,ready);
            Map<String,Object> supplied;
            try(LocalSocket local=secrets.accept()){local.setSoTimeout(10000);String line=new BufferedReader(new InputStreamReader(local.getInputStream(),StandardCharsets.UTF_8)).readLine();supplied=JsonCodec.object(JsonCodec.parse(line));}
            String host=Models.string(supplied.remove("host")),username=Models.string(supplied.remove("username")),password=Models.string(supplied.remove("password"));
            JsonHttpTransport http=new JsonHttpTransport(session,"2.1.6");
            Set<String> allowed=new HashSet<>(Arrays.asList("/api/login/login/distinguish","/api/server/get_server_addr","/api/app/check_update","/api/mj/get_config","/api/config/get_config","/api/zhuo/device_status_all"));
            ApiContract.Transport bounded=request->{if(!allowed.contains(request.path))throw new IOException("Not a read-only probe route");ApiContract.Response response=http.execute(request);Map<String,Object> observed=ApiContract.map("method",request.method,"path",request.path,"status",response.status);if(response.data instanceof Map){Object ok=response.object().get("success");if(ok instanceof Boolean)observed.put("success",ok);}requests.add(observed);return response;};
            LoginFlow.Result login=new LoginFlow(session,bounded).login(host,username,password,asset("key/pub_key.pem"),asset("key/private_key.pem"),"2.1.6");
            username=null;password=null;session.username="";session.password="";
            checks.add("Android HTTP login, JWT propagation and RSA server config decrypt");report.put("device_count",session.channels.size());report.put("model_unresolved",login.unresolved);
            for(Models.Channel channel:session.channels)if(!(channel.device.fields.get("version") instanceof Double))throw new AssertionError("version toDouble missing");
            checks.add("Live device versions pass confirmed numeric conversion");
            for(Models.Channel channel:session.channels){Object value=channel.device.fields.get("create_time");if(!(value instanceof DartDateTime))throw new AssertionError("create_time not parsed");DartDateTime date=(DartDateTime)value;DartDateTime again=DartDateTime.parse(date.toIso8601String());if(!date.equals(again))throw new AssertionError("create_time ISO roundtrip differs");}
            if(!login.unresolved.isEmpty())throw new AssertionError("Device model conversion remains unresolved");
            checks.add("Live device DateTime parse and ISO roundtrip complete without model conversion gaps");
            ApiContract.Response palette=bounded.execute(ApiContract.mjConfig());if(!palette.ok()||!Boolean.TRUE.equals(palette.object().get("success")))throw new AssertionError("Palette request failed");report.put("palette_count",JsonCodec.array(palette.object().get("list")).size());checks.add("Read-only palette load");
            ApiContract.Response config=bounded.execute(ApiContract.config());if(!config.ok()||!Boolean.TRUE.equals(config.object().get("success")))throw new AssertionError("Configuration request failed");Models.read("OnlineConfig",JsonCodec.object(config.object().get("data")));checks.add("Live configuration passes typed model converters");
            ApiContract.Response devices=bounded.execute(ApiContract.deviceStatus());if(!devices.ok()||!Boolean.TRUE.equals(devices.object().get("success")))throw new AssertionError("Device status request failed");report.put("status_device_count",JsonCodec.array(devices.object().get("data")).size());checks.add("Read-only device status load");
            CountDownLatch auth=new CountDownLatch(1);List<Object> states=Collections.synchronizedList(new ArrayList<>());
            socket=new WsSession(new WsSession.Listener(){public void state(boolean connected,boolean authenticated,String detail){states.add(ApiContract.map("connected",connected,"authenticated",authenticated));if(authenticated)auth.countDown();}public void business(Map<String,Object> message){/* No MessageEngine: cannot cause result uploads or device commands. */}public void error(String detail){/* Raw server strings/tokens are deliberately not recorded. */}});
            socket.start(session.businessHost,session.jwt);if(!auth.await(15,TimeUnit.SECONDS))throw new AssertionError("WS authentication not confirmed");checks.add("Android WebSocket upgrade and authentication");report.put("ws_states",states);report.put("status","PASS_READ_ONLY_LIVE_LOGIN");
        }catch(Throwable failure){report.put("status","FAIL");report.put("exception_type",failure.getClass().getName());if(failure instanceof LoginFlow.Failure)report.put("failure_stage",((LoginFlow.Failure)failure).stage);}
        finally{if(socket!=null)socket.close();session.jwt="";session.username="";session.password="";}
        try(OutputStream out=getTargetContext().openFileOutput("live-login-checks.json",Context.MODE_PRIVATE)){out.write(JsonCodec.stringify(report).getBytes(StandardCharsets.UTF_8));}catch(IOException e){report.put("write_failed",true);}
        Bundle result=new Bundle();result.putString("stream",JsonCodec.stringify(report)+"\n");finish(String.valueOf(report.get("status")).startsWith("PASS")?-1:0,result);
    }
}
