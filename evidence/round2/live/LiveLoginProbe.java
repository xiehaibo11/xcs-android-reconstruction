import com.re.xcs.rebuild.core.*;
import com.re.xcs.rebuild.net.WsSession;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Explicitly invoked read-only integration probe; credentials are read from stdin, never saved. */
public final class LiveLoginProbe {
    static Object shape(Object v,int depth) {
        if(v==null)return "null";
        if(depth>8)return "depth-limit";
        if(v instanceof Map){Map<String,Object> m=new LinkedHashMap<>();for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet())m.put(String.valueOf(e.getKey()),shape(e.getValue(),depth+1));return m;}
        if(v instanceof List){List<?> a=(List<?>)v;List<Object> types=new ArrayList<>();for(Object o:a){Object s=shape(o,depth+1);if(!types.contains(s))types.add(s);if(types.size()>=8)break;}return ApiContract.map("kind","array","count",a.size(),"observed_element_shapes",types);}
        if(v instanceof String)return "string";
        if(v instanceof Boolean)return "boolean";
        return v instanceof Double||v instanceof Float?"double":v instanceof Number?"integer":v.getClass().getSimpleName();
    }
    public static void main(String[] args)throws Exception {
        String input;Console console=System.console();
        if(console!=null){char[] c=console.readPassword("Credentials JSON (not echoed): ");input=new String(c);Arrays.fill(c,'\0');}
        else input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8)).readLine();
        Map<String,Object> supplied=JsonCodec.object(JsonCodec.parse(input));input=null;
        String host=Models.string(supplied.remove("host")),name=Models.string(supplied.remove("username")),password=Models.string(supplied.remove("password"));
        Map<String,Object> report=new LinkedHashMap<>();List<Object> requests=new ArrayList<>();report.put("requests",requests);
        report.put("credentials_recorded",false);report.put("raw_responses_recorded",false);report.put("device_mutation_requests_permitted",false);
        SessionState state=new SessionState();JsonHttpTransport http=new JsonHttpTransport(state,"2.1.6");
        Set<String> allowed=new HashSet<>(Arrays.asList("/api/login/login/distinguish","/api/server/get_server_addr","/api/app/check_update","/api/mj/get_config","/api/config/get_config","/api/zhuo/device_status_all"));
        ApiContract.Transport recorded=request->{if(!allowed.contains(request.path))throw new IOException("Request outside read-only probe scope");ApiContract.Response response=http.execute(request);Map<String,Object> summary=ApiContract.map("path",request.path,"method",request.method,"status",response.status,"response_shape",shape(response.data,0));if(response.data instanceof Map){Object success=response.object().get("success");if(success instanceof Boolean)summary.put("success",success);}requests.add(summary);return response;};
        WsSession socket=null;
        try {
            Path assets=Paths.get(args[0]);
            LoginFlow.Result result=new LoginFlow(state,recorded).login(host,name,password,new String(Files.readAllBytes(assets.resolve("key/pub_key.pem")),StandardCharsets.UTF_8),new String(Files.readAllBytes(assets.resolve("key/private_key.pem")),StandardCharsets.UTF_8),"2.1.6");
            name=null;password=null;state.username="";state.password="";
            report.put("login","PASS");report.put("rsa_server_config_decrypted",true);report.put("device_count",state.channels.size());report.put("model_unresolved",result.unresolved);
            for(ApiContract.Request request:Arrays.asList(ApiContract.mjConfig(),ApiContract.config(),ApiContract.deviceStatus()))recorded.execute(request);
            CountDownLatch auth=new CountDownLatch(1);List<Object> events=Collections.synchronizedList(new ArrayList<>());List<Object> messageTypes=Collections.synchronizedList(new ArrayList<>());
            socket=new WsSession(new WsSession.Listener(){public void state(boolean connected,boolean authenticated,String detail){events.add(ApiContract.map("connected",connected,"authenticated",authenticated));if(authenticated)auth.countDown();}public void business(Map<String,Object> message){messageTypes.add(message.get("msg_type"));}public void error(String detail){events.add(ApiContract.map("event","transport_error","detail_recorded",false));}});
            socket.start(state.businessHost,state.jwt);boolean authenticated=auth.await(12,TimeUnit.SECONDS);
            report.put("websocket_authenticated",authenticated);report.put("websocket_events",events);report.put("observed_msg_types",messageTypes);report.put("status",authenticated?"PASS_READ_ONLY_LOGIN_AND_WS":"HTTP_PASS_WS_NOT_CONFIRMED");
        } catch(Exception e){report.put("status","FAIL");report.put("exception_type",e.getClass().getName());if(e instanceof LoginFlow.Failure)report.put("failure_stage",((LoginFlow.Failure)e).stage);}
        finally {if(socket!=null)socket.close();state.jwt="";state.username="";state.password="";}
        System.out.println(JsonCodec.stringify(report));
    }
}
