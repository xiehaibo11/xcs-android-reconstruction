package com.re.xcs.rebuild.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;

/** Deterministic local behavioral regression checks. No business endpoint contacted. */
public final class BusinessCoreTest {
    static int checks;
    static void check(boolean test,String name){checks++;if(!test)throw new AssertionError(name);}
    static void throwsError(Runnable body,String name){boolean threw=false;try{body.run();}catch(RuntimeException e){threw=true;}check(threw,name);}
    public static void main(String[] args)throws Exception{
        Map<String,Object> parsed=JsonCodec.object(JsonCodec.parse("{\"n\":1,\"f\":1.0,\"s\":\"中文\\n\",\"v\":[null,true,false]}"));
        check(parsed.get("n") instanceof Long,"JSON preserves int");check(parsed.get("f") instanceof Double,"JSON preserves double");
        check(JsonCodec.stringify(parsed).contains("中文\\n"),"JSON escapes control chars");
        check(JsonCodec.object(JsonCodec.parse("{\"a\":1,\"a\":2}")).get("a").equals(2L),"Dart-compatible duplicate overwrite");
        throwsError(()->JsonCodec.parseStrict("{\"a\":1,\"a\":2}"),"strict rejects duplicate");
        throwsError(()->JsonCodec.parse("01"),"leading zero rejected");throwsError(()->JsonCodec.parse("1."),"missing fraction rejected");
        throwsError(()->JsonCodec.parse("{} true"),"trailing input rejected");throwsError(()->JsonCodec.stringify(Double.NaN),"NaN not JSON");
        ApiContract.Request login=ApiContract.login("user","pass");check(login.method.equals("POST")&&login.path.equals("/api/login/login/distinguish"),"login path");
        check(login.query.get("app_name").equals("xcs")&&JsonCodec.object(login.body).get("devicetype").equals(1),"login request tagged integer unwrapped");
        check(ApiContract.startPreview(7).method.equals("GET"),"preview starts GET");check(ApiContract.endPreview(7).body==null,"end preview empty data");
        check(ApiContract.previewImageType(null,null).path.endsWith("/null/1"),"nullable preview path semantics");
        check(ApiContract.defaultWifi().method.equals("POST"),"default WiFi POST");
        check(ApiContract.imageUrl("x/y","host").equals("http://host/x/y"),"image omits API port");
        check(ApiContract.imageUrl("https://other/x","host").equals("https://other/x"),"absolute image URL");
        check(ApiContract.decodeData("x","y,x|z,y").equals("z"),"substitutions reverse pair and ordered");
        throwsError(()->ApiContract.decodeData("x","broken"),"malformed rules explicit error");
        check(new ApiContract.Response(204,null).ok()&&!new ApiContract.Response(300,null).ok(),"HTTP ok boundaries");
        check(ApiContract.businessAccepted(new ApiContract.Response(200,ApiContract.map())),"missing success not false");
        check(!ApiContract.businessAccepted(new ApiContract.Response(200,ApiContract.map("success",false))),"business false rejected");
        check(ApiContract.passwordValidation("123456","x","x").isEmpty(),"new password has only nonempty test");
        check(!ApiContract.passwordValidation("12345","x","x").isEmpty(),"old password length");
        throwsError(()->Models.read("MessageUpImg",ApiContract.map("ai_precision",1)),"double model rejects int coercion");
        check(Models.read("MessageUpImg",ApiContract.map("ai_precision",1.0)).get("ai_precision").equals(1.0),"double model accepted");
        check(Models.read("ViewSetting",ApiContract.map("orientationHeight",1)).get("orientationHeight").equals(640.0),"original ViewSetting ignores persisted values");
        Models.Record device=Models.read("Devices",ApiContract.map("create_time","2026-01-01","version",2));
        check(device.unresolved.isEmpty()&&device.get("version").equals(2.0)&&device.get("create_time") instanceof DartDateTime,"device DateTime and numeric conversions integrated");check(device.toJson().get("create_time").equals("2026-01-01T00:00:00.000"),"device serializer emits Dart local ISO format");
        SessionState state=new SessionState();state.jwt="token";
        check(!state.onHttpError(new ApiContract.Response(401,ApiContract.map("code",400)))&&state.jwt.equals("token"),"401 requires both conditions");
        check(state.onHttpError(new ApiContract.Response(401,ApiContract.map("code",401)))&&state.jwt.isEmpty(),"401 clears JWT");
        check(state.requestHeaders("2.1.6").get("Authorization").equals("Bearer "),"empty JWT header preserved");
        Models.Channel channel=new Models.Channel(new Models.Device(ApiContract.map("id",7,"serial_no","0012","direction",1,"mj_count",4,"lighting_switch",1)));
        state.channels.add(channel);
        for(int i=1;i<=4;i++){Models.Tile t=new Models.Tile(i);t.result="11";channel.results.add(t);}
        check(ResultRules.validate(state.channels).valid(),"four same recognized tiles valid");
        check(ResultRules.uploadPayload(state.channels).get(0).get("serial_number").equals(12L),"serial numeric parsing");
        channel.results.get(0).result="12";check(!ResultRules.validate(state.channels).valid(),"counts below40 must be4");
        channel.results.get(0).result="";throwsError(()->ResultRules.validate(state.channels),"empty result throws before upload");channel.results.get(0).result="11";
        ResultRules.deleteMain(channel,2);check(channel.results.size()==3&&channel.results.get(1).sequence==2&&channel.removedOffset==1,"main delete shifts sequence and increments offset");
        ResultRules.deleteLeft(channel,2);check(channel.results.size()==2&&channel.results.get(1).sequence==3&&channel.removedOffset==1,"left delete does not shift");
        channel.results.clear();state.user.put("timeout",2);state.imageRules="A,A";state.businessHost="offline.test";
        FakeScheduler scheduler=new FakeScheduler();Events events=new Events();int[] loads={0};
        MessageEngine engine=new MessageEngine(state,(url,rules,done)->{loads[0]++;done.success("/local/image.png");},events,scheduler);
        engine.palette.add(ApiContract.map("number",11,"url","asset11"));engine.currentPreviewDeviceId=7;
        engine.accept(ApiContract.map("msg_type",117,"msg_content","0012|ignored"));check(channel.device.open(),"117 first segment serial");
        engine.accept(ApiContract.map("msg_type",115,"msg_content","0012"));check(!channel.device.open()&&channel.device.fields.get("online").equals(0),"115 offline clears lighting");
        engine.accept(ApiContract.map("msg_type",116,"msg_content","0012"));check(channel.device.fields.get("online").equals(1),"116 online");
        engine.accept(ApiContract.map("msg_type",102,"msg_content","8|wrong"));check(events.previews==0,"preview device filtered");
        engine.accept(ApiContract.map("msg_type",102,"msg_content","7|frame|ignored"));check(events.previews==1&&engine.previewFrame.equals("frame"),"preview takes segment1");
        engine.accept(ApiContract.map("msg_type",102,"msg_content","lateUnprefixed"));check(events.previews==2,"unprefixed frame accepted");
        engine.accept(ApiContract.map("msg_type",113,"msg_content",null));check(engine.countdown==2&&channel.results.isEmpty(),"113 starts countdown and clears");
        scheduler.periodic.run();check(engine.countdown==1,"countdown decrements");engine.accept(ApiContract.map("msg_type",113));check(engine.countdown==1,"113 ignored while positive");
        scheduler.periodic.run();check(engine.countdown==0&&events.ready==0,"expiry does not upload");
        engine.accept(ApiContract.map("msg_type",101,"msg_content",ApiContract.map("serial_number","0012","mahjong_number",1,"img","x")));
        check(channel.results.size()==1&&loads[0]==0&&events.ready==0,"placeholder skips GET and completeness");channel.results.clear();
        for(int i=1;i<=4;i++)engine.accept(ApiContract.map("msg_type",101,"msg_content",ApiContract.map("serial_number","0012","mahjong_number",i,"img","img","ai_val",11,"ai_precision",0.9)));
        check(loads[0]==4&&events.ready==1&&channel.results.get(0).confidence==0.9,"recognition equality triggers ready");
        engine.accept(ApiContract.map("msg_type",114,"msg_content","0012"));check(engine.countdown==0&&scheduler.delayed!=null,"114 closes and schedules5s");
        channel.results.remove(0);scheduler.delayed.run();check(events.shortfalls==1,"5s check reads live state");
        engine.endGamesAccepted();check(engine.statusText.equals("未开始游戏"),"endGames success state");engine.close();scheduler.shutdownNow();
        check(events.errors==0,"no unexpected receiver errors");
        Path temp=Files.createTempDirectory("xcs-local-test-");
        LocalConfig.writeLogin(temp.toFile(),"ip","user","password",false);check(LocalConfig.readLogin(temp.toFile()).get("password").equals(""),"remember false persists empty password");
        LocalConfig.writeLocalPhrase(temp.toFile(),"hello");check(LocalConfig.read(temp.resolve("inlet_pwd.conf").toFile()).equals("5d41402abc4b2a76b9719d911017c592"),"local phrase UTF8 MD5");
        throwsError(()->{try{LocalConfig.writeLocalPhrase(temp.toFile(),"6666");}catch(IOException e){throw new RuntimeException(e);}},"reserved phrase rejected");
        final boolean[] saved={false};new CachedImageLoader(r->new ApiContract.Response(500,"aGVsbG8="),temp.toFile(),Runnable::run).fetchAndCache("http://offline.test/img","A,A",new MessageEngine.ImageResult(){public void success(String path){try{saved[0]=new String(Files.readAllBytes(Paths.get(path)),StandardCharsets.UTF_8).equals("hello");}catch(IOException e){throw new RuntimeException(e);}}public void failure(Exception e){throw new RuntimeException(e);}});
        check(saved[0],"image pipeline preserves lack of status guard and writes decoded bytes");
        String privatePem=new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8);RSAPrivateCrtKey rsa=(RSAPrivateCrtKey)LoginFlow.parsePrivateKey(privatePem);
        PublicKey pub=KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsa.getModulus(),rsa.getPublicExponent()));Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");cipher.init(Cipher.ENCRYPT_MODE,pub);String plain="[\"offline.test\",\"A,A\"]";String encrypted=Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
        check(LoginFlow.decryptServerConfig(encrypted,privatePem).equals(plain),"PKCS1 PEM and real RSA roundtrip local fixture");
        SessionState loginState=new SessionState();List<ApiContract.Request> requests=new ArrayList<>();
        ApiContract.Transport mock=request->{requests.add(request);if(requests.size()==1)return new ApiContract.Response(200,ApiContract.map("success",true,"jwt","fixture-only","loginUser",ApiContract.map("timeout",60),"devices",Arrays.asList(ApiContract.map("create_time","2026-01-01","version",1.0,"direction",2),ApiContract.map("create_time","2026-01-01","version",1.0,"direction",1))));if(requests.size()==2){check(loginState.jwt.equals("fixture-only"),"JWT set before server config");return new ApiContract.Response(200,ApiContract.map("success",true,"msg",encrypted));}return new ApiContract.Response(200,ApiContract.map("success",false));};
        LoginFlow.Result result=new LoginFlow(loginState,mock).login("entry.test","fixtureuser","fixturepass","PUBLIC FIXTURE",privatePem,"2.1.6");
        check(requests.size()==3&&loginState.baseUri.equals("http://offline.test:8081/"),"login two-stage and update requests");check(loginState.channels.get(0).device.direction()==1,"login sorts by direction");check(!loginState.authenticated&&!loginState.connected,"HTTP login does not fake WS auth");check(result.unresolved.isEmpty(),"login fixture passes confirmed model conversions");
        try(java.util.stream.Stream<Path> paths=Files.walk(temp)){paths.sorted(Comparator.reverseOrder()).forEach(p->{try{Files.delete(p);}catch(IOException e){throw new RuntimeException(e);}});}
        System.out.println("PASS "+checks+" local behavior checks; no network calls; RSA used local synthetic ciphertext only.");
    }
    static final class Events implements MessageEngine.Listener {int previews,ready,shortfalls,errors;public void changed(){}public void status(String s){}public void preview(String s){previews++;}public void readyToValidateAndUpload(){ready++;}public void shortfall(int e,int a){shortfalls++;}public void failure(Exception e){errors++;throw new AssertionError(e);}}
    static final class FakeScheduler extends ScheduledThreadPoolExecutor {
        Runnable periodic,delayed;FakeScheduler(){super(1);}
        @Override public ScheduledFuture<?> scheduleAtFixedRate(Runnable r,long initial,long period,TimeUnit unit){periodic=r;return new FakeFuture();}
        @Override public ScheduledFuture<?> schedule(Runnable r,long delay,TimeUnit unit){delayed=r;return new FakeFuture();}
    }
    static final class FakeFuture implements ScheduledFuture<Object>{boolean cancelled;public long getDelay(TimeUnit unit){return 0;}public int compareTo(Delayed d){return 0;}public boolean cancel(boolean interrupt){cancelled=true;return true;}public boolean isCancelled(){return cancelled;}public boolean isDone(){return cancelled;}public Object get(){return null;}public Object get(long timeout,TimeUnit unit){return null;}}
}
