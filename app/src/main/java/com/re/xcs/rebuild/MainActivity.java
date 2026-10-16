package com.re.xcs.rebuild;

import android.app.*;
import android.os.*;
import android.content.*;
import android.graphics.*;
import android.media.MediaPlayer;
import android.net.Uri;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import com.re.xcs.rebuild.core.*;
import com.re.xcs.rebuild.net.WsSession;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/** New native Android UI over recovered contracts. Not the original Flutter UI. */
public final class MainActivity extends Activity {
    private final SessionState session=new SessionState();
    private final ExecutorService jobs=Executors.newCachedThreadPool();
    private final ScheduledExecutorService timers=Executors.newScheduledThreadPool(2);
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final JsonHttpTransport http=new JsonHttpTransport(session,"2.1.6");
    private volatile WsSession ws;private volatile MessageEngine engine;private ScheduledFuture<?> deviceTimer;
    private final Object networkLock=new Object();private volatile long generation;private volatile boolean destroyed;
    private boolean loginPending;private final Map<MediaPlayer,File> activePlayers=new HashMap<>();private Bitmap previewBitmap;
    private LinearLayout root,body;private TextView status,connection;private ImageView previewImage;
    private String page="login";
    private Models.Device previewDevice;private final Map<String,EditText> previewInputs=new LinkedHashMap<>();
    private final List<String> logs=new ArrayList<>();private Map<String,Object> viewSettings;
    private String entryIp="";
    private SettingsLogic.WifiPolling wifiPolling;

    @Override public void onCreate(Bundle b){super.onCreate(b);getWindow().setStatusBarColor(Color.rgb(20,50,65));getWindow().setNavigationBarColor(Color.WHITE);try{viewSettings=LocalConfig.readView(getFilesDir());}catch(Exception e){viewSettings=Models.viewDefaults();log("显示配置读取失败: "+e.getMessage());}loginScreen();}
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private TextView text(String value,int size){TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(Color.rgb(25,45,55));t.setPadding(0,dp(5),0,dp(5));return t;}
    private void screen(String title){status=null;connection=null;channelsView=null;previewImage=null;releasePreviewBitmap();root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(12),dp(18),dp(12));root.setBackgroundColor(Color.rgb(246,248,249));TextView heading=text(title,24);root.addView(heading);ScrollView scroll=new ScrollView(this);body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);scroll.addView(body);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));setContentView(root);}
    private EditText input(LinearLayout parent,String label,String value,boolean password){parent.addView(text(label,14));EditText e=new EditText(this);e.setSingleLine(true);e.setText(value);e.setTextSize(16);if(password)e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);parent.addView(e,new LinearLayout.LayoutParams(-1,dp(50)));return e;}
    private Button button(LinearLayout parent,String label,Runnable action){Button b=new Button(this);b.setText(label);b.setAllCaps(false);b.setOnClickListener(v->{try{action.run();}catch(Exception e){fail(e);}});parent.addView(b,new LinearLayout.LayoutParams(-1,-2));return b;}
    private void note(String message){Toast.makeText(this,message,Toast.LENGTH_LONG).show();log(message);}
    private void fail(Exception e){note(e.getMessage()==null?e.toString():e.getMessage());}
    private void log(String s){synchronized(logs){logs.add(new java.text.SimpleDateFormat("HH:mm:ss",Locale.ROOT).format(new Date())+" "+s);if(logs.size()>300)logs.remove(0);}}
    private void onUi(Runnable action){ui.post(()->{if(!destroyed)try{action.run();}catch(Exception e){fail(e);}});}
    private void onUi(long expected,Runnable action){onUi(()->{if(generation==expected)action.run();});}
    private MessageEngine activeEngine(){MessageEngine e=engine;if(e==null)throw new IllegalStateException("会话已结束，请重新登录");return e;}
    private String asset(String name)throws IOException{try(InputStream in=getAssets().open(name);ByteArrayOutputStream b=new ByteArrayOutputStream()){byte[] data=new byte[4096];int n;while((n=in.read(data))!=-1)b.write(data,0,n);return new String(b.toByteArray(),StandardCharsets.UTF_8);}}
    private void request(ApiContract.Request request,Consumer<ApiContract.Response> done){
        final long expected=generation;if(destroyed)return;
        try{jobs.submit(()->{try{final ApiContract.Response r;synchronized(networkLock){if(destroyed||generation!=expected)return;r=http.execute(request);}onUi(expected,()->{if(session.onHttpError(r)){stopMain();loginScreen();note("登录已失效，请重新登录");return;}done.accept(r);});}catch(Exception e){onUi(expected,()->fail(e));}});}
        catch(RejectedExecutionException e){if(!destroyed)onUi(expected,()->fail(e));}
    }
    private boolean accepted(ApiContract.Response r){if(!r.ok()){note("请求失败，HTTP "+r.status);return false;}if(Boolean.FALSE.equals(r.object().get("success"))){note(String.valueOf(r.object().get("msg")));return false;}return true;}
    private void loginScreen(){page="login";screen("鑫财神 · 重建");body.addView(text("登录设备管理服务",18));Map<String,Object> saved=null;try{saved=LocalConfig.readLogin(getFilesDir());}catch(Exception e){fail(e);}final Map<String,Object> config=saved;
        EditText ip=input(body,"服务器 IP / 主机",config==null?entryIp:String.valueOf(config.get("ip")),false);
        EditText user=input(body,"账号",config==null?session.username:String.valueOf(config.get("username")),false);
        EditText pass=input(body,"密码",config==null?session.password:String.valueOf(config.get("password")),true);
        CheckBox remember=new CheckBox(this);remember.setText("记住密码");remember.setChecked(config!=null&&Boolean.TRUE.equals(config.get("rememberPassword")));body.addView(remember);
        TextView progress=text("",14);body.addView(progress);
        Button[] submit=new Button[1];submit[0]=button(body,"登录",()->{
            if(loginPending)return;
            String host=ip.getText().toString(),name=user.getText().toString(),password=pass.getText().toString();
            if(host.isEmpty()||name.isEmpty()||password.isEmpty()){note("请填写服务器、账号和密码");return;}
            if(host.contains(":")||host.contains("/")){note("服务器填写主机或 IPv4；接口端口固定为 8081");return;}
            final boolean rememberValue=remember.isChecked();
            entryIp=host;loginPending=true;submit[0].setEnabled(false);progress.setText("正在登录…");
            stopMain();final long expected=generation;
            jobs.submit(()->{try{final LoginFlow.Result result;synchronized(networkLock){if(destroyed||generation!=expected)return;result=new LoginFlow(session,http).login(host,name,password,asset("key/pub_key.pem"),asset("key/private_key.pem"),"2.1.6");LocalConfig.writeLogin(getFilesDir(),host,name,password,rememberValue);}onUi(expected,()->{loginPending=false;submit[0].setEnabled(true);progress.setText("");if(result.updateCheck.data instanceof Map&&Boolean.TRUE.equals(result.updateCheck.object().get("success")))updateScreen(result.updateCheck.object());else startMain();for(String limitation:result.unresolved)log(limitation);});}catch(Exception e){onUi(expected,()->{loginPending=false;submit[0].setEnabled(true);progress.setText("登录未完成");fail(e);});}});
        });
        button(body,"清空登录设置",()->{if(loginPending){note("正在登录，请等待当前请求完成");return;}ip.setText("");user.setText("");pass.setText("");try{LocalConfig.writeLogin(getFilesDir(),"","","",remember.isChecked());}catch(IOException e){fail(e);}});
        button(body,"关于此重建版本",this::about);
        body.addView(text("本地重建版本 · 连接你指定的服务",12));
    }
    private void startMain(){
        stopMain();final long expected=generation;getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        for(Models.Channel c:session.channels)c.device.lighting(0);
        CachedImageLoader loader=new CachedImageLoader(request->{synchronized(networkLock){if(destroyed||generation!=expected)throw new IOException("会话已结束");return http.execute(request);}},getCacheDir(),jobs);
        engine=new MessageEngine(session,loader,new MessageEngine.Listener(){
            public void changed(){onUi(expected,()->{if(page.equals("main")||page.equals("results"))renderChannels();});}
            public void status(String s){onUi(expected,()->{if(status!=null)status.setText(s);log(s);});}
            public void preview(String frame){onUi(expected,()->showPreview(frame));}
            public void readyToValidateAndUpload(){onUi(expected,()->{if(engine!=null){showResults();upload();}});}
            public void shortfall(int expectedCount,int actual){onUi(expected,()->{play("assets/number_error.wav");note("接收不足："+actual+" / "+expectedCount);});}
            public void failure(Exception e){onUi(expected,()->fail(e));}
        },timers);
        final MessageEngine owner=engine;mainScreen();
        request(ApiContract.mjConfig(),r->{if(engine!=owner)return;if(Boolean.TRUE.equals(r.object().get("success"))){synchronized(owner){for(Object v:JsonCodec.array(r.object().get("list")))owner.palette.add(Models.read("MjConfig",JsonCodec.object(v)).values);}startSocket();}else note("牌配置获取失败，尚未启动连接");});
        pollDevices();deviceTimer=timers.scheduleAtFixedRate(this::pollDevices,5,5,TimeUnit.SECONDS);
    }
    private void startSocket(){
        final MessageEngine owner=activeEngine();final long expected=generation;
        if(ws!=null)ws.close();final WsSession[] created=new WsSession[1];
        created[0]=new WsSession(new WsSession.Listener(){
            public void state(boolean connected,boolean authenticated,String detail){onUi(expected,()->{if(ws!=created[0]||engine!=owner)return;session.connected=connected;session.authenticated=authenticated;if(connection!=null)connection.setText(detail);log(detail);});}
            public void business(Map<String,Object>message){if(generation!=expected||engine!=owner||ws!=created[0])return;try{owner.accept(message);}catch(Exception ex){onUi(expected,()->fail(ex));}}
            public void error(String message){if(generation==expected)log(message);}
        });ws=created[0];ws.start(session.businessHost,session.jwt);
    }
    private LinearLayout channelsView;
    private void mainScreen(){if(engine==null){loginScreen();return;}page="main";screen("设备与牌局");connection=text(session.connected?(session.authenticated?"已连接 · 已认证":"已连接 · 等待认证"):"尚未连接",14);body.addView(connection);status=text(engine==null?"未开始游戏":engine.statusText,16);body.addView(status);
        button(body,"开始",()->{if(ws==null||!ws.isConnected())startSocket();request(ApiContract.startGames(),r->{if(Boolean.TRUE.equals(r.object().get("success")))note("指令下发成功");});});
        button(body,"结束",()->request(ApiContract.endGames(),r->{if(Boolean.TRUE.equals(r.object().get("success"))){engine.endGamesAccepted();note("指令下发成功");}}));
        button(body,"重置本轮",()->{request(ApiContract.resetGames(),r->{if(r.ok()&&Boolean.TRUE.equals(r.object().get("success")))note("重新开始成功");});synchronized(engine){for(Models.Channel c:session.channels)c.results.clear();}renderChannels();});
        button(body,"查看和修改识别结果",this::showResults);button(body,"设备预览与参数",this::previewScreen);button(body,"配置",this::settingsScreen);
        channelsView=new LinearLayout(this);channelsView.setOrientation(LinearLayout.VERTICAL);body.addView(channelsView);renderChannels();
        button(body,"日志",this::logsScreen);button(body,"退出登录",()->{if(ws!=null)ws.logout();stopMain();loginScreen();});
    }
    private void renderChannels(){if(channelsView==null||engine==null||!(page.equals("main")||page.equals("results")))return;channelsView.removeAllViews();synchronized(engine){for(Models.Channel c:session.channels){String direction=direction(c.device.direction());channelsView.addView(text(direction+" · "+c.device.serial()+" · "+(Models.intOr(c.device.fields.get("online"),0)==1?"在线":"离线"),18));channelsView.addView(text(c.results.size()+" / "+c.device.expected()+" 张",14));if(page.equals("results")){for(Models.Tile tile:new ArrayList<>(c.results)){button(channelsView,"#"+tile.sequence+"  "+(tile.result.isEmpty()?"未识别":tile.result)+"  置信度 "+tile.confidence,()->editTile(c,tile));}}}}}
    private static String direction(Integer n){return n==null?"未分配":n>=1&&n<=4?new String[]{"东","南","西","北"}[n-1]:"方向 "+n;}
    private void pollDevices(){final MessageEngine owner=engine;if(owner==null||destroyed)return;request(ApiContract.deviceStatus(),r->{if(engine!=owner||!r.ok()||!Boolean.TRUE.equals(r.object().get("success")))return;String[] keys={"ip","online","delay","connected_at","ver","client_wifi","client_ip","run_time","up_time"};synchronized(owner){for(Models.Channel c:session.channels)for(Object value:JsonCodec.array(r.object().get("data"))){Map<String,Object> row=JsonCodec.object(value);if(Objects.equals(c.device.serial(),row.get("serial_no"))){if(Models.intOr(c.device.fields.get("online"),0)==1&&Models.intOr(row.get("online"),0)==0)play("assets/offline_error.wav");for(String k:keys)c.device.fields.put(k,row.get(k));}}}renderChannels();});}
    private void showResults(){activeEngine();ResultRules.openChangePage(session);page="results";screen("识别结果");status=text(engine.statusText,16);body.addView(status);button(body,"校验并上传",this::upload);channelsView=new LinearLayout(this);channelsView.setOrientation(LinearLayout.VERTICAL);body.addView(channelsView);renderChannels();button(body,"返回",()->{ResultRules.closeChangePage(session);mainScreen();});}
    private void editTile(Models.Channel channel,Models.Tile tile){final MessageEngine owner=activeEngine();ResultRules.selectResultForEdit(session,tile);List<Map<String,Object>> palette;synchronized(owner){palette=new ArrayList<>(owner.palette);}String[] names=new String[palette.size()+2];for(int i=0;i<palette.size();i++)names[i]=palette.get(i).get("number")+"  "+palette.get(i).get("name");names[palette.size()]="删除并调整后续序号";names[palette.size()+1]="查看接收图片";new AlertDialog.Builder(this).setTitle("第 "+tile.sequence+" 张").setItems(names,(d,index)->{try{if(engine!=owner)return;synchronized(owner){if(!channel.results.contains(tile)){note("这条结果已被新一轮数据替换");return;}if(index<palette.size())ResultRules.selectMain(session,palette.get(index));else if(index==palette.size())ResultRules.deleteMain(channel,tile.sequence);else{ImageView image=new ImageView(this);Bitmap b=BitmapFactory.decodeFile(tile.uploadImg);if(b==null)note("此条没有本地图像");else{image.setImageBitmap(b);image.setAdjustViewBounds(true);AlertDialog dialog=new AlertDialog.Builder(this).setView(image).setPositiveButton("关闭",null).create();dialog.setOnDismissListener(v->{image.setImageDrawable(null);b.recycle();});dialog.show();}}}renderChannels();}catch(Exception e){fail(e);}}).setOnCancelListener(dialog->{if(engine==owner)ResultRules.cancelResultSelection(session);}).show();}
    private void upload(){final MessageEngine owner=activeEngine();final List<Map<String,Object>> payload;try{synchronized(owner){ResultRules.Validation validation=ResultRules.validate(session.channels);if(!validation.valid()){new AlertDialog.Builder(this).setTitle("校验未通过").setMessage(String.join("\n",validation.errors)).setPositiveButton("返回修改",null).show();return;}payload=ResultRules.uploadPayload(session.channels);}}catch(RuntimeException error){fail(error);return;}request(ApiContract.addResults(payload),r->{if(engine!=owner)return;if(accepted(r)){synchronized(owner){ResultRules.afterUploadAccepted(session);}note("发送成功");mainScreen();}});}
    private void settingsScreen(){page="settings";screen("配置");button(body,"方位数量与数据设置",this::onlineSettings);button(body,"设备 Wi-Fi",this::wifiSettings);button(body,"修改密码",this::passwordSettings);button(body,"显示设置",this::displaySettings);button(body,"设置本地口令",this::localPhrase);button(body,"重启所有设备",()->request(ApiContract.restartDevice(),r->{if(accepted(r))note("重启所有设备成功");}));button(body,"返回",this::mainScreen);}
    private void onlineSettings(){page="online";screen("方位数量与数据设置");final MessageEngine owner=activeEngine();Map<String,EditText> inputs=new LinkedHashMap<>();String[] keys={"east","south","west","north","timeout","delay","data_send","count_type","upload_img_clarity"};String[] labels={"东侧张数","南侧张数","西侧张数","北侧张数","接收超时（秒）","延迟","发送模式（1自动 / 2手动）","计数类型（1光控 / 2双线 / 3T / 4S / 5单线）","上传清晰度（0节流 / 1标清 / 2高清 / 3超清）"};for(int i=0;i<keys.length;i++)inputs.put(keys[i],input(body,labels[i],i<4?"26":i==4?"60":i==5?"5":"1",false));
        button(body,"保存方位数量",()->request(SettingsLogic.prepareNumberSave(onlineForm(inputs,false)),r->{if(engine!=owner)return;SettingsLogic.Outcome outcome;synchronized(owner){outcome=SettingsLogic.applyNumberResponse(onlineForm(inputs,false),session,r,null);}note(outcome.message.isEmpty()?"请求失败，HTTP "+r.status:outcome.message);}));
        button(body,"保存数据设置",()->{final ApiContract.Request request;synchronized(owner){request=SettingsLogic.prepareDataSave(onlineForm(inputs),session);}request(request,r->{SettingsLogic.Outcome outcome=SettingsLogic.evaluateResponse(SettingsLogic.Action.DATA,r,null);note(outcome.message.isEmpty()?"请求失败，HTTP "+r.status:outcome.message);});});button(body,"返回",this::settingsScreen);
        request(ApiContract.config(),r->{if(!page.equals("online")||engine!=owner)return;SettingsLogic.Form form=new SettingsLogic.Form();if(!SettingsLogic.applyConfig(form,r)){accepted(r);return;}String[] values={form.east,form.south,form.west,form.north,form.timeout,form.delay,Integer.toString(form.dataSend),Integer.toString(form.countType),Integer.toString(form.uploadImageClarity)};for(int i=0;i<keys.length;i++)inputs.get(keys[i]).setText(values[i]);});
    }
    private SettingsLogic.Form onlineForm(Map<String,EditText> inputs){return onlineForm(inputs,true);}
    private SettingsLogic.Form onlineForm(Map<String,EditText> inputs,boolean parseData){SettingsLogic.Form form=new SettingsLogic.Form();form.east=inputs.get("east").getText().toString();form.south=inputs.get("south").getText().toString();form.west=inputs.get("west").getText().toString();form.north=inputs.get("north").getText().toString();form.timeout=inputs.get("timeout").getText().toString();form.delay=inputs.get("delay").getText().toString();if(parseData){form.dataSend=intInput(inputs,"data_send");form.countType=intInput(inputs,"count_type");form.uploadImageClarity=intInput(inputs,"upload_img_clarity");}return form;}
    private static int intInput(Map<String,EditText>m,String key){return Math.toIntExact(ResultRules.parseInt(m.get(key).getText().toString()));}
    private void wifiSettings(){page="wifi";screen("设备 Wi-Fi");EditText ssid=input(body,"Wi-Fi 名称","",false),pwd=input(body,"Wi-Fi 密码","",true);button(body,"扫描设备周边 Wi-Fi",()->scanWifi(ssid));button(body,"读取默认 Wi-Fi",()->request(ApiContract.defaultWifi(),r->{if(!page.equals("wifi"))return;SettingsLogic.Form form=new SettingsLogic.Form();if(SettingsLogic.applyDefaultWifi(form,r)){ssid.setText(form.ssid);pwd.setText(form.wifiPassword);}else note("默认 Wi-Fi 未返回成功");}));button(body,"保存",()->{SettingsLogic.Form form=new SettingsLogic.Form();form.ssid=ssid.getText().toString();form.wifiPassword=pwd.getText().toString();request(SettingsLogic.prepareWifiSave(form,false),r->{SettingsLogic.Outcome result=SettingsLogic.evaluateResponse(SettingsLogic.Action.WIFI_MANUAL,r,null);note(result.message.isEmpty()?"请求失败，HTTP "+r.status:result.message);});});button(body,"返回",this::settingsScreen);}
    private void scanWifi(EditText selected){
        if(wifiPolling!=null)wifiPolling.close();final long expected=generation;
        LinearLayout list=new LinearLayout(this);list.setOrientation(1);list.setPadding(dp(16),0,dp(16),0);list.addView(text("正在获取设备扫描结果…",15));ScrollView scroll=new ScrollView(this);scroll.addView(list);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("发现的 Wi-Fi").setView(scroll).setNegativeButton("关闭",null).create();
        SettingsLogic.Dispatcher dispatcher=(req,done)->{if(destroyed||generation!=expected)return;try{jobs.submit(()->{try{final ApiContract.Response response;synchronized(networkLock){if(destroyed||generation!=expected)return;response=http.execute(req);}onUi(expected,()->{if(session.onHttpError(response)){dialog.dismiss();stopMain();loginScreen();return;}done.complete(response,null);});}catch(Exception e){onUi(expected,()->done.complete(null,e.getMessage()));}});}catch(RejectedExecutionException ignored){/* disposed Activity */}};
        SettingsLogic.Scheduler scheduler=(delay,action)->{ScheduledFuture<?> f=timers.scheduleAtFixedRate(action,delay,delay,TimeUnit.MILLISECONDS);return ()->f.cancel(false);};
        final SettingsLogic.WifiPolling poll=new SettingsLogic.WifiPolling(scheduler,dispatcher,(response,error)->{if(!dialog.isShowing())return;try{SettingsLogic.WifiScan scan=SettingsLogic.parseWifiResponse(response);if(scan==null){if(error!=null)log("Wi-Fi 扫描: "+error);return;}list.removeAllViews();if(scan.inputOrderItems.isEmpty())list.addView(text("暂未发现 Wi-Fi",15));for(SettingsLogic.WifiItem item:scan.inputOrderItems)button(list,item.ssid+" ("+item.percent+"%)",()->{selected.setText(item.ssid);dialog.dismiss();});if(!scan.orderingRecovered)log(scan.limitation);}catch(Exception e){list.removeAllViews();list.addView(text("无法解析扫描结果："+e.getMessage(),14));}});
        wifiPolling=poll;dialog.setOnDismissListener(d->{poll.close();if(wifiPolling==poll)wifiPolling=null;});dialog.show();poll.start();
    }
    private void passwordSettings(){page="password";screen("修改密码");EditText old=input(body,"原密码","",true),next=input(body,"新密码","",true),confirm=input(body,"确认密码","",true);button(body,"修改密码",()->{ApiContract.Request request=SettingsLogic.preparePassword(old.getText().toString(),next.getText().toString(),confirm.getText().toString());request(request,r->{SettingsLogic.Outcome outcome=SettingsLogic.evaluateResponse(SettingsLogic.Action.PASSWORD,r,null);note(outcome.message.isEmpty()?"请求失败，HTTP "+r.status:outcome.message);if(outcome.accepted()){stopMain();loginScreen();}});});button(body,"返回",this::settingsScreen);}
    private void displaySettings(){page="display";screen("显示设置");Map<String,EditText> inputs=new LinkedHashMap<>();for(Map.Entry<String,Object> e:viewSettings.entrySet())if(e.getValue() instanceof Number)inputs.put(e.getKey(),input(body,e.getKey(),e.getValue().toString(),false));CheckBox ai=new CheckBox(this);ai.setText("显示识别置信度");ai.setChecked(Boolean.TRUE.equals(viewSettings.get("orientationAiVis")));body.addView(ai);button(body,"保存",()->{for(Map.Entry<String,EditText> e:inputs.entrySet())viewSettings.put(e.getKey(),Double.parseDouble(e.getValue().getText().toString()));viewSettings.put("orientationAiVis",ai.isChecked());try{LocalConfig.writeView(getFilesDir(),viewSettings);note("保存成功");}catch(Exception e){fail(e);}});button(body,"返回",this::settingsScreen);}
    private void localPhrase(){EditText e=new EditText(this);e.setInputType(129);new AlertDialog.Builder(this).setTitle("设置本地口令").setView(e).setPositiveButton("保存",(d,w)->{try{LocalConfig.writeLocalPhrase(getFilesDir(),e.getText().toString());note("保存成功");}catch(Exception ex){fail(ex);}}).setNegativeButton("取消",null).show();}
    private void previewScreen(){MessageEngine owner=activeEngine();page="preview";screen("设备预览");owner.enterPreviewPage();previewImage=new ImageView(this);previewImage.setAdjustViewBounds(true);body.addView(previewImage,new LinearLayout.LayoutParams(-1,dp(240)));for(Models.Channel c:session.channels)button(body,direction(c.device.direction())+" · "+c.device.serial(),()->selectPreview(c.device));button(body,"调整参数",this::previewParameters);button(body,"图像类型",()->{String[] types={"0","1","2"};new AlertDialog.Builder(this).setTitle("图像类型（枚举名称未恢复）").setItems(types,(d,n)->{if(previewDevice!=null)for(Models.Channel c:session.channels)if(Objects.equals(c.device.direction(),previewDevice.direction()))request(ApiContract.previewImageType(c.device.id(),n),r->{});}).show();});button(body,"结束预览并返回",this::exitPreview);if(!session.channels.isEmpty())selectPreview(session.channels.get(0).device);}
    private void selectPreview(Models.Device d){final MessageEngine owner=activeEngine();previewDevice=d;request(owner.startPreview(d),r->{if(engine!=owner)return;owner.onStartPreviewValue(d,r);log("预览启动请求完成，HTTP "+r.status);});}
    private void showPreview(String frame){if(!page.equals("preview")||frame.isEmpty()||previewImage==null)return;byte[] bytes=Base64.getDecoder().decode(frame);if(bytes.length<2||(bytes[0]&255)!=255||(bytes[1]&255)!=216)throw new IllegalArgumentException("预览不是 JPEG");Bitmap bitmap=BitmapFactory.decodeByteArray(bytes,0,bytes.length);if(bitmap==null)throw new IllegalArgumentException("无法解码预览 JPEG");Bitmap mutable=bitmap.copy(Bitmap.Config.ARGB_8888,true);bitmap.recycle();if(mutable==null)throw new IllegalStateException("无法分配预览图像");if(previewDevice!=null){Map<String,Object>d;synchronized(activeEngine()){d=new LinkedHashMap<>(previewDevice.fields);}if(d.get("left")instanceof Number&&d.get("top")instanceof Number&&d.get("right")instanceof Number&&d.get("bottom")instanceof Number){float x=((Number)d.get("left")).floatValue(),y=((Number)d.get("top")).floatValue();Paint p=new Paint();p.setColor(Color.argb(128,255,0,0));new Canvas(mutable).drawRect(x,y,x+((Number)d.get("right")).floatValue(),y+((Number)d.get("bottom")).floatValue(),p);}}Bitmap old=previewBitmap;previewBitmap=mutable;previewImage.setImageBitmap(mutable);if(old!=null)old.recycle();}
    private void releasePreviewBitmap(){if(previewBitmap!=null){previewBitmap.recycle();previewBitmap=null;}}
    private void previewParameters(){if(previewDevice==null){note("请选择设备");return;}LinearLayout fields=new LinearLayout(this);fields.setOrientation(1);fields.setPadding(dp(18),0,dp(18),0);previewInputs.clear();String[] keys={"left","top","right","bottom","brightness","motor","cap_brightness","cap_exposure","cap_hue","cap_saturation","cap_contrast","cap_gain","img_rotation","img_min_hreshold","cap_fps","bate","img_add_num","gk_min","gk_max"};for(String key:keys){Object value=previewDevice.fields.get(key.equals("bate")?"beta":key);if(value==null&&key.equals("brightness"))value=75.0;if(value==null&&key.equals("motor"))value=3000;previewInputs.put(key,input(fields,key,value==null?"":value.toString(),false));}ScrollView scroll=new ScrollView(this);scroll.addView(fields);new AlertDialog.Builder(this).setTitle("预览参数").setView(scroll).setPositiveButton("保存并退出",(d,w)->savePreview(true)).setNeutralButton("更新图像",(d,w)->savePreview(false)).setNegativeButton("取消",null).show();}
    private void savePreview(boolean close){try{final MessageEngine owner=activeEngine();final Models.Device device=Objects.requireNonNull(previewDevice,"请选择设备");Map<String,Object> input=new LinkedHashMap<>();for(Map.Entry<String,EditText> e:previewInputs.entrySet()){String value=e.getValue().getText().toString();if(value.isEmpty())throw new IllegalArgumentException("缺少设备参数 "+e.getKey());if(e.getKey().equals("brightness")||Arrays.asList("left","top","right","bottom","motor").contains(e.getKey()))input.put(e.getKey(),Double.parseDouble(value));else input.put(e.getKey(),ResultRules.parseInt(value));}ApiContract.Request request=owner.savePreviewParams(device.id(),input);synchronized(owner){for(Map.Entry<String,Object> e:input.entrySet())device.fields.put(e.getKey().equals("bate")?"beta":e.getKey(),e.getValue());device.fields.put("brightness",75.0);}request(request,r->{if(engine!=owner)return;MessageEngine.PreviewSaveOutcome outcome=owner.onSavePreviewValue(device,close,r);if(r.ok()&&Boolean.TRUE.equals(r.object().get("success")))note("保存成功");if(outcome.endRequest!=null)request(outcome.endRequest,MessageEngine::sharedNullCompletion);if(outcome.popWithTrue&&page.equals("preview"))mainScreen();});}catch(Exception e){fail(e);}}
    private void exitPreview(){ApiContract.Request end=activeEngine().onPreviewRouteReturned();if(end!=null)request(end,MessageEngine::sharedNullCompletion);mainScreen();}
    private void updateScreen(Map<String,Object> data){page="update";screen("应用更新");body.addView(text("服务端返回了更新信息。重建版本尚未恢复原 OTA 安装插件的完整行为。",16));Object raw=data.get("data");Map<String,Object> update=raw instanceof Map?JsonCodec.object(raw):data;Object url=update.get("update_url");if(url instanceof String)button(body,"打开下载地址",()->startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse((String)url))));button(body,"返回登录",this::loginScreen);}
    private void logsScreen(){page="logs";screen("运行日志");synchronized(logs){body.addView(text(String.join("\n",logs),13));}button(body,"返回",this::mainScreen);}
    private void about(){new AlertDialog.Builder(this).setTitle("重建状态").setMessage("此版本为基于本地静态证据新写的 Java Android 工程，包含真实 HTTP、RSA 配置解密、WS 收发和识别结果处理。\n\n原 Flutter 界面、OTA 插件、原生全部并发行为和未解业务分支尚未完整恢复。原始源码未恢复；仅通过真实登录与只读接口验证，设备控制和完整业务尚未验收。详细差异见工程 evidence 目录。").setPositiveButton("关闭",null).show();}
    private void play(String asset){
        if(destroyed)return;MediaPlayer player=new MediaPlayer();File sound=null;
        try{sound=File.createTempFile("xcs-sound-",".wav",getCacheDir());try(InputStream input=getAssets().open(asset);OutputStream output=new FileOutputStream(sound)){byte[] bytes=new byte[8192];int n;while((n=input.read(bytes))!=-1)output.write(bytes,0,n);}activePlayers.put(player,sound);player.setDataSource(sound.getAbsolutePath());player.setOnPreparedListener(p->{if(destroyed)releasePlayer(p);else p.start();});player.setOnCompletionListener(this::releasePlayer);player.setOnErrorListener((p,what,extra)->{log("提示音播放失败: "+what+"/"+extra);releasePlayer(p);return true;});player.prepareAsync();}
        catch(Exception e){releasePlayer(player);if(sound!=null)sound.delete();log("提示音播放失败: "+e.getMessage());}
    }
    private void releasePlayer(MediaPlayer player){File sound=activePlayers.remove(player);player.release();if(sound!=null)sound.delete();}
    private void stopMain(){generation++;if(wifiPolling!=null)wifiPolling.close();wifiPolling=null;if(deviceTimer!=null)deviceTimer.cancel(false);deviceTimer=null;WsSession oldWs=ws;ws=null;if(oldWs!=null)oldWs.close();MessageEngine old=engine;engine=null;if(old!=null)old.close();session.connected=false;session.authenticated=false;getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);}
    @Override public void onBackPressed(){if(page.equals("preview")&&engine!=null)exitPreview();else if(engine==null){if(page.equals("login")){if(loginPending){note("正在登录，请等待当前请求完成");return;}super.onBackPressed();}else loginScreen();}else if(!page.equals("main")){if(page.equals("results"))ResultRules.closeChangePage(session);mainScreen();}else super.onBackPressed();}
    @Override public void onDestroy(){destroyed=true;stopMain();for(MediaPlayer player:new ArrayList<>(activePlayers.keySet()))releasePlayer(player);releasePreviewBitmap();ui.removeCallbacksAndMessages(null);jobs.shutdownNow();timers.shutdownNow();super.onDestroy();}
}
