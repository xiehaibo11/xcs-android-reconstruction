package com.re.xcs.rebuild;

import android.app.*;
import android.os.*;
import android.content.*;
import android.view.*;
import android.widget.*;
import com.re.xcs.rebuild.core.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.io.*;
import java.net.*;

/** Instrumentation operating the real Activity against explicit loopback fixtures. */
public final class RuntimeChecks extends Instrumentation {
    private Activity activity;private final List<String> passed=new ArrayList<>();
    @Override public void onCreate(Bundle b){super.onCreate(b);start();}
    @Override public void onStart(){Bundle result=new Bundle();try{
        resetFixture();
        Intent intent=new Intent(getTargetContext(),MainActivity.class);intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);activity=startActivitySync(intent);waitForIdleSync();
        check(has("鑫财神 · 重建"),"Activity launches and renders login");Thread.sleep(500);screenshot("login");
        runOnMainSync(()->{List<EditText> fields=new ArrayList<>();collect(activity.getWindow().getDecorView(),fields);fields.get(0).setText("127.0.0.1");fields.get(1).setText("fixture-user");fields.get(2).setText("fixture-password");});
        click("登录");waitText("设备与牌局",15000);passed.add("Real Activity login + HTTP + bundled RSA key decrypt");
        verifyRound3Conversions();
        waitFixture("ws_logins",1,10000);waitFixture("heartbeats",1,5000);passed.add("WebSocket upgrade, login and immediate heartbeat");screenshot("main");
        click("开始");long end=System.currentTimeMillis()+15000;Map<String,Object> f=null;
        while(System.currentTimeMillis()<end){f=fixture();if(JsonCodec.array(f.get("uploads")).size()>0)break;Thread.sleep(100);}
        List<Object> uploads=JsonCodec.array(f.get("uploads"));check(uploads.size()>0,"Actual 101 image GET -> decode/cache -> count validation -> HTTP upload");
        List<Object> rows=JsonCodec.array(uploads.get(0));check(rows.size()==4,"Upload contains all four synthetic recognition results");
        Set<Long> seq=new HashSet<>();for(Object raw:rows){Map<String,Object> row=JsonCodec.object(raw);seq.add(((Number)row.get("mahjong_number")).longValue());check(((Number)row.get("serial_number")).longValue()==1001&&((Number)row.get("direction")).intValue()==1&&((Number)row.get("result")).intValue()==1,"Upload field values preserved");}check(seq.equals(new HashSet<Long>(Arrays.asList(1L,2L,3L,4L))),"Concurrent image completion preserves sequence identity");
        waitText("设备与牌局",5000);verifyResultNavigation();click("设备预览与参数");waitText("设备预览",5000);waitFixture("preview_starts",1,5000);Thread.sleep(1800);
        AtomicReference<Boolean> image=new AtomicReference<>(false);runOnMainSync(()->image.set(hasImage(activity.getWindow().getDecorView())));check(image.get(),"WS102 JPEG rendered in Android ImageView");screenshot("preview");
        fixtureControl("end_failure");click("结束预览并返回");waitFixture("preview_ends",1,5000);passed.add("Preview exit posts matching device end request");
        waitText("设备与牌局",3000);waitFixture("late_preview_frames_sent",1,5000);Thread.sleep(300);
        MessageEngine observed=(MessageEngine)field("engine");SessionState observedState=(SessionState)field("session");
        synchronized(observed){check(observedState.preview.serviceDeviceId.longValue()==0&&observed.currentPreviewDeviceId==7,"Failed end leaves service ID cleared and filter ID retained");String hash=hex(java.security.MessageDigest.getInstance("SHA-256").digest(observed.previewFrame.getBytes("UTF-8")));check(hash.equals(fixture().get("late_preview_frame_sha256")),"Late WS102 updates retained preview state after route exit");}
        check(has("设备与牌局"),"Late preview message does not reopen the departed Android screen");
        click("设备预览与参数");waitFixture("preview_starts",2,5000);Thread.sleep(1000);runOnMainSync(()->image.set(hasImage(activity.getWindow().getDecorView())));check(image.get(),"Re-entered preview renders a fresh WS102 frame after end failure");click("结束预览并返回");waitText("设备与牌局",3000);
        click("配置");click("方位数量与数据设置");waitText("方位数量与数据设置",3000);Thread.sleep(500);click("保存数据设置");Thread.sleep(600);passed.add("Settings screen renders and submits data configuration");screenshot("settings");
        f=fixture();boolean loginHeaders=false,settings=false;for(Object raw:JsonCodec.array(f.get("requests"))){Map<String,Object> r=JsonCodec.object(raw);String path=(String)r.get("path");if(path.startsWith("/api/server/get_server_addr")){Map<String,Object> h=JsonCodec.object(r.get("headers"));loginHeaders="Bearer fixture-only-token".equals(h.get("Authorization"))&&"android".equals(h.get("clienttype"));}if(path.equals("/api/config/set_data_config")){Map<String,Object> p=JsonCodec.object(r.get("json"));settings=p.keySet().equals(new HashSet<String>(Arrays.asList("data_send","timeout","delay","count_type","upload_img_clarity")));}}
        check(loginHeaders,"JWT and clienttype on second login request");check(settings,"Settings emits exact five-key HTTP body");
        click("返回");click("设备 Wi-Fi");click("扫描设备周边 Wi-Fi");waitDialogText("fixture-wifi (100%)",5000);clickDialog("fixture-wifi (100%)");check(has("fixture-wifi"),"Wi-Fi scan HTTP string parsed and selected into form");click("保存");Thread.sleep(500);
        int up=0,list=0;boolean wifiSaved=false;for(Object raw:JsonCodec.array(fixture().get("requests"))){Map<String,Object> r=JsonCodec.object(raw);if(r.get("path").equals("/api/config/wifi_device_up"))up++;if(r.get("path").equals("/api/config/get_device_wifi_list"))list++;if(r.get("path").equals("/api/config/set_wifi"))wifiSaved="fixture-wifi".equals(JsonCodec.object(r.get("json")).get("ssid"));}check(up>=2&&list>=2,"Wi-Fi opening issues two deviceUp and follow-up list requests");check(wifiSaved,"Selected Wi-Fi is submitted with actual HTTP request");
        write(ApiContract.map("status","PASS","synthetic_only",true,"business_server_contacted",false,"assertions",passed));result.putString("result","PASS "+passed.size()+" checks");finish(Activity.RESULT_OK,result);
    }catch(Throwable t){try{write(ApiContract.map("status","FAIL","synthetic_only",true,"assertions",passed,"error",t.toString()));}catch(Exception ignored){}result.putString("error",t.toString());finish(Activity.RESULT_CANCELED,result);}}
    private void check(boolean ok,String message){if(!ok)throw new AssertionError(message);passed.add(message);}
    private void verifyRound3Conversions()throws Exception{
        SessionState state=(SessionState)field("session");Object created=state.channels.get(0).device.fields.get("create_time");
        check(created instanceof DartDateTime&&((DartDateTime)created).toIso8601String().equals("2026-10-14T00:00:00.000Z"),"Actual Activity login stores parsed DateTime with UTC identity");
        Models.Record overflow=Models.read("Devices",ApiContract.map("create_time","2020-01-42T00:00:00.1234567Z","version",9007199254740993L));
        check(overflow.unresolved.isEmpty()&&overflow.toJson().get("create_time").equals("2020-02-11T00:00:00.123456Z"),"Android Devices serializer normalizes overflow and truncates fractional microseconds");
        check(overflow.get("version").equals(9007199254740992.0),"Android Mint toDouble retains IEEE754 rounding");
        DartDateTime offset=DartDateTime.parse("2026-01-01T00:30:00+01:00");
        check(offset.toIso8601String().equals("2025-12-31T23:30:00.000Z")&&offset.isUtc(),"Android explicit date offset normalizes to UTC across year boundary");
        check(Models.read("Message",ApiContract.map("msg_content",offset)).toJson().get("msg_content").equals("2025-12-31 23:30:00.000Z"),"Android dynamic DateTime content uses its own toString selector");
        check(Models.read("Message",ApiContract.map("msg_content",Arrays.asList(Long.MIN_VALUE,Long.MAX_VALUE))).toJson().get("msg_content").equals("[-9223372036854775808, 9223372036854775807]"),"Android Message formats full Mint range inside collections");
        List<Object> numeric=JsonCodec.array(JsonCodec.parse("[9223372036854775807,9223372036854775808,1e309]"));
        check(numeric.get(0).equals(Long.MAX_VALUE)&&numeric.get(1) instanceof Double,"Android JSON preserves Mint maximum and converts overflow to Double");
        check(numeric.get(2).equals(Double.POSITIVE_INFINITY)&&DartConversions.messageContentString(numeric.get(2)).equals("Infinity"),"Android JSON exponent overflow reaches dynamic Double conversion");
        byte[] bytes={(byte)255,1,2,(byte)255,3,(byte)255};
        check(GoBytePrimitives.count(bytes,1,4,255)==1&&GoBytePrimitives.indexOf(bytes,1,4,255)==2,"Android executes reconstructed Go byte primitives with slice boundaries");
        check(GoBytePrimitives.count(null,0,0,0)==0&&GoBytePrimitives.indexOf(null,0,0,0)==-1,"Android Go nil empty-slice behavior");
        boolean rejected=false;try{Models.read("Devices",ApiContract.map("create_time","not-a-date","version","invalid"));}catch(DartDateTime.FormatException expected){rejected=true;}
        check(rejected,"Android date parse failure precedes later dynamic version failure");
    }
    private void verifyResultNavigation()throws Exception{
        MessageEngine owner=(MessageEngine)field("engine");SessionState state=(SessionState)field("session");Models.Tile tile=new Models.Tile(99);
        synchronized(owner){state.channels.get(0).results.add(tile);}
        click("查看和修改识别结果");click("#99  未识别  置信度 0.0");waitDialogText("第 99 张",3000);
        if(state.mainView.selectedResult!=tile)throw new AssertionError("Editor did not capture fixture tile");
        sendKeyDownUpSync(KeyEvent.KEYCODE_BACK);waitForIdleSync();Thread.sleep(200);
        check(state.mainView.selectedResult==null&&has("识别结果"),"Cancelling the actual tile dialog clears its captured selection");
        sendKeyDownUpSync(KeyEvent.KEYCODE_BACK);waitText("设备与牌局",3000);
        check(state.mainView.pageMode==1,"System back from actual results page applies closeChangePage");
        synchronized(owner){state.channels.get(0).results.remove(tile);}
    }
    private Object field(String name)throws Exception{java.lang.reflect.Field field=MainActivity.class.getDeclaredField(name);field.setAccessible(true);return field.get(activity);}
    private static String hex(byte[] bytes){StringBuilder b=new StringBuilder();for(byte value:bytes)b.append(String.format(java.util.Locale.ROOT,"%02x",value&255));return b.toString();}
    private static void fixtureControl(String name)throws Exception{HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:8081/__fixture/"+name).openConnection();c.setRequestMethod("POST");c.setConnectTimeout(3000);c.setReadTimeout(3000);try{if(c.getResponseCode()!=200)throw new IOException("Fixture control failed");}finally{c.disconnect();}}
    private void click(String label){runOnMainSync(()->{View v=find(activity.getWindow().getDecorView(),label,true);if(v==null)throw new AssertionError("Button missing: "+label);v.performClick();});waitForIdleSync();}
    private boolean has(String label){AtomicReference<Boolean>b=new AtomicReference<>(false);runOnMainSync(()->b.set(find(activity.getWindow().getDecorView(),label,false)!=null));return b.get();}
    private void waitText(String label,long ms)throws Exception{long end=System.currentTimeMillis()+ms;while(System.currentTimeMillis()<end){if(has(label))return;Thread.sleep(100);}throw new AssertionError("UI timeout: "+label);}
    private android.view.accessibility.AccessibilityNodeInfo dialogNode(String label){android.view.accessibility.AccessibilityNodeInfo root=getUiAutomation().getRootInActiveWindow();if(root==null)return null;for(android.view.accessibility.AccessibilityNodeInfo node:root.findAccessibilityNodeInfosByText(label))if(label.contentEquals(node.getText()==null?"":node.getText()))return node;return null;}
    private void clickDialog(String label){android.view.accessibility.AccessibilityNodeInfo node=dialogNode(label);if(node==null||!node.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK))throw new AssertionError("Dialog click failed");waitForIdleSync();}
    private void waitDialogText(String label,long ms)throws Exception{long end=System.currentTimeMillis()+ms;while(System.currentTimeMillis()<end){if(dialogNode(label)!=null)return;Thread.sleep(100);}throw new AssertionError("Dialog timeout: "+label);}
    private void waitFixture(String key,int min,long ms)throws Exception{long end=System.currentTimeMillis()+ms;while(System.currentTimeMillis()<end){if(((Number)fixture().get(key)).intValue()>=min)return;Thread.sleep(100);}throw new AssertionError("Fixture timeout: "+key);}
    private static View find(View v,String text,boolean button){if(v instanceof TextView&&(!button||v instanceof Button)&&((TextView)v).getText().toString().equals(text))return v;if(v instanceof ViewGroup){ViewGroup g=(ViewGroup)v;for(int i=0;i<g.getChildCount();i++){View found=find(g.getChildAt(i),text,button);if(found!=null)return found;}}return null;}
    private static void collect(View v,List<EditText>out){if(v instanceof EditText)out.add((EditText)v);if(v instanceof ViewGroup){ViewGroup g=(ViewGroup)v;for(int i=0;i<g.getChildCount();i++)collect(g.getChildAt(i),out);}}
    private static boolean hasImage(View v){if(v instanceof ImageView&&((ImageView)v).getDrawable()!=null)return true;if(v instanceof ViewGroup){ViewGroup g=(ViewGroup)v;for(int i=0;i<g.getChildCount();i++)if(hasImage(g.getChildAt(i)))return true;}return false;}
    private static Map<String,Object> fixture()throws Exception{HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:8081/__fixture/status").openConnection();c.setConnectTimeout(3000);c.setReadTimeout(3000);try(InputStream in=c.getInputStream();ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1)out.write(b,0,n);return JsonCodec.object(JsonCodec.parse(new String(out.toByteArray(),"UTF-8")));}finally{c.disconnect();}}
    private void write(Object value)throws IOException{try(OutputStream out=getTargetContext().openFileOutput("runtime-checks.json",0)){out.write(JsonCodec.stringify(value).getBytes("UTF-8"));}}
    private void screenshot(String name)throws IOException{android.graphics.Bitmap b=getUiAutomation().takeScreenshot();if(b==null)throw new IOException("Screenshot failed");try(OutputStream out=getTargetContext().openFileOutput("runtime-"+name+".png",0)){if(!b.compress(android.graphics.Bitmap.CompressFormat.PNG,100,out))throw new IOException("PNG write failed");}finally{b.recycle();}}
    private static void resetFixture()throws Exception{HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:8081/__fixture/reset").openConnection();c.setRequestMethod("POST");c.setConnectTimeout(3000);c.setReadTimeout(3000);try{if(c.getResponseCode()!=200)throw new IOException("Fixture reset failed");}finally{c.disconnect();}}
}
