package com.re.xcs.rebuild.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Pure JDK behavior checks for explicitly bounded recovered settings contracts. */
public final class SettingsLogicTest {
    private static int assertions;
    private static void check(boolean value, String reason) {
        assertions++;
        if (!value) throw new AssertionError(reason);
    }
    private static void equal(Object expected, Object actual, String reason) {
        check(expected == null ? actual == null : expected.equals(actual),
                reason + ": expected=" + expected + ", actual=" + actual);
    }
    private static void rejected(Class<? extends Throwable> type, Runnable action, String reason) {
        assertions++;
        try { action.run(); }
        catch (Throwable error) {
            if (type.isInstance(error)) return;
            throw new AssertionError(reason + ": wrong exception " + error, error);
        }
        throw new AssertionError(reason + ": input was accepted");
    }
    private static ApiContract.Response response(Object... body) {
        return new ApiContract.Response(200, ApiContract.map(body));
    }
    private static Map<String,Object> body(ApiContract.Request request) {
        return JsonCodec.object(request.body);
    }
    private static Models.Channel channel(int direction, int count) {
        return new Models.Channel(new Models.Device(ApiContract.map("direction",direction,"mj_count",count)));
    }

    public static void main(String[] args) {
        passwords();
        dataAndNumberSaves();
        configAndResponses();
        wifiForms();
        polling();
        wifiParsing();
        equal(42,SettingsLogic.inputInteger(" +42 "),"decimal trim/sign adapter");
        rejected(IllegalArgumentException.class,()->SettingsLogic.inputInteger("0x10"),"unported hex rejected explicitly");
        rejected(IllegalArgumentException.class,()->SettingsLogic.inputInteger("2147483648"),"unported 64-bit range rejected explicitly");
        System.out.println("PASS SettingsLogicTest: " + assertions + " assertions; original_source_recovered=false; full_behavior_equivalence=false");
    }

    private static void passwords() {
        equal("请输入原密码",SettingsLogic.validatePassword("12345","x","x").get("old_password"),"old password six UTF-16 units minimum");
        check(SettingsLogic.validatePassword("123456","x","x").isEmpty(),"new password has no six-character rule");
        check(SettingsLogic.validatePassword("😀😀😀"," "," ").isEmpty(),"Dart string length and no trimming");
        equal("请输入新密码",SettingsLogic.validatePassword("123456","","").get("password"),"new required message");
        equal("请输入重复新密码",SettingsLogic.validatePassword("123456","x","").get("confirmation"),"confirmation required message");
        equal("重复密码与新密码不一致",SettingsLogic.validatePassword("123456","x","y").get("confirmation"),"confirmation exact equality");
        Map<String,Object> password = body(SettingsLogic.preparePassword(" 123456 "," "," "));
        equal(" 123456 ",password.get("old_password"),"old password sent raw");
        equal(" ",password.get("password"),"new password sent raw");
    }

    private static void dataAndNumberSaves() {
        SessionState session = new SessionState();
        session.user.put("timeout",60); session.user.put("data_send",9); session.user.put("delay",88);
        SettingsLogic.Form form = new SettingsLogic.Form();
        form.timeout="77"; form.delay="6"; form.dataSend=2; form.countType=5; form.uploadImageClarity=3;
        Map<String,Object> data=body(SettingsLogic.prepareDataSave(form,session));
        equal(77,session.user.get("timeout"),"timeout written before request dispatch");
        equal(77,data.get("timeout"),"timeout sent"); equal(6,data.get("delay"),"delay sent");
        equal(2,data.get("data_send"),"data send sent"); equal(5,data.get("count_type"),"count type sent");
        equal(3,data.get("upload_img_clarity"),"clarity sent");
        SettingsLogic.Outcome failed=SettingsLogic.evaluateResponse(SettingsLogic.Action.DATA,response("success",false,"msg","denied"),null);
        equal(SettingsLogic.Failure.BUSINESS,failed.failure,"business rejection recognized");
        equal(77,session.user.get("timeout"),"no timeout rollback on failure");
        equal(9,session.user.get("data_send"),"data_send session unchanged");
        equal(88,session.user.get("delay"),"delay session unchanged");
        form.timeout="90"; form.delay="bad";
        rejected(IllegalArgumentException.class,()->SettingsLogic.prepareDataSave(form,session),"all parses before timeout write");
        equal(77,session.user.get("timeout"),"parse error before mutation");

        for(int direction=1;direction<=5;direction++)session.channels.add(channel(direction,26));
        Map<String,Object> sent=body(SettingsLogic.prepareNumberSave(form));
        equal(26,sent.get("east"),"request captures send time value");
        form.east="31";form.south="32";form.west="33";form.north="34";
        SettingsLogic.applyNumberResponse(form,session,response(),null);
        for(int index=0;index<4;index++)equal(31+index,session.channels.get(index).device.count(),"response rereads current controllers for direction "+(index+1));
        equal(26,session.channels.get(4).device.count(),"unknown direction unchanged");
        form.east="99";
        SettingsLogic.applyNumberResponse(form,session,response("success",false,"msg","rejected"),null);
        equal(31,session.channels.get(0).device.count(),"business failure does not write device count");
        equal(2,SettingsLogic.mapChannelId(1,true),"reverse odd maps to next");
        equal(1,SettingsLogic.mapChannelId(2,true),"reverse even maps to previous");
        equal(3,SettingsLogic.mapChannelId(3,false),"normal order unchanged");
    }

    private static void configAndResponses() {
        SettingsLogic.Form form=new SettingsLogic.Form();form.ssid="manual";form.wifiPassword="existing";
        Map<String,Object> config=ApiContract.map("config_number",ApiContract.map(),"data_config",ApiContract.map(),"wifi_config",ApiContract.map("ssid","remote","pwd","server"),"lighting_config",ApiContract.map());
        check(SettingsLogic.applyConfig(form,response("data",config)),"missing success accepted by config callback");
        equal("26",form.east,"number default");equal("60",form.timeout,"timeout default");equal("5",form.delay,"delay default");
        equal(1,form.dataSend,"send default");equal(1,form.countType,"count default");equal(1,form.uploadImageClarity,"clarity default");
        equal("manual",form.ssid,"config load preserves manual ssid");equal("existing",form.wifiPassword,"config load preserves manual pwd");
        rejected(IllegalArgumentException.class,()->SettingsLogic.applyConfig(form,response("data",ApiContract.map())),"missing required nested config maps rejected");
        check(!SettingsLogic.applyConfig(form,response("success",false)),"config business failure keeps form");
        check(SettingsLogic.applyDefaultWifi(form,response("success",true,"data",ApiContract.map("ssid","default","pwd",null))),"default wifi bool true");
        equal("default",form.ssid,"default ssid");equal("null",form.wifiPassword,"Dart null toString retained");
        check(!SettingsLogic.applyDefaultWifi(form,response("success",false)),"default wifi bool false");
        rejected(IllegalArgumentException.class,()->SettingsLogic.applyDefaultWifi(form,response()),"default wifi bool cast rejects missing success");
        check(SettingsLogic.evaluateResponse(SettingsLogic.Action.DATA,response("success",null),null).accepted(),"null success accepted for ordinary save");
        check(SettingsLogic.evaluateResponse(SettingsLogic.Action.DATA,response("success",0),null).accepted(),"nonfalse success accepted for ordinary save");
        equal(SettingsLogic.Navigation.LOGIN_CLEAR_STACK,SettingsLogic.evaluateResponse(SettingsLogic.Action.PASSWORD,response(),null).navigation,"password navigation resets stack");
        SettingsLogic.Outcome restart=SettingsLogic.evaluateResponse(SettingsLogic.Action.RESTART,response(),null);
        equal(SettingsLogic.Navigation.POP,restart.navigation,"restart pops page");equal("black",restart.logColor,"restart black log");check(restart.useOriginalShowErr,"restart uses original showErr helper even on success");
        SettingsLogic.Outcome failed=SettingsLogic.evaluateResponse(SettingsLogic.Action.NUMBER,new ApiContract.Response(500,ApiContract.map()),"offline");
        equal(SettingsLogic.Failure.NETWORK,failed.failure,"HTTP failure");equal("offline",failed.message,"transport message");equal("red",failed.logColor,"number transport log");
        rejected(IllegalArgumentException.class,()->SettingsLogic.evaluateResponse(SettingsLogic.Action.DATA,response("success",false,"msg",7),null),"original message String cast retained");
    }

    private static void wifiForms() {
        SettingsLogic.Form form=new SettingsLogic.Form();
        equal("",body(SettingsLogic.prepareWifiSave(form,false)).get("ssid"),"manual wifi accepts blank ssid");
        rejected(IllegalArgumentException.class,()->SettingsLogic.prepareWifiSave(form,true),"scan wifi requires selected ssid");
        form.ssid="Office";
        rejected(IllegalArgumentException.class,()->SettingsLogic.prepareWifiSave(form,true),"scan wifi requires password");
        form.wifiPassword="pass";
        equal("pass",body(SettingsLogic.prepareWifiSave(form,true)).get("pwd"),"wifi raw password");
        SettingsLogic.selectWifi(form,new SettingsLogic.WifiItem("Other","3/5"));
        equal("Other",form.ssid,"wifi selection fills ssid");equal("",form.wifiPassword,"wifi selection clears password");
    }

    private static final class Timer implements SettingsLogic.Cancel {
        final long millis;final Runnable task;boolean cancelled;
        Timer(long millis,Runnable task){this.millis=millis;this.task=task;}
        @Override public void cancel(){cancelled=true;}
    }
    private static final class Sent {
        final ApiContract.Request request;final SettingsLogic.Completion completion;
        Sent(ApiContract.Request request,SettingsLogic.Completion completion){this.request=request;this.completion=completion;}
    }
    private static void polling() {
        final List<Timer> timers=new ArrayList<>();final List<Sent> calls=new ArrayList<>();final int[] lists={0};
        SettingsLogic.WifiPolling polling=new SettingsLogic.WifiPolling((millis,task)->{Timer timer=new Timer(millis,task);timers.add(timer);return timer;},(request,completion)->calls.add(new Sent(request,completion)),(response,error)->lists[0]++);
        polling.start();equal(2,calls.size(),"two initial device-up requests");
        equal("/api/config/wifi_device_up",calls.get(0).request.path,"initial device up 1");
        equal("/api/config/wifi_device_up",calls.get(1).request.path,"initial device up 2");
        equal(2,timers.size(),"two timers");equal(3000L,timers.get(0).millis,"list period");equal(15000L,timers.get(1).millis,"device up period");
        calls.get(0).completion.complete(new ApiContract.Response(500,ApiContract.map()),"offline");
        equal("/api/config/get_device_wifi_list",calls.get(2).request.path,"device-up failure still fetches list");
        timers.get(0).task.run();equal("/api/config/get_device_wifi_list",calls.get(3).request.path,"3-second tick");
        timers.get(1).task.run();equal("/api/config/wifi_device_up",calls.get(4).request.path,"15-second tick");
        polling.close();check(timers.get(0).cancelled&&timers.get(1).cancelled,"dispose cancels both timers");
        calls.get(1).completion.complete(response("success",false),null);
        equal("/api/config/get_device_wifi_list",calls.get(5).request.path,"late device-up callback after dispose still gets list");
        calls.get(5).completion.complete(response("data",""),null);equal(1,lists[0],"late list callback not silently suppressed by core");
        rejected(IllegalStateException.class,()->polling.start(),"single page init");
    }

    private static void wifiParsing() {
        SettingsLogic.WifiScan dbm=SettingsLogic.parseWifiData("-44dBm|Alpha,-45dBm|Bravo,-55dBm|Charlie,-70dBm|Delta,-80dBm|Echo");
        equal(5,dbm.inputOrderItems.size(),"unquoted schema item count");
        for(int i=0;i<5;i++)equal(100-i*20,dbm.inputOrderItems.get(i).percent,"dBm threshold boundary "+i);
        equal("Alpha",dbm.inputOrderItems.get(0).ssid,"input response order retained explicitly");
        check(!dbm.orderingRecovered&&!dbm.limitation.isEmpty(),"unrecovered original sort is declared");
        SettingsLogic.WifiScan quoted=SettingsLogic.parseWifiData("\"Office\",5/5Signallevel=-40|\"Cafe\",3/5|\"\",4/5");
        equal(2,quoted.inputOrderItems.size(),"quoted schema ignores empty ssid");equal("Office",quoted.inputOrderItems.get(0).ssid,"quotes removed");
        equal("5/5",quoted.inputOrderItems.get(0).score,"Signallevel suffix removed");equal(60,quoted.inputOrderItems.get(1).percent,"score percentage");
        SettingsLogic.WifiItem strong=quoted.inputOrderItems.get(0),weak=quoted.inputOrderItems.get(1);
        equal(0,SettingsLogic.originalWifiCompare(strong,weak),"original stronger comparator return is zero");
        equal(1,SettingsLogic.originalWifiCompare(strong,strong),"original equal comparator return is one");
        equal("中Office",SettingsLogic.parseWifiData("-40dBm|\\xE4\\xB8\\xADOffice").inputOrderItems.get(0).ssid,"escaped UTF8 prefix plus suffix");
        equal("中",SettingsLogic.escapedHexToUtf8("\\xE4\\xB8\\xAD"),"hex radix sixteen");
        rejected(IllegalArgumentException.class,()->SettingsLogic.escapedHexToUtf8("\\xE"),"odd hex fails");
        rejected(IllegalArgumentException.class,()->SettingsLogic.escapedHexToUtf8("\\xFF"),"strict UTF8 fails");
        rejected(UnsupportedOperationException.class,()->SettingsLogic.parseWifiData("bad|SomeSSID"),"unclosed original exception branch fails explicitly");
        rejected(UnsupportedOperationException.class,()->SettingsLogic.parseWifiResponse(response("data",ApiContract.map())),"dynamic non-string data not fabricated");
        equal(null,SettingsLogic.parseWifiResponse(new ApiContract.Response(500,ApiContract.map())),"transport failure preserves old wifi list");
        equal(1,SettingsLogic.parseWifiResponse(response("success",false,"data","-40dBm|Office")).inputOrderItems.size(),"scan callback ignores business success flag");
        check(SettingsLogic.parseWifiData("").orderingRecovered,"empty sort is exact");
        equal(0,new SettingsLogic.WifiItem("x","").percent,"blank score returns zero");
    }
}
