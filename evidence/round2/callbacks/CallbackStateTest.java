package com.re.xcs.rebuild.core;

import java.util.*;
import java.util.concurrent.*;

/** Synthetic, local callback ordering/state checks. No networking, credentials, Android UI or original APK execution. */
public final class CallbackStateTest {
    static final List<String> passed=new ArrayList<>();
    static void check(boolean condition,String name){if(!condition)throw new AssertionError(name);passed.add(name);}
    static void eq(Object actual,Object expected,String name){check(Objects.equals(actual,expected),name+" ["+String.valueOf(actual)+"]");}
    static void throwsError(Runnable action,String name){try{action.run();}catch(RuntimeException expected){passed.add(name);return;}throw new AssertionError(name+": did not throw");}
    static Models.Device device(Long id){return new Models.Device(ApiContract.map("id",id,"serial_no","1","direction",1,"mj_count",1));}
    static ApiContract.Response response(int status,Object success){return new ApiContract.Response(status,ApiContract.map("success",success));}
    static void message(MessageEngine engine,Object value){engine.accept(ApiContract.map("msg_type",102,"msg_content",value));}
    static Map<String,Object> params(){Map<String,Object> map=new LinkedHashMap<>();for(String key:new String[]{"left","top","right","bottom","brightness","motor","cap_brightness","cap_exposure","cap_hue","cap_saturation","cap_contrast","cap_gain","img_rotation","img_min_hreshold","cap_fps","bate","img_add_num","gk_min","gk_max"})map.put(key,1);return map;}
    static final class Events implements MessageEngine.Listener {
        final List<String> frames=new ArrayList<>();int ready;SessionState session;
        public void changed(){}public void status(String text){}public void preview(String frame){frames.add(frame);}
        public void readyToValidateAndUpload(){eq(session.mainView.pageMode,2,"recognition callback sees already-open edit page");ready++;}
        public void shortfall(int expected,int actual){}public void failure(Exception error){throw new AssertionError(error);}
    }
    public static void main(String[] args){
        ScheduledExecutorService scheduler=Executors.newSingleThreadScheduledExecutor();
        try{
            SessionState state=new SessionState();state.imageRules="A,A";Events events=new Events();events.session=state;
            MessageEngine engine=new MessageEngine(state,(url,rules,callback)->callback.success("/fixture/frame.png"),events,scheduler);
            Models.Device first=device(7L),second=device(8L);
            eq(state.preview.serviceDeviceId,0L,"initial service ID is zero");eq(engine.currentPreviewDeviceId,-1L,"initial filter is minus one");eq(engine.previewFrame,"","initial frame empty");eq(engine.statusText,"未开始游戏","original main status default");
            engine.enterPreviewPage();eq(events.frames.size(),1,"first equal Rx empty value emits");engine.enterPreviewPage();eq(events.frames.size(),1,"subsequent equal Rx empty suppressed");
            ApiContract.Request start=engine.startPreview(first);eq(start.method,"GET","start method");eq(start.path,"/api/preview/start_preview/7","start path");eq(state.preview.serviceDeviceId,7L,"start writes service before response");eq(engine.currentPreviewDeviceId,-1L,"start does not synchronously change filter");
            message(engine,"7|early");eq(engine.previewFrame,"","prefixed early new device rejected before start value");
            engine.onStartPreviewValue(first,response(500,false));eq(engine.currentPreviewDeviceId,7L,"normal HTTP failure value still sets filter");
            message(engine,"7|frame|tail");eq(engine.previewFrame,"frame","frame reads only split index one");int emitted=events.frames.size();message(engine,"7|frame|other");eq(events.frames.size(),emitted,"duplicate decoded frame notification suppressed");
            message(engine,new String("7|frame"));eq(events.frames.size(),emitted,"equal distinct String object is suppressed");
            message(engine,"8|wrong");eq(engine.previewFrame,"frame","other device ignored");
            throwsError(()->message(engine,"bad|broken"),"invalid prefix parse throws");eq(engine.previewFrame,"frame","parse failure preserves prior frame");
            state.imageRules="invalid";throwsError(()->message(engine,"7|broken"),"decode rule failure throws");eq(engine.previewFrame,"frame","decode failure preserves old frame");state.imageRules="A,A";
            message(engine,"not-base64");eq(engine.previewFrame,"not-base64","Rx writes before external renderer validates image");
            ApiContract.Request end=engine.endPreview(first.id());eq(end.path,"/api/preview/end_preview/7","end path");eq(state.preview.serviceDeviceId,0L,"end clears service before response");eq(engine.currentPreviewDeviceId,7L,"end keeps filter");eq(engine.previewFrame,"not-base64","end keeps frame");
            eq(MessageEngine.sharedNullCompletion(response(500,false)),null,"shared failed end value returns null");eq(engine.currentPreviewDeviceId,7L,"shared failure no filter recovery");eq(state.preview.serviceDeviceId,0L,"shared failure no service rollback");
            message(engine,"7|late");eq(engine.previewFrame,"late","late matching WS102 still updates after end");message(engine,"late-any-device");eq(engine.previewFrame,"late-any-device","unprefixed late WS102 still accepted");
            engine.enterPreviewPage();eq(engine.previewFrame,"","reenter clears frame");eq(engine.currentPreviewDeviceId,7L,"reenter retains filter");message(engine,"7|old-session");eq(engine.previewFrame,"old-session","old-device frame accepted in reentry window");
            engine.startPreview(second);eq(state.preview.serviceDeviceId,8L,"second start request sets new service ID");eq(engine.currentPreviewDeviceId,7L,"second pending start leaves old filter");
            state.connected=false;state.authenticated=false;eq(engine.currentPreviewDeviceId,7L,"disconnect does not reset preview filter");eq(state.preview.serviceDeviceId,8L,"disconnect does not clear request ID");
            state.connected=true;state.authenticated=true;eq(engine.currentPreviewDeviceId,7L,"reconnect/auth state does not change filter");
            engine.onStartPreviewValue(second,response(200,true));engine.onStartPreviewValue(first,response(200,true));eq(engine.currentPreviewDeviceId,7L,"out-of-order completion last value wins");eq(state.preview.serviceDeviceId,8L,"start response does not rewind service ID");
            first.fields.put("id",9L);engine.onStartPreviewValue(first,response(200,false));eq(engine.currentPreviewDeviceId,9L,"start callback reads captured device live ID");
            ApiContract.Request returned=engine.onPreviewRouteReturned();eq(returned.path,"/api/preview/end_preview/8","route ends current service ID not current filter");eq(engine.onPreviewRouteReturned(),null,"second route return zero skips end");
            Models.Device missing=device(null);eq(engine.startPreview(missing).path,"/api/preview/start_preview/null","nullable start ID preserved");eq(state.preview.serviceDeviceId,null,"service can hold null");engine.onStartPreviewValue(missing,response(500,false));eq(engine.currentPreviewDeviceId,0L,"null callback ID defaults filter zero");eq(engine.onPreviewRouteReturned().path,"/api/preview/end_preview/null","route null differs from zero and ends null");
            engine.startPreview(first);engine.savePreviewParams(first.id(),params());eq(state.preview.serviceDeviceId,0L,"save clears service regardless close mode");
            MessageEngine.PreviewSaveOutcome failed=engine.onSavePreviewValue(first,true,response(500,true));check(!failed.popWithTrue&&failed.endRequest==null,"HTTP failure save no end/no pop");eq(engine.onPreviewRouteReturned(),null,"failed save leaves zero so route cleanup skips end");
            failed=engine.onSavePreviewValue(first,true,response(200,false));check(!failed.popWithTrue&&failed.endRequest==null,"business false save no end/no pop");
            failed=engine.onSavePreviewValue(first,false,response(200,true));check(!failed.popWithTrue&&failed.endRequest==null,"save-only success leaves page");
            throwsError(()->engine.onSavePreviewValue(first,true,response(200,null)),"missing success is type failure");throwsError(()->engine.onSavePreviewValue(first,true,response(200,"true")),"string success is type failure");throwsError(()->engine.onSavePreviewValue(first,true,response(200,1)),"integer success is type failure");
            first.fields.put("id",10L);MessageEngine.PreviewSaveOutcome close=engine.onSavePreviewValue(first,true,response(200,true));check(close.popWithTrue,"accepted close requests immediate pop");eq(close.endRequest.path,"/api/preview/end_preview/10","accepted close uses device live ID");eq(state.preview.serviceDeviceId,0L,"close clears service before caller submits end/pop");eq(engine.onPreviewRouteReturned(),null,"pop continuation avoids second end");
            engine.startPreview(second);throwsError(()->engine.savePreviewParams(second.id(),Collections.emptyMap()),"bad reconstruction params rejected");eq(state.preview.serviceDeviceId,0L,"service clear precedes parameter validation");
            engine.onStartPreviewValue(second,response(200,true));message(engine,"8|persist");engine.close();
            MessageEngine replacement=new MessageEngine(state,(u,r,c)->{},events,scheduler);eq(replacement.currentPreviewDeviceId,8L,"new Main engine keeps singleton filter");eq(replacement.previewFrame,"persist","new Main engine keeps singleton frame");
            eq(state.mainView.pageMode,1,"new Main page mode reset");eq(state.mainView.displayType,2,"new Main display default");
            replacement.close();throwsError(()->message(replacement,"discard"),"reconstruction closed engine intentionally rejects receiver dispatch");
            SessionState.PreviewState rx=new SessionState.PreviewState();check(rx.setFrame(""),"Rx first equal emits in isolation");check(!rx.setFrame(""),"Rx later equal does not emit");check(rx.setFrame("x"),"Rx changed value emits");rx.closeFrameStream();check(!rx.setFrame("y"),"closed framework stream ignores setter");eq(rx.frame,"x","closed framework stream does not update value");check(rx.frameStreamClosed(),"explicit framework stream close visible");
            for(Object code:new Object[]{401L,401,401.0}){state.jwt="fixture";check(state.onHttpError(new ApiContract.Response(401,ApiContract.map("code",code))),"HTTP numeric equality accepts "+code.getClass().getSimpleName());eq(state.jwt,"","matching numeric 401 clears JWT");}
            for(Object code:new Object[]{"401",400,401.5,null}){state.jwt="fixture";check(!state.onHttpError(new ApiContract.Response(401,ApiContract.map("code",code))),"nonmatching code rejected "+code);eq(state.jwt,"fixture","nonmatching code preserves JWT");}
            check(!state.onHttpError(new ApiContract.Response(200,ApiContract.map("code",401))),"code401 with HTTP200 does not clear");
            testMainCallbacks();testRecognition(scheduler);testLateImage(scheduler);
            System.out.println(JsonCodec.stringify(ApiContract.map("status","PASS","assertion_count",passed.size(),"checks",passed,"business_server_contacted",false,"original_apk_executed",false,"scope","Executable reconstructed callback state only; not dynamic equivalence of original Flutter framework or server")));
        }finally{scheduler.shutdownNow();}
    }
    static void testMainCallbacks(){
        SessionState s=new SessionState();Models.Tile tile=new Models.Tile(1);Map<String,Object> config=ApiContract.map("id",11,"number",99,"url","asset11");
        eq(s.mainView.pageMode,1,"page default 1");eq(s.mainView.displayType,2,"display default 2");check(!s.mainView.paletteVisible&&s.mainView.selectedResult==null,"initial palette/selection");
        ResultRules.openChangePage(s);eq(s.mainView.pageMode,2,"open edit sets2");ResultRules.closeChangePage(s);eq(s.mainView.pageMode,1,"close from2 sets1");ResultRules.closeChangePage(s);eq(s.mainView.pageMode,0,"close from1 sets0");ResultRules.closeChangePage(s);eq(s.mainView.pageMode,1,"close from0 sets1");
        ResultRules.selectResultForEdit(s,tile);check(s.mainView.selectedResult==tile&&s.mainView.paletteVisible,"result click captures object and opens palette");
        ResultRules.toggleDisplayType(s);eq(s.mainView.displayType,1,"display2 becomes1");check(s.mainView.paletteVisible&&s.mainView.selectedResult==tile,"display toggle retains palette/selection");ResultRules.selectMain(s,config);eq(tile.result,"11","main selects config id rather than number");eq(tile.resultImg,"asset11","main selection updates image");check(s.mainView.paletteVisible,"display1 selection leaves palette");
        ResultRules.toggleDisplayType(s);eq(s.mainView.displayType,2,"display1 becomes2");ResultRules.selectMain(s,config);check(!s.mainView.paletteVisible&&s.mainView.selectedResult==tile,"display2 selection hides but retains selected object");
        ResultRules.openPalette(s);ResultRules.cancelResultSelection(s);check(s.mainView.selectedResult==null&&s.mainView.paletteVisible,"cancel clears selected only, caller pops");ResultRules.selectMain(s,ApiContract.map());check(s.mainView.paletteVisible,"no selected tile means selection no-op");ResultRules.closePalette(s);check(!s.mainView.paletteVisible,"close palette false");
        ResultRules.openChangePage(s);ResultRules.selectResultForEdit(s,tile);ResultRules.afterUploadAccepted(s);eq(s.mainView.pageMode,2,"empty channels upload leaves page mode");check(s.mainView.paletteVisible,"empty channels upload leaves palette");
        Models.Channel channel=new Models.Channel(device(1L));channel.results.add(tile);s.channels.add(channel);channel.removedOffset=3;
        List<Models.Tile> previousResults=channel.results;ResultRules.afterUploadAccepted(s);check(previousResults!=channel.results,"upload replaces list identity");eq(previousResults.size(),1,"old list reference retains old result");eq(channel.results.size(),0,"accepted upload clears live results");eq(s.mainView.pageMode,1,"nonempty channels upload sets page1");check(!s.mainView.paletteVisible,"display2 upload hides palette");check(s.mainView.selectedResult==tile,"upload retains selected object");eq(channel.removedOffset,3,"upload retains removed offset");
        s.mainView.displayType=1;ResultRules.openPalette(s);ResultRules.afterUploadAccepted(s);check(s.mainView.paletteVisible,"display1 upload leaves palette visible");
    }
    static void testLateImage(ScheduledExecutorService scheduler){
        SessionState s=new SessionState();s.imageRules="A,A";s.businessHost="fixture.invalid";s.user.put("timeout",60);Models.Channel channel=new Models.Channel(device(1L));s.channels.add(channel);Events events=new Events();events.session=s;
        List<MessageEngine.ImageResult> pending=new ArrayList<>();MessageEngine engine=new MessageEngine(s,(u,r,c)->pending.add(c),events,scheduler);
        Models.Tile old=new Models.Tile(1);channel.results.add(old);List<Models.Tile> oldList=channel.results;
        engine.accept(ApiContract.map("msg_type",101,"msg_content",ApiContract.map("serial_number","1","mahjong_number",2,"img","fixture","ai_val",-1)));
        engine.accept(ApiContract.map("msg_type",113));check(channel.results!=oldList,"new round replaces list identity");eq(oldList.size(),1,"new round leaves old list snapshot intact");eq(channel.results.size(),0,"new round installs empty live list");
        pending.get(0).success("/fixture/late-image.png");eq(channel.results.size(),1,"late image appends to current new-round list");eq(channel.results.get(0).sequence,2,"late image keeps captured sequence");
        engine.accept(ApiContract.map("msg_type",101,"msg_content",ApiContract.map("serial_number","1","mahjong_number",3,"img","fixture","ai_val",-1)));engine.close();pending.get(1).success("/fixture/disposed.png");eq(channel.results.size(),1,"reconstruction close intentionally suppresses late image after disposal");
    }
    static void testRecognition(ScheduledExecutorService scheduler){
        SessionState s=new SessionState();s.imageRules="A,A";s.businessHost="fixture.invalid";Models.Channel channel=new Models.Channel(device(1L));s.channels.add(channel);Events events=new Events();events.session=s;
        MessageEngine engine=new MessageEngine(s,(u,r,c)->c.success("/fixture/image.png"),events,scheduler);engine.palette.add(ApiContract.map("number",11,"url","asset11"));
        engine.accept(ApiContract.map("msg_type",101,"msg_content",ApiContract.map("serial_number","1","mahjong_number",1,"img","fixture","ai_val",11,"ai_precision",0.9)));
        eq(events.ready,1,"recognition completeness reaches validation callback");eq(s.mainView.pageMode,2,"recognition opens edit page");engine.close();
    }
}
