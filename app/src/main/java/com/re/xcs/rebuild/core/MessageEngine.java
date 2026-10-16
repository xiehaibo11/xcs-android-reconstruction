package com.re.xcs.rebuild.core;

import java.util.*;
import java.util.concurrent.*;

/** Runnable receive-side business state, not a WebSocket/authentication implementation. */
public final class MessageEngine implements AutoCloseable {
    public interface ImageLoader { void fetchAndCache(String url,String substitutionRules,ImageResult result); }
    public interface ImageResult { void success(String localPath);void failure(Exception error); }
    public interface Listener {
        void changed();void status(String text);void preview(String base64Jpeg);
        void readyToValidateAndUpload();void shortfall(int expected,int actual);void failure(Exception error);
    }
    private final SessionState state;private final ImageLoader images;private final Listener listener;
    private final ScheduledExecutorService scheduler;
    private ScheduledFuture<?> countdownTask;private final List<ScheduledFuture<?>> delayed=new ArrayList<>();
    private boolean closed;public boolean pairSwap;public long currentPreviewDeviceId=-1;
    public int countdown;public String statusText="未开始游戏",previewFrame="";
    public final List<Map<String,Object>> palette=new ArrayList<>();
    public MessageEngine(SessionState state,ImageLoader images,Listener listener,ScheduledExecutorService scheduler){this.state=Objects.requireNonNull(state);this.images=Objects.requireNonNull(images);this.listener=Objects.requireNonNull(listener);this.scheduler=Objects.requireNonNull(scheduler);currentPreviewDeviceId=state.preview.filterDeviceId;previewFrame=state.preview.frame;state.mainView.reset();}
    /** FramePreview.initState clears the global Rx value, not either device ID. */
    public synchronized void enterPreviewPage(){setPreviewFrame("");}
    /** Caller executes the returned request; this method does not contact a server. */
    public synchronized ApiContract.Request startPreview(Models.Device device){Long id=Objects.requireNonNull(device).id();state.preview.serviceDeviceId=id;return ApiContract.startPreview(id);}
    /** Normal Future values, including ok=false, set the filter. A rejected/pending Future never calls this. */
    public synchronized void onStartPreviewValue(Models.Device capturedDevice,ApiContract.Response ignored){Long id=Objects.requireNonNull(capturedDevice).id();currentPreviewDeviceId=id==null?0:id;state.preview.filterDeviceId=currentPreviewDeviceId;}
    /** PreviewService.setParams clears the request ID before constructing/sending the request. */
    public synchronized ApiContract.Request savePreviewParams(Number id,Map<String,Object> params){state.preview.serviceDeviceId=0L;return ApiContract.previewParams(id,params);}
    public static final class PreviewSaveOutcome {
        public final ApiContract.Request endRequest;public final boolean popWithTrue;
        private PreviewSaveOutcome(ApiContract.Request endRequest,boolean pop){this.endRequest=endRequest;this.popWithTrue=pop;}
    }
    /**
     * 0x460b60: strict Boolean success; on accepted close, issue end BEFORE pop(true), without
     * waiting for its response. The captured Devices object's id is read at callback time.
     * Caller owns navigation and its mounted policy; no original mounted check is invented here.
     */
    public synchronized PreviewSaveOutcome onSavePreviewValue(Models.Device capturedDevice,boolean close,ApiContract.Response response){
        if(!response.ok())return new PreviewSaveOutcome(null,false);
        Object success=response.object().get("success");if(!(success instanceof Boolean))throw new IllegalArgumentException("preview save success must be bool");
        if(!((Boolean)success)||!close)return new PreviewSaveOutcome(null,false);
        return new PreviewSaveOutcome(endPreview(Objects.requireNonNull(capturedDevice).id()),true);
    }
    /** Clear before POST even if it later fails. No filter/frame reset, retry, or rollback. */
    public synchronized ApiContract.Request endPreview(Number id){state.preview.serviceDeviceId=0L;return ApiContract.endPreview(id);}
    /** Parent route completion ignores pop's result. null != 0, so a null ID still ends /null. */
    public synchronized ApiContract.Request onPreviewRouteReturned(){Long id=state.preview.serviceDeviceId;return id!=null&&id==0?null:endPreview(id);}
    /** Exact shared 8-byte closure at 0x6f2a58 (mov x0,x22; ret), not an unfinished stub. */
    public static Object sharedNullCompletion(Object ignored){return null;}
    public synchronized void accept(Map<String,Object> message){
        if(closed)throw new IllegalStateException("Message engine closed");
        Long type=Models.integer(message.get("msg_type"));Object content=message.get("msg_content");if(type==null||type<Integer.MIN_VALUE||type>Integer.MAX_VALUE)return;
        switch(type.intValue()){
            case 101: saveImage(Models.read("MessageUpImg",JsonCodec.object(content)));break;
            case 102: preview(content);break;
            case 117:{String serial=contentString(content).split("\\|",-1)[0];for(Models.Channel c:state.channels)if(Objects.equals(serial,c.device.serial())){c.device.lighting(1);listener.changed();}status("升降牌打开，等待洗牌中...");break;}
            case 115:for(Models.Channel c:state.channels)if(Objects.equals(contentString(content),c.device.serial())){c.device.online(0);c.device.lighting(0);}break;
            case 116:for(Models.Channel c:state.channels)if(Objects.equals(contentString(content),c.device.serial()))c.device.online(1);break;
            case 114: finishDevice(content);break;
            case 113: startRound();break;
            default: // Observed listener deliberately ignores unhandled message types.
        }
    }
    public synchronized void endGamesAccepted(){cancelCountdown(false);countdown=0;status("未开始游戏");}
    private static String contentString(Object content){return content==null?"null":DartConversions.messageContentString(content);}
    private void preview(Object content){String s=contentString(content);if(s.contains("|")){String[] p=s.split("\\|",-1);if(ResultRules.parseInt(p[0])!=currentPreviewDeviceId)return;s=p[1];}setPreviewFrame(ApiContract.decodeData(s,state.imageRules));}
    private void setPreviewFrame(String value){if(state.preview.setFrame(value)){previewFrame=state.preview.frame;listener.preview(previewFrame);}}
    private void status(String text){statusText=text;listener.status(text);}
    private void cancelCountdown(boolean clearReference){if(countdownTask!=null)countdownTask.cancel(false);if(clearReference)countdownTask=null;}
    private void startRound(){if(countdown>0)return;for(Models.Channel c:state.channels){c.results=new ArrayList<>();listener.changed();}countdown=state.timeout();status("数据接收中...("+countdown+"秒)");
        countdownTask=scheduler.scheduleAtFixedRate(new Runnable(){public void run(){synchronized(MessageEngine.this){if(closed)return;countdown--;status("数据接收中...("+countdown+"秒)");if(countdown<=0)cancelCountdown(false);}}},1,1,TimeUnit.SECONDS);
    }
    private void finishDevice(Object content){boolean allClosed=true;for(Models.Channel c:state.channels){if(Objects.equals(c.device.serial(),contentString(content))){c.device.lighting(0);listener.changed();}if(c.device.open())allClosed=false;}
        if(allClosed){status("接受完成，等待下轮数据...");cancelCountdown(true);countdown=0;delayed.add(scheduler.schedule(new Runnable(){public void run(){synchronized(MessageEngine.this){if(closed)return;int expected=state.expectedCount(),actual=state.receivedCount();if(actual<expected)listener.shortfall(expected,actual);}}},5,TimeUnit.SECONDS));}
    }
    private void saveImage(final Models.Record image){int raw=Models.intOr(image.get("mahjong_number"),0);final int number=pairSwap?(raw%2==0?raw-1:raw+1):raw;String path=image.text("img");if(path==null)path="";
        if(path.equals("x")){Models.Tile tile=new Models.Tile(number);for(Models.Channel c:state.channels)if(Objects.equals(c.device.serial(),image.text("serial_number"))){c.results.add(tile);listener.changed();break;}return;}
        images.fetchAndCache(ApiContract.imageUrl(path,state.businessHost),state.imageRules,new ImageResult(){public void failure(Exception e){listener.failure(e);}public void success(String localPath){synchronized(MessageEngine.this){if(closed)return;try{
            Models.Tile tile=new Models.Tile(number);tile.uploadImg=localPath;Long ai=image.number("ai_val");
            if(!Long.valueOf(-1).equals(ai)){for(Map<String,Object> entry:palette)if(String.valueOf(entry.get("number")).equals(String.valueOf(ai))){tile.result=String.valueOf(ai);tile.resultImg=Models.string(entry.get("url"));Double confidence=Models.nullableDouble(image.get("ai_precision"));tile.confidence=confidence==null?0.0:confidence;break;}}
            for(Models.Channel c:state.channels)if(Objects.equals(c.device.serial(),image.text("serial_number"))){Objects.requireNonNull(c.device.direction(),"matched device.direction");if(tile.sequence==1)c.removedOffset=0;tile.sequence-=c.removedOffset;c.results.add(tile);listener.changed();break;}
            if(state.recognizedCount()==state.expectedCount()){cancelCountdown(false);countdown=0;status("等待数据发送中...");ResultRules.openChangePage(state);listener.readyToValidateAndUpload();}
        }catch(Exception e){listener.failure(e);}}}});
    }
    /** Reconstruction lifecycle guard: original late HTTP image callbacks had no mounted/closed gate. */
    @Override public synchronized void close(){closed=true;cancelCountdown(true);for(ScheduledFuture<?> f:delayed)f.cancel(false);delayed.clear();}
}
