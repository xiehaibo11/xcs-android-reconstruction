package com.re.xcs.rebuild.core;

import java.util.*;

/** State slots separated by observed ownership; transport connection is not authentication. */
public final class SessionState {
    public String baseUri="",businessHost="",imageRules="",jwt="",deviceId="",username="",password="";
    public Map<String,Object> user=new LinkedHashMap<>();
    public final List<Models.Channel> channels=new ArrayList<>();
    public boolean connected,authenticated;
    /** Original singleton service slots survive a preview route being removed. */
    public final PreviewState preview=new PreviewState();
    /** Main page fields; a newly constructed Main page initializes these values. */
    public final MainViewState mainView=new MainViewState();
    public static final class PreviewState {
        public Long serviceDeviceId=0L;
        public long filterDeviceId=-1;
        public String frame="";
        private boolean firstEmission=true,streamClosed;
        /** RxString.value= at 0x51d884: first equal value emits, later equal values do not. */
        public boolean setFrame(String value){Objects.requireNonNull(value,"RxString value");if(streamClosed||(!firstEmission&&frame.equals(value)))return false;firstEmission=false;frame=value;return true;}
        /** Framework behavior only: preview route exit does NOT call this. */
        public void closeFrameStream(){streamClosed=true;}
        public boolean frameStreamClosed(){return streamClosed;}
    }
    public static final class MainViewState {
        public int pageMode=1,displayType=2;
        public boolean paletteVisible;
        public Models.Tile selectedResult;
        public void reset(){pageMode=1;displayType=2;paletteVisible=false;selectedResult=null;}
    }
    public Map<String,String> requestHeaders(String constructedClientVersion){Map<String,String> m=new LinkedHashMap<>();m.put("Content-Type","application/json");m.put("clienttype","android");m.put("Authorization","Bearer "+jwt);m.put("deviceId",deviceId);m.put("clientversion",constructedClientVersion);return m;}
    public boolean onHttpError(ApiContract.Response response){if(response.status==401&&response.data instanceof Map){Object code=JsonCodec.object(response.data).get("code");if(code instanceof Number&&((Number)code).doubleValue()==401.0){jwt="";return true;}}return false;}
    public int timeout(){return Models.intOr(user.get("timeout"),60);}
    public int expectedCount(){int n=0;for(Models.Channel c:channels)n+=c.device.expected();return n;}
    public int receivedCount(){int n=0;for(Models.Channel c:channels)n+=c.results.size();return n;}
    public int recognizedCount(){int n=0;for(Models.Channel c:channels)for(Models.Tile r:c.results)if(!r.result.isEmpty())n++;return n;}
}
