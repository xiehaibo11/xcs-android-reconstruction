package com.re.xcs.rebuild.core;

import java.util.*;

/** Validation, upload payload and editing bodies at 4a26cc / 4a2164 / 4a67dc / 4b68d4. */
public final class ResultRules {
    private ResultRules() {}
    public static final class Validation {
        public final List<String> errors;public final int expected,actual;
        Validation(List<String> errors,int expected,int actual){this.errors=Collections.unmodifiableList(errors);this.expected=expected;this.actual=actual;}
        public boolean valid(){return errors.isEmpty();}
    }
    /** Empty/non-numeric results throw, matching the observed int.parse path. */
    public static Validation validate(List<Models.Channel> channels){
        List<String> errors=new ArrayList<>();Map<Long,Integer> counts=new LinkedHashMap<>();int actual=0,expected=0;
        for(Models.Channel channel:channels){for(Models.Tile tile:channel.results){long value=parseInt(tile.result);Integer n=counts.get(value);counts.put(value,n==null?1:n+1);actual++;}expected+=channel.device.expected();
            if(!Objects.equals(channel.device.count(),Integer.valueOf(channel.results.size())))errors.add("方向 "+String.valueOf(channel.device.direction())+" 配置 "+String.valueOf(channel.device.count())+" 张，实际 "+channel.results.size()+" 张");}
        for(Map.Entry<Long,Integer> e:counts.entrySet())if(e.getKey()<40&&e.getValue()>0&&e.getValue()!=4)errors.add("牌 "+e.getKey()+" 应为 4 张，实际 "+e.getValue()+" 张");
        if(expected!=actual&&expected!=0)errors.add("配置合计 "+expected+" 张，实际 "+actual+" 张");return new Validation(errors,expected,actual);
    }
    public static List<Map<String,Object>> uploadPayload(List<Models.Channel> channels){List<Map<String,Object>> out=new ArrayList<>();for(Models.Channel c:channels)for(Models.Tile tile:c.results){Number serial=parseNumber(c.device.serial()==null?"0":c.device.serial());out.add(ApiContract.map("mahjong_number",tile.sequence,"serial_number",serial,"direction",c.device.direction(),"result",parseInt(tile.result)));}return out;}
    public static long parseInt(String input){String s=input.trim();boolean negative=s.startsWith("-");String digits=(negative||s.startsWith("+"))?s.substring(1):s;if(digits.startsWith("0x")||digits.startsWith("0X")){long n=Long.parseLong(digits.substring(2),16);return negative?-n:n;}return Long.parseLong(s);}
    public static Number parseNumber(String input){try{return Long.valueOf(parseInt(input));}catch(NumberFormatException e){return Double.valueOf(input.trim());}}
    public static void deleteMain(Models.Channel channel,int sequence){Iterator<Models.Tile> it=channel.results.iterator();while(it.hasNext()){Models.Tile t=it.next();if(t.sequence==sequence)it.remove();else if(t.sequence>sequence)t.sequence--;}channel.removedOffset++;}
    public static void deleteLeft(Models.Channel channel,int sequence){Iterator<Models.Tile> it=channel.results.iterator();while(it.hasNext())if(it.next().sequence==sequence)it.remove();}
    public static void selectMain(Models.Tile tile,Map<String,Object> config){tile.result=DartConversions.messageContentString(Objects.requireNonNull(config.get("id"),"MjConfig.id"));tile.resultImg=Models.string(config.get("url"));}
    /** Main State closures 4aa71c / 4a375c / 4a383c; pageMode 0 is observable. */
    public static void openChangePage(SessionState session){session.mainView.pageMode=2;}
    public static void closeChangePage(SessionState session){session.mainView.pageMode=session.mainView.pageMode==1?0:1;}
    public static void toggleDisplayType(SessionState session){session.mainView.displayType=session.mainView.displayType==2?1:2;}
    public static void openPalette(SessionState session){session.mainView.paletteVisible=true;}
    public static void closePalette(SessionState session){session.mainView.paletteVisible=false;}
    public static void selectResultForEdit(SessionState session,Models.Tile tile){session.mainView.selectedResult=tile;session.mainView.paletteVisible=true;}
    /** 4a6c04 clears selection before Navigator.pop; caller performs the pop. */
    public static void cancelResultSelection(SessionState session){session.mainView.selectedResult=null;}
    /** 4a33cc guards null before 4a344c; selection leaves the selected object retained, even when its palette is hidden. */
    public static void selectMain(SessionState session,Map<String,Object> config){if(session.mainView.selectedResult==null)return;selectMain(session.mainView.selectedResult,config);if(session.mainView.displayType==2)session.mainView.paletteVisible=false;}
    public static void selectLeft(Models.Channel channel,Models.Tile tile,Map<String,Object> config,int sequence){if(tile==null){tile=new Models.Tile(sequence);tile.uploadImg=Models.string(config.get("url"));channel.results.add(tile);}tile.result=String.valueOf(config.get("number"));tile.resultImg=Models.string(config.get("url"));}
    /** Called only on observed business-accepted upload; clears current live channel state. */
    public static void afterUploadAccepted(SessionState session){for(Models.Channel c:session.channels){session.mainView.pageMode=1;c.results=new ArrayList<>();if(session.mainView.displayType==2&&session.mainView.paletteVisible)session.mainView.paletteVisible=false;}}
}
