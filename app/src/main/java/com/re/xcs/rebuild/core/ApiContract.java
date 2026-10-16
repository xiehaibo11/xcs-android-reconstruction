package com.re.xcs.rebuild.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** 22 client-side HTTP templates from AOT. Does not assert server requirements. */
public final class ApiContract {
    private ApiContract() {}
    public interface Transport { Response execute(Request request) throws IOException; }
    public static final class Request {
        public final String method,path; public final Map<String,Object> query; public final Object body;
        public Request(String method,String path,Map<String,Object> query,Object body){this.method=method;this.path=path;this.query=Collections.unmodifiableMap(new LinkedHashMap<>(query));this.body=body;}
    }
    public static final class Response {
        public final int status;public final Object data;
        public Response(int status,Object data){this.status=status;this.data=data;}
        public boolean ok(){return status>=200&&status<=299;}
        public Map<String,Object> object(){return JsonCodec.object(data);}
    }
    public static Map<String,Object> map(Object... pairs){if((pairs.length&1)!=0)throw new IllegalArgumentException("Odd key/value count");Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)m.put((String)pairs[i],pairs[i+1]);return m;}
    public static Request get(String path){return new Request("GET",path,Collections.<String,Object>emptyMap(),null);}
    public static Request post(String path,Object body){return new Request("POST",path,Collections.<String,Object>emptyMap(),body);}
    public static Request login(String username,String password){return new Request("POST","/api/login/login/distinguish",map("app_name","xcs"),map("username",username,"password",password,"devicetype",1));}
    public static Request serverAddress(String publicPem){return post("/api/server/get_server_addr",map("client_type",1,"key",Base64.getEncoder().encodeToString(publicPem.getBytes(StandardCharsets.UTF_8))));}
    public static Request wifi(String ssid,String pwd){return post("/api/config/set_wifi",map("ssid",ssid,"pwd",pwd));}
    public static Request dataConfig(int send,int timeout,int delay,int countType,int clarity){return post("/api/config/set_data_config",map("data_send",send,"timeout",timeout,"delay",delay,"count_type",countType,"upload_img_clarity",clarity));}
    public static Request numberConfig(int east,int south,int west,int north){return post("/api/config/set_number",map("east",east,"south",south,"west",west,"north",north));}
    public static Request defaultWifi(){return post("/api/config/get_default_wifi",null);}
    public static Request wifiDeviceUp(){return get("/api/config/wifi_device_up");}
    public static Request wifiList(){return get("/api/config/get_device_wifi_list");}
    public static Request mjConfig(){return get("/api/mj/get_config");}
    public static Request config(){return get("/api/config/get_config");}
    public static Request startPreview(Number deviceId){return get("/api/preview/start_preview/"+String.valueOf(deviceId));}
    public static Request endPreview(Number deviceId){return post("/api/preview/end_preview/"+String.valueOf(deviceId),null);}
    public static Request previewImageType(Number deviceId,Integer type){return post("/api/preview/set_preview_img_type/"+String.valueOf(deviceId)+"/"+(type==null?1:type),null);}
    public static Request previewParams(Number id,Map<String,Object> input){
        String[] keys={"left","top","right","bottom","brightness","motor","cap_brightness","cap_exposure","cap_hue","cap_saturation","cap_contrast","cap_gain","img_rotation","img_min_hreshold","cap_fps","bate","img_add_num","gk_min","gk_max"};
        Map<String,Object> out=new LinkedHashMap<>();for(String key:keys){Object v=input.get(key);if(!(v instanceof Number))throw new IllegalArgumentException("Missing numeric preview parameter "+key);
            Number n=(Number)v;if(!Double.isFinite(n.doubleValue()))throw new IllegalArgumentException("Non-finite "+key);
            if(key.equals("brightness"))out.put(key,n.doubleValue());else if(Arrays.asList("left","top","right","bottom","motor").contains(key))out.put(key,(long)n.doubleValue());else{if(!Models.isInteger(v))throw new IllegalArgumentException("Expected int "+key);out.put(key,v);}}
        return post("/api/preview/set_params_v2/"+String.valueOf(id),out);
    }
    public static Request addResults(List<Map<String,Object>> body){return post("/api/zhuo/add",body);}
    public static Request resetGames(){return get("/api/zhuo/zhuo_reset_games");}
    public static Request endGames(){return get("/api/zhuo/end_games");}
    public static Request startGames(){return get("/api/zhuo/start_games");}
    public static Request restartDevice(){return get("/api/zhuo/restart_device");}
    public static Request deviceStatus(){return get("/api/zhuo/device_status_all");}
    public static Request checkUpdate(String version){return new Request("GET","/api/app/check_update",map("type",1,"version",version,"app_name","xcs"),null);}
    public static Request editPassword(String oldPassword,String password){return post("/account/edit/pwd",map("old_password",oldPassword,"password",password));}
    public static String imageUrl(String image,String businessHost){return image.startsWith("http://")||image.startsWith("https://")?image:"http://"+businessHost+"/"+image;}
    public static String decodeData(String input,String rules){for(String rule:rules.split("\\|",-1)){String[] pair=rule.split(",",-1);if(pair.length<2)throw new IllegalArgumentException("Invalid substitution rule: missing comma");input=input.replace(pair[1],pair[0]);}return input;}
    public static boolean businessAccepted(Response response){return response.ok()&&!Boolean.FALSE.equals(response.object().get("success"));}
    public static List<String> passwordValidation(String oldPassword,String password,String confirmation){List<String> errors=new ArrayList<>();if(oldPassword==null||oldPassword.length()<6)errors.add("原密码至少6个字符");if(password==null||password.isEmpty())errors.add("新密码不能为空");if(confirmation==null||confirmation.isEmpty())errors.add("确认密码不能为空");else if(!confirmation.equals(password))errors.add("两次密码不一致");return errors;}
}
