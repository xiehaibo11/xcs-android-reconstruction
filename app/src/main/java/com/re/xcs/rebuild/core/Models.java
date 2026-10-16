package com.re.xcs.rebuild.core;

import java.util.*;

/** Bounded model-field reconstruction. Unknown conversions remain explicit. */
public final class Models {
    private Models() {}
    private static final Map<String,LinkedHashMap<String,String>> SCHEMAS=new LinkedHashMap<>();
    static {
        add("AppUpdate","type","int?");
        add("AppUpdate","version","String?");
        add("AppUpdate","update_url","String?");
        add("AppUpdate","ota_url","String?");
        add("ConfigNumber","east","int?");
        add("ConfigNumber","south","int?");
        add("ConfigNumber","west","int?");
        add("ConfigNumber","north","int?");
        add("DataConfig","data_send","int?");
        add("DataConfig","timeout","int?");
        add("DataConfig","delay","int?");
        add("DataConfig","count_type","int?");
        add("DataConfig","upload_img_clarity","int?");
        add("Devices","id","int?");
        add("Devices","user_id","int?");
        add("Devices","create_time","String");
        add("Devices","server_id","int?");
        add("Devices","agent_id","int?");
        add("Devices","working_time","int?");
        add("Devices","lighting_switch","int?");
        add("Devices","remarks","String?");
        add("Devices","first_time","dynamic");
        add("Devices","last_ip","dynamic");
        add("Devices","last_time","dynamic");
        add("Devices","create_id","int?");
        add("Devices","version","dynamic");
        add("Devices","status","int?");
        add("Devices","direction","int?");
        add("Devices","top","double?");
        add("Devices","left","double?");
        add("Devices","right","double?");
        add("Devices","bottom","double?");
        add("Devices","mj_count","int?");
        add("Devices","serial_no","String?");
        add("Devices","online","int?");
        add("Devices","ip","String?");
        add("Devices","motor","int?");
        add("Devices","delay","double?");
        add("Devices","cap_brightness","int?");
        add("Devices","cap_exposure","int?");
        add("Devices","cap_hue","int?");
        add("Devices","cap_saturation","int?");
        add("Devices","cap_contrast","int?");
        add("Devices","cap_gain","int?");
        add("Devices","img_rotation","int?");
        add("Devices","img_min_hreshold","int?");
        add("Devices","cap_fps","int?");
        add("Devices","client_wifi","String?");
        add("Devices","client_ip","String?");
        add("Devices","up_time","String?");
        add("Devices","run_time","String?");
        add("Devices","beta","int?");
        add("Devices","img_add_num","int?");
        add("Devices","gk_min","int?");
        add("Devices","gk_max","int?");
        add("LightingConfig","switch","bool?");
        add("LightingConfig","east","bool?");
        add("LightingConfig","south","bool?");
        add("LightingConfig","west","bool?");
        add("LightingConfig","north","bool?");
        add("MessageUpImg","serial_number","String?");
        add("MessageUpImg","mahjong_number","int?");
        add("MessageUpImg","img","String?");
        add("MessageUpImg","ai_val","int?");
        add("MessageUpImg","ai_precision","double?");
        add("Message","msg_type","int?");
        add("Message","msg_content","dynamic");
        add("MjConfig","id","dynamic");
        add("MjConfig","number","dynamic");
        add("MjConfig","name","dynamic");
        add("MjConfig","url","dynamic");
        add("OnlineConfig","config_number","Map<String, dynamic>");
        add("OnlineConfig","lighting_config","Map<String, dynamic>");
        add("OnlineConfig","wifi_config","Map<String, dynamic>");
        add("OnlineConfig","data_config","Map<String, dynamic>");
        add("User","id","int?");
        add("User","username","String?");
        add("User","token","String?");
        add("User","login_type","int?");
        add("User","exp","int?");
        add("User","nbf","int?");
        add("User","data_send","int?");
        add("User","timeout","int?");
        add("User","delay","int?");
        add("ViewSetting","orientationMjHeight","dynamic");
        add("ViewSetting","orientationMjWidth","dynamic");
        add("ViewSetting","validMjWidth","dynamic");
        add("ViewSetting","validMjHeight","dynamic");
        add("ViewSetting","editMjWidth","dynamic");
        add("ViewSetting","editMjHeight","dynamic");
        add("ViewSetting","orientationAiVis","dynamic");
        add("ViewSetting","orientationHeight","dynamic");
        add("WifiConfig","ssid","String?");
        add("WifiConfig","pwd","String?");
    }
    private static void add(String model,String key,String type){LinkedHashMap<String,String> schema=SCHEMAS.get(model);if(schema==null){schema=new LinkedHashMap<>();SCHEMAS.put(model,schema);}schema.put(key,type);}
    public static boolean isInteger(Object value){return DartIntegers.isInteger(value);}
    public static String string(Object value){if(!(value instanceof String))throw new IllegalArgumentException("Expected non-null String");return (String)value;}
    public static String nullableString(Object value){return value==null?null:string(value);}
    public static Long integer(Object value){if(value==null)return null;if(!isInteger(value))throw new IllegalArgumentException("Expected int?");return ((Number)value).longValue();}
    public static int intOr(Object value,int fallback){Long n=integer(value);if(n==null)return fallback;if(n<Integer.MIN_VALUE||n>Integer.MAX_VALUE)throw new IllegalArgumentException("Outside host int range");return n.intValue();}
    public static Double nullableDouble(Object value){if(value==null)return null;if(!(value instanceof Double))throw new IllegalArgumentException("Expected double? without int coercion");return (Double)value;}
    public static Map<String,String> schema(String name){Map<String,String> s=SCHEMAS.get(name);if(s==null)throw new UnsupportedOperationException("No recovered JSON converter: "+name);return Collections.unmodifiableMap(s);}
    public static Record read(String name,Map<String,Object> source){
        if(name.equals("ViewSetting")){for(String key:schema(name).keySet())source.get(key);return new Record(name,viewDefaults(),Collections.<String>emptyList());}
        Map<String,Object> fields=new LinkedHashMap<>();List<String> limits=new ArrayList<>();
        for(Map.Entry<String,String> e:schema(name).entrySet()){
            Object value=source.get(e.getKey());String t=e.getValue();boolean nullable=t.endsWith("?")||t.equals("dynamic");
            if(value==null&&!nullable)throw new IllegalArgumentException(name+"."+e.getKey()+" must be "+t);
            if(value!=null){
                if(t.startsWith("String"))string(value);
                else if(t.startsWith("int"))integer(value);
                else if(t.startsWith("double"))nullableDouble(value);
                else if(t.startsWith("bool")&&!(value instanceof Boolean))throw new IllegalArgumentException(name+"."+e.getKey()+" must be bool?");
                else if(t.startsWith("Map"))JsonCodec.object(value);
            }
            // Original Devices.fromJson parses create_time at 0x490328, before
            // the version selector at 0x490620 and subsequent field checks.
            if(name.equals("Devices")&&e.getKey().equals("create_time"))value=DartDateTime.parse((String)value);
            if(name.equals("Devices")&&e.getKey().equals("version"))value=DartConversions.toDouble(value);
            fields.put(e.getKey(),value);
        }
        if(name.equals("Message"))try{DartConversions.messageContentString(fields.get("msg_content"));}catch(UnsupportedOperationException e){limits.add(e.getMessage());}
        if(name.equals("MjConfig"))limits.add("Only serializer fields recovered; this reader is a reconstruction adapter, not recovered original factory");
        if(name.equals("OnlineConfig")){fields.put("config_number",read("ConfigNumber",JsonCodec.object(fields.get("config_number"))).values);fields.put("lighting_config",read("LightingConfig",JsonCodec.object(fields.get("lighting_config"))).values);fields.put("wifi_config",read("WifiConfig",JsonCodec.object(fields.get("wifi_config"))).values);fields.put("data_config",read("DataConfig",JsonCodec.object(fields.get("data_config"))).values);}
        return new Record(name,fields,limits);
    }
    public static final class Record {
        public final String model; public final Map<String,Object> values;public final List<String> unresolved;
        private Record(String model,Map<String,Object> fields,List<String> limits){this.model=model;values=Collections.unmodifiableMap(new LinkedHashMap<>(fields));unresolved=Collections.unmodifiableList(new ArrayList<>(limits));}
        public Object get(String key){return values.get(key);}
        public String text(String key){return nullableString(get(key));}
        public Long number(String key){return integer(get(key));}
        /** Only emits known complete converter semantics. Raw maps are available via values. */
        public Map<String,Object> toJson(){if(!unresolved.isEmpty())throw new UnsupportedOperationException(model+": "+unresolved);Map<String,Object> result=new LinkedHashMap<>(values);if(model.equals("Devices"))result.put("create_time",((DartDateTime)values.get("create_time")).toIso8601String());if(model.equals("Message"))result.put("msg_content",DartConversions.messageContentString(values.get("msg_content")));return result;}
    }
    public static Map<String,Object> viewDefaults(){return ApiContract.map("orientationMjHeight",3.0,"orientationMjWidth",1.9,"orientationHeight",640.0,"validMjWidth",34.0,"validMjHeight",70.0,"editMjWidth",60.0,"editMjHeight",64.0,"orientationAiVis",true);}
    public static final class Device {
        public final Map<String,Object> fields;
        public Device(Map<String,Object> source){fields=new LinkedHashMap<>(source);}
        public String serial(){return nullableString(fields.get("serial_no"));}
        public Integer direction(){Long n=integer(fields.get("direction"));return n==null?null:Math.toIntExact(n);}
        public Long id(){return integer(fields.get("id"));}
        public Integer count(){Long n=integer(fields.get("mj_count"));return n==null?null:Math.toIntExact(n);}
        public int expected(){Integer n=count();return n==null?0:n;}
        public boolean open(){return Long.valueOf(1).equals(integer(fields.get("lighting_switch")));}
        public void lighting(int value){fields.put("lighting_switch",value);}
        public void online(int value){fields.put("online",value);}
    }
    public static final class Tile {
        public String result="",resultImg="images/other/empty.jpg",uploadImg="images/other/empty.jpg";
        public double confidence;public int sequence;public boolean selected,warning;
        public Tile(int sequence){this.sequence=sequence;}
    }
    public static final class Channel {
        public final Device device;public List<Tile> results=new ArrayList<>();public int removedOffset;
        public Channel(Device device){this.device=device;}
    }
}
