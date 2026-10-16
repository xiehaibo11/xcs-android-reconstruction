package com.re.xcs.rebuild.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** Real private-file persistence. Source behavior stores remembered password as plaintext. */
public final class LocalConfig {
    private LocalConfig() {}
    public static Map<String,Object> readLogin(File filesDir)throws IOException{File file=new File(filesDir,"app_config.conf");if(!file.exists())return null;Map<String,Object> m=JsonCodec.object(JsonCodec.parse(read(file)));Models.string(m.get("ip"));Models.string(m.get("username"));Models.string(m.get("password"));if(!(m.get("rememberPassword") instanceof Boolean))throw new IllegalArgumentException("rememberPassword must be bool");return m;}
    public static void writeLogin(File filesDir,String ip,String user,String password,boolean remember)throws IOException{write(new File(filesDir,"app_config.conf"),JsonCodec.stringify(ApiContract.map("ip",ip,"username",user,"password",remember?password:"","rememberPassword",remember)));}
    public static void writeView(File filesDir,Map<String,Object> current)throws IOException{write(new File(filesDir,"view_setting.conf"),JsonCodec.stringify(current));}
    public static Map<String,Object> readView(File filesDir)throws IOException{File file=new File(filesDir,"view_setting.conf");return !file.exists()?Models.viewDefaults():Models.read("ViewSetting",JsonCodec.object(JsonCodec.parse(read(file)))).toJson();}
    public static void writeLocalPhrase(File filesDir,String phrase)throws IOException{if(phrase==null||phrase.isEmpty()||phrase.equals("6666"))throw new IllegalArgumentException("口令不能为空或等于6666");try{byte[] hash=MessageDigest.getInstance("MD5").digest(phrase.getBytes(StandardCharsets.UTF_8));StringBuilder hex=new StringBuilder();for(byte b:hash)hex.append(String.format(Locale.ROOT,"%02x",b&255));write(new File(filesDir,"inlet_pwd.conf"),hex.toString());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
    public static String read(File file)throws IOException{try(InputStream in=new FileInputStream(file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] buffer=new byte[8192];int n;while((n=in.read(buffer))!=-1)out.write(buffer,0,n);return new String(out.toByteArray(),StandardCharsets.UTF_8);}}
    private static void write(File file,String value)throws IOException{try(OutputStream out=new FileOutputStream(file)){out.write(value.getBytes(StandardCharsets.UTF_8));}}
}
