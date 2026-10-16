package com.re.xcs.rebuild.core;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Real HTTP transport. Invoked by UI only after explicit login/send action. */
public final class JsonHttpTransport implements ApiContract.Transport {
    private final SessionState session;private final String clientVersion;
    private final CookieManager cookies=new CookieManager(null,CookiePolicy.ACCEPT_ALL);
    public int connectTimeoutMs=15000,readTimeoutMs=20000;
    public JsonHttpTransport(SessionState session,String constructedClientVersion){this.session=session;this.clientVersion=constructedClientVersion;}
    @Override public ApiContract.Response execute(ApiContract.Request request)throws IOException{
        String path=request.path;
        if(!request.query.isEmpty()){StringBuilder b=new StringBuilder(path);b.append(path.contains("?")?'&':'?');boolean first=true;for(Map.Entry<String,Object> e:request.query.entrySet()){if(!first)b.append('&');first=false;b.append(URLEncoder.encode(e.getKey(),"UTF-8")).append('=').append(URLEncoder.encode(String.valueOf(e.getValue()),"UTF-8"));}path=b.toString();}
        URL url=path.startsWith("http://")||path.startsWith("https://")?new URL(path):new URL(new URL(session.baseUri),path);
        HttpURLConnection c=(HttpURLConnection)url.openConnection();
        try{
            c.setConnectTimeout(connectTimeoutMs);c.setReadTimeout(readTimeoutMs);c.setRequestMethod(request.method);
            for(Map.Entry<String,String> e:session.requestHeaders(clientVersion).entrySet())c.setRequestProperty(e.getKey(),e.getValue());
            URI uri;try{uri=url.toURI();}catch(URISyntaxException e){throw new IOException(e);}
            for(Map.Entry<String,List<String>> e:cookies.get(uri,Collections.<String,List<String>>emptyMap()).entrySet())for(String v:e.getValue())c.addRequestProperty(e.getKey(),v);
            if(request.method.equals("POST")){c.setDoOutput(true);byte[] bytes=request.body==null?new byte[0]:(request.body instanceof String?(String)request.body:JsonCodec.stringify(request.body)).getBytes(StandardCharsets.UTF_8);c.setFixedLengthStreamingMode(bytes.length);try(OutputStream out=c.getOutputStream()){out.write(bytes);}}
            int status=c.getResponseCode();cookies.put(uri,c.getHeaderFields());InputStream stream=status>=400?c.getErrorStream():c.getInputStream();String text=stream==null?"":read(stream);
            String type=c.getContentType();Object body=text;if(type!=null&&(type.toLowerCase(Locale.ROOT).contains("application/json")||type.toLowerCase(Locale.ROOT).contains("+json"))&&!text.isEmpty())body=JsonCodec.parse(text);
            ApiContract.Response response=new ApiContract.Response(status,body);session.onHttpError(response);return response;
        }finally{c.disconnect();}
    }
    private static String read(InputStream in)throws IOException{try(InputStream input=in;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] b=new byte[8192];int n;while((n=input.read(b))!=-1)out.write(b,0,n);return new String(out.toByteArray(),StandardCharsets.UTF_8);}}
}
