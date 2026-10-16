package com.re.xcs.rebuild.core;

import java.io.*;
import java.util.Base64;
import java.util.concurrent.Executor;

/** Actual GET -> ordered substitution -> Base64 -> cache file pipeline. */
public final class CachedImageLoader implements MessageEngine.ImageLoader {
    private final ApiContract.Transport transport;private final File directory;private final Executor executor;
    public CachedImageLoader(ApiContract.Transport transport,File directory,Executor executor){this.transport=transport;this.directory=directory;this.executor=executor;}
    @Override public void fetchAndCache(final String url,final String rules,final MessageEngine.ImageResult callback){executor.execute(new Runnable(){public void run(){try{
        ApiContract.Response response=transport.execute(ApiContract.get(url));
        // Original 529164 does not test response.ok before its String cast.
        String encoded=Models.string(response.data);byte[] bytes=Base64.getDecoder().decode(ApiContract.decodeData(encoded,rules));
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("Cannot create image cache");File file=File.createTempFile("recognized_",".png",directory);
        try(OutputStream out=new FileOutputStream(file)){out.write(bytes);}callback.success(file.getAbsolutePath());
    }catch(Exception e){callback.failure(e);}}});}
}
