package com.re.xcs.rebuild.core;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.Cipher;

/** Real two-stage HTTP login and RSA configuration decrypt, reconstructed from AOT. */
public final class LoginFlow {
    private final SessionState session;private final ApiContract.Transport transport;
    public LoginFlow(SessionState session,ApiContract.Transport transport){this.session=session;this.transport=transport;}
    public static final class Failure extends IOException {public final String stage;public Failure(String stage,String reason){super(reason);this.stage=stage;}}
    public static final class Result {
        public final ApiContract.Response updateCheck;public final List<String> unresolved;
        Result(ApiContract.Response update,List<String> limits){updateCheck=update;unresolved=Collections.unmodifiableList(limits);}
    }
    /** Blocking. UI must call on a worker. No implicit socket authentication or success fabrication. */
    public Result login(String entryIp,String username,String password,String publicPem,String privatePem,String version)throws IOException,GeneralSecurityException{
        session.baseUri="http://"+entryIp+":8081/";
        ApiContract.Response response=transport.execute(ApiContract.login(username,password));
        if(!response.ok())throw new Failure("login","HTTP "+response.status);
        Map<String,Object> body=response.object();
        if(Boolean.FALSE.equals(body.get("success")))throw new Failure("login",Models.string(body.get("msg")));
        session.jwt=Models.string(body.get("jwt"));
        session.user=new LinkedHashMap<>(Models.read("User",JsonCodec.object(body.get("loginUser"))).values);
        List<Models.Channel> channels=new ArrayList<>();List<String> limits=new ArrayList<>();
        for(Object raw:JsonCodec.array(body.get("devices"))){Models.Record record=Models.read("Devices",JsonCodec.object(raw));channels.add(new Models.Channel(new Models.Device(record.values)));for(String limit:record.unresolved)if(!limits.contains(limit))limits.add(limit);}
        session.channels.clear();session.channels.addAll(channels);session.username=username;session.password=password;
        ApiContract.Response config=transport.execute(ApiContract.serverAddress(publicPem));
        if(!config.ok())throw new Failure("server_config","HTTP "+config.status);
        Map<String,Object> configBody=config.object();
        if(!Boolean.TRUE.equals(configBody.get("success")))throw new Failure("server_config",String.valueOf(configBody.get("msg")));
        List<Object> plain=JsonCodec.array(JsonCodec.parse(decryptServerConfig(Models.string(configBody.get("msg")),privatePem)));
        if(plain.size()<2)throw new Failure("server_config","Decrypted configuration requires host and substitution rules");
        session.businessHost=Models.string(plain.get(0));session.imageRules=Models.string(plain.get(1));session.baseUri="http://"+session.businessHost+":8081/";
        Collections.sort(session.channels,new Comparator<Models.Channel>(){public int compare(Models.Channel a,Models.Channel b){return Objects.requireNonNull(a.device.direction(),"device.direction").compareTo(Objects.requireNonNull(b.device.direction(),"device.direction"));}});
        return new Result(transport.execute(ApiContract.checkUpdate(version)),limits);
    }
    public static String decryptServerConfig(String base64,String privatePem)throws GeneralSecurityException{
        byte[] ciphertext=Base64.getDecoder().decode(base64);PrivateKey key=parsePrivateKey(privatePem);
        Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");cipher.init(Cipher.DECRYPT_MODE,key);
        // UTF-8 decoder replacement matches allowMalformed:true for ordinary malformed inputs.
        return new String(cipher.doFinal(ciphertext),StandardCharsets.UTF_8);
    }
    public static PrivateKey parsePrivateKey(String pem)throws GeneralSecurityException{
        String data=pem.replaceAll("-----[A-Z ]+-----","").replaceAll("\\s","");
        final byte[] der;try{der=Base64.getDecoder().decode(data);}catch(IllegalArgumentException e){throw new InvalidKeySpecException("Invalid PEM Base64",e);}
        KeyFactory f=KeyFactory.getInstance("RSA");if(pem.contains("BEGIN PRIVATE KEY"))return f.generatePrivate(new PKCS8EncodedKeySpec(der));
        if(!pem.contains("BEGIN RSA PRIVATE KEY"))throw new InvalidKeySpecException("Unsupported PEM key kind");
        try{Der d=new Der(der);Der seq=new Der(d.value(0x30));if(d.at!=der.length)throw new IllegalArgumentException("Trailing DER");BigInteger version=seq.integer();if(!version.equals(BigInteger.ZERO))throw new IllegalArgumentException("Multi-prime key unsupported");
            RSAPrivateCrtKeySpec spec=new RSAPrivateCrtKeySpec(seq.integer(),seq.integer(),seq.integer(),seq.integer(),seq.integer(),seq.integer(),seq.integer(),seq.integer());if(seq.at!=seq.data.length)throw new IllegalArgumentException("Trailing key fields");return f.generatePrivate(spec);
        }catch(IllegalArgumentException e){throw new InvalidKeySpecException("Invalid PKCS#1 key",e);}
    }
    private static final class Der {final byte[] data;int at;Der(byte[] data){this.data=data;}int next(){if(at>=data.length)throw new IllegalArgumentException("Truncated DER");return data[at++]&255;}byte[] value(int tag){if(next()!=tag)throw new IllegalArgumentException("Unexpected DER tag");int n=next();if((n&128)!=0){int count=n&127;if(count==0||count>4)throw new IllegalArgumentException("Invalid DER length");n=0;for(int i=0;i<count;i++)n=(n<<8)|next();}if(n<0||n>data.length-at)throw new IllegalArgumentException("Truncated DER value");byte[] out=Arrays.copyOfRange(data,at,at+n);at+=n;return out;}BigInteger integer(){return new BigInteger(value(2));}}
}
