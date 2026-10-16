package com.re.xcs.rebuild.net;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;

/** New transport implementation, RFC6455 sections 4–5. Not recovered Rust.
 * Original application uses ws://host:18889. TLS/extensions/binary messages are
 * deliberately unsupported here and fail explicitly, never fake a connection.
 */
public final class WsWire implements Closeable {
    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final SecureRandom random = new SecureRandom();
    private volatile boolean closing;
    private static final int LIMIT=16*1024*1024;

    public WsWire(URI uri) throws Exception {
        if (!"ws".equals(uri.getScheme())) throw new IOException("Only recovered ws:// transport is implemented");
        socket=new Socket();
        try {
            socket.connect(new InetSocketAddress(uri.getHost(),uri.getPort()<0?80:uri.getPort()),10000);
            socket.setSoTimeout(15000);
            in=new BufferedInputStream(socket.getInputStream()); out=socket.getOutputStream();
            byte[] nonce=new byte[16]; random.nextBytes(nonce);
            String key=Base64.getEncoder().encodeToString(nonce);
            String path=uri.getRawPath(); if(path==null||path.isEmpty()) path="/";
            if(uri.getRawQuery()!=null) path+="?"+uri.getRawQuery();
            String host=uri.getHost()+(uri.getPort()<0?"":":"+uri.getPort());
            out.write(("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "+key+"\r\nSec-WebSocket-Version: 13\r\n\r\n").getBytes(StandardCharsets.US_ASCII)); out.flush();
            String status=line();
            if(!status.matches("HTTP/1\\.[01] 101(?: .*|)")) throw new IOException("WebSocket upgrade rejected: "+status);
            Map<String,String> headers=new HashMap<>(); int size=status.length();
            for(String line=line();!line.isEmpty();line=line()) {
                size+=line.length(); if(size>32768) throw new IOException("Upgrade headers too long");
                int colon=line.indexOf(':'); if(colon<1) throw new IOException("Malformed header");
                headers.put(line.substring(0,colon).trim().toLowerCase(Locale.ROOT),line.substring(colon+1).trim());
            }
            String accept=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
            if(!accept.equals(headers.get("sec-websocket-accept"))||!"websocket".equalsIgnoreCase(headers.get("upgrade"))||!tokens(headers.get("connection")).contains("upgrade")) throw new IOException("Invalid WebSocket handshake");
            if(headers.containsKey("sec-websocket-extensions")||headers.containsKey("sec-websocket-protocol")) throw new IOException("Unrequested WebSocket negotiation");
            socket.setSoTimeout(0);
        } catch(Exception e){try{socket.close();}catch(IOException closeError){e.addSuppressed(closeError);}throw e;}
    }
    private static Set<String> tokens(String s){return new HashSet<>(Arrays.asList((s==null?"":s.toLowerCase(Locale.ROOT)).split("\\s*,\\s*")));}
    private String line() throws IOException {
        ByteArrayOutputStream b=new ByteArrayOutputStream(); int previous=-1;
        while(true){int c=in.read();if(c<0)throw new EOFException(); if(previous==13&&c==10){byte[] a=b.toByteArray();return new String(a,0,a.length-1,StandardCharsets.US_ASCII);} b.write(c);previous=c;if(b.size()>8192)throw new IOException("Header line too long");}
    }
    private int one() throws IOException {int b=in.read();if(b<0)throw new EOFException();return b;}
    public String receiveText() throws IOException {
        ByteArrayOutputStream message=null;
        while(true){
            int a=one(),b=one(),op=a&15; boolean fin=(a&128)!=0;
            if((a&112)!=0||(b&128)!=0) throw new IOException("Invalid server RSV/masking");
            long n=b&127;
            if(n==126){n=(one()<<8)|one();if(n<126)throw new IOException("Nonminimal length");}
            else if(n==127){n=0;for(int i=0;i<8;i++){int v=one();if(i==0&&(v&128)!=0)throw new IOException("Invalid length");n=(n<<8)|v;}if(n<65536)throw new IOException("Nonminimal length");}
            if(n>LIMIT||(op>=8&&(!fin||n>125)))throw new IOException("Invalid frame size");
            byte[] data=new byte[(int)n];for(int p=0;p<data.length;){int k=in.read(data,p,data.length-p);if(k<0)throw new EOFException();p+=k;}
            if(op==8){if(n==1)throw new IOException("Invalid close payload");if(n>=2){int code=((data[0]&255)<<8)|(data[1]&255);if(code<1000||code>=5000||code==1004||code==1005||code==1006||code==1015||code>=1016&&code<3000)throw new IOException("Invalid close status code");}if(n>2)utf8(Arrays.copyOfRange(data,2,data.length));if(!closing)frame(8,data);close();return null;}
            if(op==9){frame(10,data);continue;} if(op==10)continue;
            if(op==2)throw new IOException("Binary messages unsupported by reconstruction");
            if(op==1){if(message!=null)throw new IOException("Interleaved fragmented message");message=new ByteArrayOutputStream();}
            else if(op!=0||message==null)throw new IOException("Invalid continuation/opcode");
            if(message.size()+n>LIMIT)throw new IOException("Message too large");message.write(data);
            if(fin)return utf8(message.toByteArray());
        }
    }
    private static String utf8(byte[] b) throws IOException {try{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();}catch(CharacterCodingException e){throw new IOException("Invalid UTF-8",e);}}
    public void sendText(String text) throws IOException {frame(1,text.getBytes(StandardCharsets.UTF_8));}
    private synchronized void frame(int opcode,byte[] bytes)throws IOException{
        if(closing)throw new IOException("WebSocket closed");
        if(bytes.length>LIMIT)throw new IOException("Frame too large");
        out.write(128|opcode);int n=bytes.length;
        if(n<126)out.write(128|n);else if(n<65536){out.write(128|126);out.write(n>>>8);out.write(n);}else{out.write(128|127);for(int i=7;i>=0;i--)out.write((int)(((long)n) >>>(8*i)));}
        byte[] mask=new byte[4];random.nextBytes(mask);out.write(mask);
        byte[] encoded=bytes.clone();for(int i=0;i<n;i++)encoded[i]^=mask[i%4];out.write(encoded);out.flush();
    }
    // Socket.close must be able to interrupt a writer blocked while holding frame's lock.
    public void close()throws IOException{closing=true;socket.close();}
}
