package ca.awoo.websoc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import ca.awoo.fwoabl.Base64;
import ca.awoo.fwoabl.function.Consumer;
import ca.awoo.fwoabl.function.Function;
import ca.awoo.praser.Context;
import ca.awoo.praser.ParseException;
import ca.awoo.praser.Parser;

import static ca.awoo.praser.Combinators.*;
import static ca.awoo.praser.Text.*;

public class WebSocket extends Socket {

    private final Socket socket;
    private final URI uri;

    private static class Connection{
        public final Socket socket;
        public final URI uri;

        public Connection(Socket socket, URI uri){
            this.socket = socket;
            this.uri = uri;
        }
    }

    public WebSocket(URI uri) throws IOException, ParseException, NoSuchAlgorithmException{
        Connection con = connect(uri);
        this.uri = con.uri;
        this.socket = con.socket;
    }

    private Connection connect(URI uri) throws IOException, ParseException, NoSuchAlgorithmException{
        if(uri.getScheme().equals("http")){
            try {
                uri = new URI("ws", uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), uri.getQuery(), uri.getFragment());
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
        if(uri.getScheme().equals("https")){
            try {
                uri = new URI("wss", uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), uri.getQuery(), uri.getFragment());
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
        Socket socket;
        if(uri.getScheme().equals("wss")){
            try {
                int port = uri.getPort();
                if(port == -1){
                    port = 443;
                }
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, null, null);
                SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(uri.getHost(), port);
                sslSocket.startHandshake();
                socket = sslSocket;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else if(uri.getScheme().equals("ws")) {
            try {
                int port = uri.getPort();
                if(port == -1){
                    port = 80;
                }
                socket = new Socket(uri.getHost(), port);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }else{
            throw new IllegalArgumentException("Invalid scheme: " + uri.getScheme());
        }
        Connection connection = new Connection(socket, uri);
        byte[] key = new byte[16];
        for(int i = 0; i < 16; i++){
            //TODO: I don't think Math.random() is on the ietf's list of suitably high-entropy random sources
            key[i] = (byte)(Math.random() * 256);
        }
        String keyString = Base64.getEncoder().encode(key);
        //This magic UUID is defined in the spec
        String responseString = keyString + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(responseString.getBytes("UTF-8"));
        String accept = Base64.getEncoder().encode(sha1);
        sendHandshake(keyString, connection);
        Connection finalConnection = receiveHandshake(accept, connection);
        return finalConnection;
    }

    private void sendHandshake(String key, Connection con) throws IOException{
        PrintStream out = new PrintStream(con.socket.getOutputStream(), true, "UTF-8");
        String path = con.uri.getPath();
        if(path.length() == 0){
            path = "/";
        }
        out.println("GET " + path + " HTTP/1.1");
        out.println("Host: " + con.uri.getHost());
        out.println("Origin: " + "https://" + con.uri.getHost() + "/");//TODO: handle origin better
        out.println("Upgrade: websocket");
        out.println("Connection: Upgrade");
        out.println("Sec-WebSocket-Key: " + key);
        out.println("Sec-WebSocket-Version: 13");
        out.println();
    }

    private static class Header{
        public final String name;
        public final String value;

        public Header(String name, String value){
            this.name = name;
            this.value = value;
        }
    }

    @SuppressWarnings("unchecked")
    private Connection receiveHandshake(String expectedKey, Connection con) throws IOException, ParseException, NoSuchAlgorithmException{
        //Parse http response
        Context<Character> context = contextFromStream(con.socket.getInputStream(), Charset.forName("UTF-8"));
        tag("HTTP/1.1 ").parse(context);
        int code = integer().parse(context);
        String message = stringFold(many(not(one('\r')))).parse(context);
        tag("\r\n").parse(context);
        Parser<Character, String> headerName = stringFold(oneOrMore(or(letter(), oneOf("-"))));
        Parser<Character, Character> printable = oneOf(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
        Parser<Character, String> headerValue = stringFold(oneOrMore(printable));
        Parser<Character, Header> header = map(seq(headerName, tag(": "), headerValue, tag("\r\n")), new Function<List<String>,Header>() {
            public Header invoke(List<String> l) {
                return new Header(l.get(0), l.get(2));
            }
        });
        Parser<Character, List<Header>> headers = many(header);
        List<Header> headerList = headers.parse(context);
        Map<String, String> headerMap = new HashMap<String, String>();
        for(Header h : headerList){
            headerMap.put(h.name.toLowerCase(), h.value);
        }

        if(code >= 300 && code <= 399){
            //Redirect
            String location = headerMap.get("location");
            if(location == null){
                throw new IOException("Redirect without location header");
            }
            URI newUri;
            try {
                newUri = new URI(location);
            } catch (URISyntaxException e) {
                throw new IOException("Invalid redirect location: " + location);
            }
            return connect(newUri);
        }
        if(code != 101){
            throw new IOException("Invalid response code: " + code + " " + message);
        }

        boolean upgrade = "websocket".equalsIgnoreCase(headerMap.get("upgrade"));
        boolean connection = "upgrade".equalsIgnoreCase(headerMap.get("connection"));
        boolean accept = expectedKey.equals(headerMap.get("sec-websocket-accept"));
        if(!upgrade || !connection || !accept){
            throw new IOException("Invalid handshake");
        }
        tag("\r\n").parse(context);
        return con;
    }

    public static class Frame {
        private final boolean fin;
        private final int opcode;
        private final boolean masked;
        private final long length;
        private final byte[] mask;
        private final byte[] data;

        public Frame(boolean fin, int opcode, boolean masked, long length, byte[] mask, byte[] data){
            this.fin = fin;
            this.opcode = opcode;
            this.masked = masked;
            this.length = length;
            this.mask = mask;
            this.data = data;
        }

        public static Frame read(InputStream is) throws IOException{
            int next = is.read();
            boolean fin = (next & 0x80) != 0;
            int opcode = next & 0x0F;
            next = is.read();
            boolean mask = (next & 0x80) != 0;
            int length = next & 0x7F;
            if(length == 126){
                length = is.read() << 8 | is.read();
            }else if(length == 127){
                length = is.read() << 56 | is.read() << 48 | is.read() << 40 | is.read() << 32 | is.read() << 24 | is.read() << 16 | is.read() << 8 | is.read();
            }
            byte[] maskKey = new byte[4];
            if(mask){
                is.read(maskKey);
            }
            byte[] data = new byte[length];
            is.read(data);
            for(int i = 0; i < data.length; i++){
                data[i] ^= maskKey[i % 4];
            }
            return new Frame(fin, opcode, mask, length, maskKey, data);
        }

        public void write(OutputStream os) throws IOException{
            os.write((fin ? 0x80 : 0) | opcode);
            if(length < 126){
                os.write((int) (length & 0x7F) | (masked ? 0x80 : 0));
            }else if(length < 65536){
                os.write(126 | (masked ? 0x80 : 0));
                os.write((int) (length >> 8));
                os.write((int) length);
            }else{
                os.write(127 | (masked ? 0x80 : 0));
                os.write((int)(length >> 56));
                os.write((int)(length >> 48));
                os.write((int)(length >> 40));
                os.write((int)(length >> 32));
                os.write((int)(length >> 24));
                os.write((int)(length >> 16));
                os.write((int)(length >> 8));
                os.write((int)length);
            }
            if(masked){
                os.write(mask);
            }
            for(int i = 0; i < length; i++){
                data[i] ^= mask[i % 4];
            }
            os.write(data);
        }

        private String bytesToString(byte[] bytes){
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            for(int i = 0; i < bytes.length; i++){
                sb.append(String.format("%02X", bytes[i]));
                if(i < bytes.length - 1){
                    sb.append(", ");
                }
            }
            sb.append("]");
            return sb.toString();
        }

        @Override
        public String toString(){
            StringBuilder sb = new StringBuilder();
            sb.append("Frame(\n");
            sb.append("  fin: ").append(fin).append("\n");
            sb.append("  opcode: ").append(opcode).append("\n");
            sb.append("  masked: ").append(masked).append("\n");
            sb.append("  length: ").append(length).append("\n");
            sb.append("  mask: ").append(bytesToString(mask)).append("\n");
            if(opcode == 1){
                sb.append("  data: ").append(new String(data)).append("\n");
            }else{
                sb.append("  data: ").append(bytesToString(data)).append("\n");
            }
            sb.append(")");
            return sb.toString();
        }
    }

    private final Set<Consumer<Frame>> readListeners = new HashSet<Consumer<Frame>>();

    /**
     * Read a frame from the WebSocket. This method will block until a frame is read.
     * <p>
     * This method will also fire any listeners that have been added with onReadFrame.
     * </p>
     * <p>
     * Be careful using this with getInputStream, as reading frames with readFrame will stop them from getting read by the InputStream.
     * </p>
     * @return the frame read from the websocket
     * @throws IOException if there was a problem reading the frame.
     */
    public Frame readFrame() throws IOException {
        Frame frame = Frame.read(socket.getInputStream());
        for(Consumer<Frame> listener : readListeners){
            listener.invoke(frame);
        }
        return frame;
    }

    /**
     * Add a listener to be fired every time a frame is read. This mostly exists for debugging purposes.
     * <p>
     * Frames will still only be read when a call to readFrame() is made or data is read from the InputStream.
     * </p>
     * @param listener A listener to call with the read frame
     * @see readFrame
     * @see getInputStream
     */
    public void onReadFrame(Consumer<Frame> listener){
        readListeners.add(listener);
    }

    private final Set<Consumer<Frame>> writeListeners = new HashSet<Consumer<Frame>>();

    /**
     * Write a frame to the WebSocket.
     * <p>
     * This method will also fire any listeners that have been added with onWriteFrame.
     * </p>
     * @param frame the frame to write
     * @throws IOException if there was a problem writing the frame.
     */
    public void writeFrame(Frame frame) throws IOException {
        for(Consumer<Frame> listener : writeListeners){
            listener.invoke(frame);
        }
        frame.write(socket.getOutputStream());
    }

    /**
     * Add a listener to be fired every time a frame is written. This mostly exists for debugging purposes.
     * @param listener A listener to call with the written frame
     * @see writeFrame
     * @see getOutputStream
     */
    public void onWriteFrame(Consumer<Frame> listener){
        writeListeners.add(listener);
    }

    private class WebSocketInputStream extends InputStream {

        List<Byte> buffer = new ArrayList<Byte>();

        private int readFrame() throws IOException{
            Frame frame;
            do{
                frame = WebSocket.this.readFrame();
                if(frame.opcode == 8){
                    return -1;
                }
                if(frame.opcode == 9){
                    Frame response = new Frame(true, 10, false, frame.length, new byte[4], frame.data);
                    response.write(socket.getOutputStream());
                    return 0;
                }
                for(int i = 0; i < frame.data.length; i++){
                    buffer.add(frame.data[i]);
                }
            }while(!frame.fin);
            return 0;
        }

        @Override
        public int read() throws IOException {
            while (buffer.isEmpty()){
                int result = readFrame();
                if(result == -1){
                    if(buffer.isEmpty()){
                        return -1;
                    }
                }
            }
            return buffer.remove(0);
        }

        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if(buffer.isEmpty()){
                int result = readFrame();
                if(result == -1){
                    return -1;
                }
            }
            int i = 0;
            while(i < len && !buffer.isEmpty()){
                b[off + i] = buffer.remove(0);
                i++;
            }
            return i;
        }
        

    }

    private class WebSocketOutputStream extends OutputStream {

        private void writeFrame(byte[] bytes, int off, long len) throws IOException {
            byte[] mask = new byte[4];
            for(int i = 0; i < 4; i++){
                mask[i] = (byte)(Math.random() * 256);
            }
            byte[] data = new byte[(int)len];
            for(int i = 0; i < len; i++){
                data[i] = bytes[off + i];
            }
            Frame frame = new Frame(true, 2, true, len, mask, data);
            WebSocket.this.writeFrame(frame);
        }

        @Override
        public void write(int b) throws IOException {
            byte[] bytes = new byte[1];
            bytes[0] = (byte)b;
            writeFrame(bytes, 0, 1);
        }

        @Override
        public void write(byte[] b) throws IOException {
            writeFrame(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            writeFrame(b, off, len);
        }

        

    }

    private final WebSocketInputStream inputStream = new WebSocketInputStream();
    private final WebSocketOutputStream outputStream = new WebSocketOutputStream();

    @Override
    public InputStream getInputStream() throws IOException {
        return inputStream;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return outputStream;
    }

    @Override
    public void sendUrgentData(int data) throws IOException{
        outputStream.write(data);
    }

    @Override
    public void close() throws SocketException {

    }

    @Override
    public void shutdownInput() throws SocketException {

    }

    @Override
    public void shutdownOutput() throws SocketException {

    }

    @Override
    public String toString() {
        return "WebSocket(" + uri + ")";
    }

    @Override
    public boolean isConnected() {
        return socket.isConnected();
    }

    @Override
    public void bind(SocketAddress bindpoint) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void connect(SocketAddress endpoint) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) {
        throw new UnsupportedOperationException();
    }

    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    @Override
    public int getPort() {
        return socket.getPort();
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress(){
        return socket.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress(){
        return socket.getLocalSocketAddress();
    }

    @Override
    public SocketChannel getChannel(){
        return socket.getChannel();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        socket.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        socket.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return socket.getSoLinger();
    }

    

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        socket.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return socket.getOOBInline();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return socket.getSoTimeout();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException{
        socket.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return socket.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        socket.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return socket.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        socket.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return socket.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        socket.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return socket.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        socket.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return socket.getReuseAddress();
    }

    @Override
    public boolean isBound() {
        return socket.isBound();
    }

    @Override
    public boolean isClosed() {
        return socket.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return socket.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown(){
        return socket.isOutputShutdown();
    }
}
