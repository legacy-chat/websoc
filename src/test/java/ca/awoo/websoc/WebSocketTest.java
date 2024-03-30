package ca.awoo.websoc;

import static org.junit.Assert.assertEquals;

import java.net.URI;

import org.junit.Test;

import ca.awoo.fwoabl.function.Consumer;

public class WebSocketTest {
    @Test
    public void echoTest() throws Exception{
        WebSocket ws = new WebSocket(new URI("ws://echo.websocket.org/"));
        ws.onReadFrame(new Consumer<WebSocket.Frame>() {
            public void invoke(WebSocket.Frame frame) {
                System.out.println(frame);
            }
        });
        ws.onWriteFrame(new Consumer<WebSocket.Frame>() {
            public void invoke(WebSocket.Frame frame) {
                System.out.println(frame);
            }
        });
        ws.readFrame(); //This server sends a little hello message when you connect
        ws.getOutputStream().write("Hello, World!".getBytes("UTF-8"));
        byte[] buffer = new byte[1024];
        int len = ws.getInputStream().read(buffer);
        String response = new String(buffer, 0, len, "UTF-8");
        assertEquals("Hello, World!", response);
        ws.close();
    }

    @Test
    public void secureEchoTest() throws Exception{
        WebSocket ws = new WebSocket(new URI("wss://echo.websocket.org"));
        ws.onReadFrame(new Consumer<WebSocket.Frame>() {
            public void invoke(WebSocket.Frame frame) {
                System.out.println(frame);
            }
        });
        ws.onWriteFrame(new Consumer<WebSocket.Frame>() {
            public void invoke(WebSocket.Frame frame) {
                System.out.println(frame);
            }
        });
        ws.readFrame(); //This server sends a little hello message when you connect
        ws.getOutputStream().write("Hello, World!".getBytes("UTF-8"));
        byte[] buffer = new byte[1024];
        int len = ws.getInputStream().read(buffer);
        String response = new String(buffer, 0, len, "UTF-8");
        assertEquals("Hello, World!", response);
        ws.close();
    }

    @Test
    public void longTest() throws Exception{
        WebSocket ws = new WebSocket(new URI("ws://echo.websocket.org/"));
        ws.onReadFrame(new Consumer<WebSocket.Frame>() {
            public void invoke(WebSocket.Frame frame) {
                System.out.println(frame);
            }
        });
        ws.onWriteFrame(new Consumer<WebSocket.Frame>() {
            public void invoke(WebSocket.Frame frame) {
                System.out.println(frame);
            }
        });
        ws.readFrame(); //This server sends a little hello message when you connect
        byte[] longBuffer = new byte[1024*50];
        for(int i = 0; i < longBuffer.length; i++){
            longBuffer[i] = (byte)(i % 256);
        }
        ws.getOutputStream().write(longBuffer);
        byte[] buffer = new byte[1024*50];
        int len = ws.getInputStream().read(buffer);
        assertEquals(longBuffer.length, len);
        for(int i = 0; i < len; i++){
            assertEquals((byte)(i % 256), buffer[i]);
        }
        ws.close();
    }
}
