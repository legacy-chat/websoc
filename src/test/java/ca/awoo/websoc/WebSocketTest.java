package ca.awoo.websoc;

import static org.junit.Assert.assertEquals;

import java.net.URI;

import org.junit.Test;

public class WebSocketTest {
    @Test
    public void echoTest() throws Exception{
        WebSocket ws = new WebSocket(new URI("ws://echo.websocket.org/"));
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
        ws.readFrame(); //This server sends a little hello message when you connect
        ws.getOutputStream().write("Hello, World!".getBytes("UTF-8"));
        byte[] buffer = new byte[1024];
        int len = ws.getInputStream().read(buffer);
        String response = new String(buffer, 0, len, "UTF-8");
        assertEquals("Hello, World!", response);
        ws.close();
    }
}
