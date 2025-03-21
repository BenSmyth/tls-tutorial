import java.io.IOException;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel; 

class TLSClient {
  public static void main(String[] args) throws NoSuchAlgorithmException, IOException {   
    //System.setProperty( "javax.net.debug", "ssl handshake verbose");
    
    System.setProperty("javax.net.ssl.trustStore", "store");
    System.setProperty("javax.net.ssl.trustStorePassword", "nopassword");
                 
    InetAddress host = InetAddress.getLocalHost();
    int port = 8443;

    SocketChannel socketChannel = SocketChannel.open();
    socketChannel.connect(new InetSocketAddress(host, port));

    SSLEngine engine = SSLContext.getDefault().createSSLEngine();
    engine.setUseClientMode(true);

    TLSHost client = new TLSHost(engine, socketChannel);
    client.wrap(ByteBuffer.wrap("Hello\r\n".getBytes()));
    client.wrap(ByteBuffer.wrap("enchanté\r\n".getBytes()));
    client.closeOutbound();
  }  
}
