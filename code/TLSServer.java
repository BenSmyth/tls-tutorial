import java.io.File;
import java.io.IOException;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel; 
import java.nio.channels.ServerSocketChannel; 

class TLSServer {
  public static void main(String[] args) throws GeneralSecurityException, IOException {   
    if (args.length != 2) {
      System.out.println("Usage: java TLSServer <<filename>> <<password>>");
      System.exit(-1);
    }

    InetAddress host = InetAddress.getLocalHost();
    int port = 8443;

    ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
    serverSocketChannel.socket().bind(new InetSocketAddress(host, port));

    SocketChannel socketChannel = serverSocketChannel.accept();

    serverSocketChannel.close();

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(KeyStore.getInstance(new File(args[0]), args[1].toCharArray()), args[1].toCharArray());

    SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
    sslContext.init(kmf.getKeyManagers(), null, null);
    
    SSLEngine engine = sslContext.createSSLEngine();
    engine.setUseClientMode(false);

    TLSHost server = new TLSHost(engine, socketChannel);
    server.wrap(ByteBuffer.wrap("World\r\n".getBytes()));
    server.wrap(ByteBuffer.wrap("It's cold today\r\n".getBytes()));
    server.closeOutbound();
  }
}
