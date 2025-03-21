import java.io.IOException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.Status;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel; 

class TLSHost extends SSLEngineHost {

  TLSHost(final SSLEngine engine, final SocketChannel socketChannel) {
    super(engine);
    
    setSSLEngineListener(new SSLEngineHost.SSLEngineListener() {
      public void postWrap(ByteBuffer outPacketBuffer, SSLEngineResult result) {
        try {
          socketChannel.write(outPacketBuffer);
          
          if (result.getStatus() == Status.CLOSED)
            socketChannel.shutdownOutput();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }

      public void postUnwrap(ByteBuffer inAppBuffer, SSLEngineResult result) {
        if (inAppBuffer.position() != 0)
          System.out.print(new String(inAppBuffer.array()));
          
        try {
          if (result.getStatus() == Status.CLOSED)
            socketChannel.shutdownInput();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    });
    
    new Thread(() -> {
      ByteBuffer inPacketBuffer = ByteBuffer.allocate(engine.getSession().getPacketBufferSize()); 
      try {
        int bytesRead;      
        while ((bytesRead = socketChannel.read(inPacketBuffer)) > 0) {
          inPacketBuffer.flip();
          this.unwrap(inPacketBuffer);
          inPacketBuffer.compact();
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    }).start();    
  }
}
