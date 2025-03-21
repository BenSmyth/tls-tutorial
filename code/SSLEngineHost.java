import java.nio.ByteBuffer;
import java.nio.BufferOverflowException;

import java.util.concurrent.Semaphore;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;

/* 
  SSLEngineHost defines methods
  
      SSLEngineHost.wrap(outAppBuffer) and SSLEngineHost.unwrap(inPacketBuffer)

  providing a high-level interface to TLS via SSLEngine methods

      SSLEngine.wrap(outAppBuffer, outPacketBuffer)

  and

      SSLEngine.unwrap(inPacketBuffer, inAppBuffer)    

  allowing plaintext application data (outAppBuffer) to be encoded into TLS
  records (outPacketBuffer), and TLS records (inPacketBuffer) to be decoded
  into application data (inAppBuffer), with calls

      sslEngineListener.postWrap(outPacketBuffer, result);

  and 

      sslEngineListener.postUnwrap(inAppBuffer, result);

  passing outgoing TLS records and incoming application data, respectively. 
  (Method setSSLEngineListener() instantiates that listener.)
*/
public class SSLEngineHost {
 
/*                               (plaintext)
                               application data                               */

  private ByteBuffer     outAppBuffer;
  private ByteBuffer                  inAppBuffer;
/*                               |            
                                 |           Λ
                                 |     |     |
                                 V     |     |
                            +----+-----|-----+----+
                            |          |          |
                    wrap()  |          |          |  unwrap()                 */

  protected final              SSLEngine engine;

/*                          |          |          |
                            | OUTBOUND | INBOUND  |
                            +----+-----|-----+----+
                                 |     |     Λ
                                 |     |     |
                                 V           |
                                             |                                */       
  private ByteBuffer    outPacketBuffer;
  private ByteBuffer        	      inPacketBuffer;

/*                               network data                          
                                 (TLS records)                                */


  //Listener called after SSLEngine.wrap() and SSLEngine.unwrap()
  private SSLEngineListener         sslEngineListener;

  //Semaphore blocking SSLEngine operation loop (method doTLS(), below) until required
  private final Semaphore      	    semaphore;

  //SSLEngine accesses outAppBuffer and inPacketBuffer on one thread, and those
  //buffers are manipulated on another, locks avoid concurrent manipulation
  private final Object 		          lockOutAppBuffer   = new Object();
  private final Object 		          lockInPacketBuffer = new Object();

  public SSLEngineHost(final SSLEngine engine) {
    this.engine = engine;

    outAppBuffer = ByteBuffer.allocate(0);
    inAppBuffer = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());

    outPacketBuffer = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
    inPacketBuffer = ByteBuffer.allocate(0);

    sslEngineListener = new SSLEngineListener();

    semaphore = new Semaphore(1);
    semaphore.drainPermits();

    new Thread() { public void run() {    doTLS();    } }.start();
  }

  private void doTLS() {
    while (!engine.isInboundDone() || !engine.isOutboundDone()) {
      semaphore.acquireUninterruptibly();

      HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
      do {
        if (handshakeStatus != HandshakeStatus.NOT_HANDSHAKING)
          doTLS(handshakeStatus);
        else if (outAppBuffer.position() != 0)
          doTLS(HandshakeStatus.NEED_WRAP);
        else if (inPacketBuffer.position() != 0)
          doTLS(HandshakeStatus.NEED_UNWRAP);
        else if (!engine.isOutboundDone() && closeOutbound) {
          engine.closeOutbound();
          doTLS(HandshakeStatus.NEED_WRAP);
          /* For OpenJDK, closeOutbound() causes getHandshakeStatus() to return
             HandshakeStatus.NEED_WRAP, whereas HandshakeStatus.NOT_HANDSHAKING is 
             returned for Bouncy Castle. Force wrap() to cover both cases. 
             (https://marc.info/?l=bouncycastle-crypto-dev&m=165243053823579&w=2) */
        }
      } while ((handshakeStatus = engine.getHandshakeStatus())
                != HandshakeStatus.NOT_HANDSHAKING ||
                outAppBuffer.position() != 0 ||
                inPacketBuffer.position() != 0 ||
                (!engine.isOutboundDone() && closeOutbound));
    }
  }

  private void doTLS(final HandshakeStatus handshakeStatus) {
    final SSLEngineResult result;

    switch (handshakeStatus) {
      case NEED_WRAP: 
        synchronized(lockOutAppBuffer) {
          outPacketBuffer.clear();
          outAppBuffer.flip();
          try {
            result = engine.wrap(outAppBuffer, outPacketBuffer);
          } catch (SSLException e) {
            engine.closeOutbound();
            break;
          }
          outAppBuffer.compact();
        }

        switch (result.getStatus()) {
          case CLOSED:
            //Outbound connection just closed or was already closed;
            //no more application data will be processed
            synchronized(lockOutAppBuffer) { outAppBuffer.clear(); }
            /* fallthrough, handover to listener */
          case OK:
            outPacketBuffer.flip();
            sslEngineListener.postWrap(outPacketBuffer, result);
            break;

          case BUFFER_OVERFLOW:
            //SSLEngine.getSession().getPacketBufferSize() returns: "the current 
            //maximum expected network packet size." Hence, outPacketBuffer *was* 
            //large enough for *expected* packets (at the time of instantiation). 
            //For current or unexpected packet sizes, allocate more space:
            outPacketBuffer = ByteBuffer.allocate(outPacketBuffer.capacity() * 2);
            break;

          case BUFFER_UNDERFLOW:
            throw new IllegalStateException(
              "SSLEngine.wrap produced SSLEngineResult.Status.BUFFER_UNDERFLOW, "
              + "which should only ever be produced on SSLEngine.unwrap");

          default:
            throw new IllegalStateException(
              "Invalid SSLEngineResult.Status: " + result.getStatus());
        }

        break;

      case NEED_UNWRAP:
        synchronized(lockInPacketBuffer) {
          inAppBuffer.clear();
          inPacketBuffer.flip();
          try {
            result = engine.unwrap(inPacketBuffer, inAppBuffer);
          } catch (SSLException e) {
            try { 
              engine.closeInbound();
            } catch (SSLException ee) {
              //SSLEngine.closeInbound() throws an SSLException when a peer's closure  
              //message hasn't been processed, including this instance
            }
            break;
          }
          inPacketBuffer.compact();
        }

        switch (result.getStatus()) {
          case CLOSED:
            //Inbound connection just closed or was already closed;
            //no more network data will be processed
            synchronized(lockInPacketBuffer) { inPacketBuffer.clear(); }
            /* fallthrough, handover to listener */
          case OK:
            sslEngineListener.postUnwrap(inAppBuffer, result); 
            break;

          case BUFFER_OVERFLOW:
            inAppBuffer = ByteBuffer.allocate(inAppBuffer.capacity() * 2);                
            break;

          case BUFFER_UNDERFLOW:
            //Not enough handshake data has been read for unwrap; there's probably          
            //a more intelligent way to iterate here, e.g., waiting for enough          //TO DO: Be intelligent
            //data on socketChannel, but it's unclear (to me) how much data is 
            //"enough" and getting that wrong could create an infinite loop
            break;

          default:
            throw new IllegalStateException(
              "Invalid SSLEngineResult.Status: " + result.getStatus());
        }

        break;

      case NEED_TASK:
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) 
          new Thread(task).start();
        break;
 
      case FINISHED:
        throw new IllegalStateException(
          "Unexpected SSLEngineResult.HandshakeStatus.FINISHED");
      case NEED_UNWRAP_AGAIN:
        throw new IllegalStateException(
          "Unexpected SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN");
      default:
        throw new IllegalStateException(
          "Invalid SSLEngineResult.HandshakeStatus: " + handshakeStatus);
    }
  }

  public void wrap(final ByteBuffer byteBuffer)  {
    synchronized(lockOutAppBuffer) {
      try {
        outAppBuffer.put(byteBuffer);
      } catch (BufferOverflowException e) {
        outAppBuffer = concat(outAppBuffer.flip(), byteBuffer);
      }          
    }
    semaphore.release();
  }

  public void unwrap(final ByteBuffer byteBuffer) {
    synchronized(lockInPacketBuffer) {
      try {
        inPacketBuffer.put(byteBuffer);
      } catch (BufferOverflowException e) {
        inPacketBuffer = concat(inPacketBuffer.flip(), byteBuffer);
      }
    }
    semaphore.release();
  }

  private static ByteBuffer concat(ByteBuffer b, ByteBuffer bb) {
    return ByteBuffer.allocate(b.remaining() + bb.remaining())
            .put(b)
            .put(bb);
  }

  public void beginHandshake() throws SSLException {
    try {
      engine.beginHandshake();
    } catch (SSLException e) {
      //SSLEngine.beginHandshake() throws an SSLException when a problem is 
      //encountered while signaling the SSLEngine to begin a new handshake,
      //re-throw any such exception
      throw e;
    } finally {
      semaphore.release();
    }
  }

  private boolean closeOutbound = false;

  /*
    In server mode (!SSLEngine.getUseClientMode()), calling closeOutbound() before 
    beginHandshake() will cause SSLEngine.closeOutbound() if neither wrap() nor 
    unwrap() have been called
  */
  public void closeOutbound() {
    closeOutbound = true;
    semaphore.release();
  }

  public void closeInbound() throws SSLException {
    try {
      engine.closeInbound(); 
    } catch (SSLException e) {
      //SSLEngine.closeInbound() throws an SSLException when a peer's closure  
      //message hasn't been processed, re-throw any such exception    
      throw e;
    } finally {
      semaphore.release();
    }
  }

  public void setSSLEngineListener(SSLEngineListener sslEngineListener) {
    this.sslEngineListener = sslEngineListener;
  }

  public static class SSLEngineListener
  {
    public void postWrap(ByteBuffer outPacketBuffer, SSLEngineResult result) {}

    public void postUnwrap(ByteBuffer inAppBuffer, SSLEngineResult result) {}
  }
}
