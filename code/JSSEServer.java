import java.io.InputStreamReader;
import java.io.File;
import java.io.OutputStreamWriter;

import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.security.KeyStore;

public class JSSEServer {

  public static void main(String[] args) throws Exception {
    
    System.setProperty​("javax.net.debug", "ssl handshake verbose");

    if (args.length != 2) {
      System.out.println("Usage: java JSSEServer <<filename>> <<password>>");
      System.exit(-1);
    }  

    //Init. default SSL context parametrised with key store args[0], using pwd args[1]
    SSLContext sslContext = SSLContext.getInstance("TLSv1.3");

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(
      KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(KeyStore.getInstance(new File(args[0]), args[1].toCharArray()), 
      args[1].toCharArray());

    sslContext.init(kmf.getKeyManagers(), null, null); 

    //Init. incoming TCP connection on <<host>> : <<port>>, using default SSL socket factory
    final InetAddress host = InetAddress.getLocalHost();
    final int port = 8443;
    final int backlog = 50;
    SSLServerSocket socket = (SSLServerSocket) sslContext.getServerSocketFactory()
      .createServerSocket(port, backlog, host);
 
    //Wait for a connection  
    Socket session = socket.accept(); 

    //Read an incoming character
    InputStreamReader in = new InputStreamReader(session.getInputStream());
    if (in.read() == -1) 
      System.exit(1);

    //Response (regardless of input)
    OutputStreamWriter out = new OutputStreamWriter(session.getOutputStream());
    out.write("HELLO WORLD\r\n");
    out.flush();

    out.close();
    in.close();
    session.close();
    socket.close();

  }    
}
