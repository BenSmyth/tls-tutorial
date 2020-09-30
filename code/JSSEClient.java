import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class JSSEClient {

  public static void main(String[] args) throws Exception {

    //System.setProperty( "javax.net.ssl.trustStore", "store" );  
    //System.setProperty( "javax.net.ssl.trustStorePassword", "nopassword");

    System.setProperty​("javax.net.debug", "ssl handshake verbose");

    //Open TCP connection to <<host>> : <<port>>, using default SSL socket factory
    final String host = "example.com";
    final int port = 443;
    SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);  

    //TLS handshake
    socket.startHandshake();  

    //Request index page from <<host>>
    OutputStreamWriter out = new OutputStreamWriter(socket.getOutputStream());
    out.write("GET / HTTP/1.1\r\n");
    out.write("Host: " + host + "\r\n");  //mandatory for HTTP/1.1 requests
    out.write("\r\n");  //header concludes with blank line
    out.flush();

    //Print response
    InputStreamReader in = new InputStreamReader(socket.getInputStream());
    int c;
    while ((c = in.read()) != -1)
      System.out.print((char)c);

    out.close();
    in.close();
    socket.close();

  }
}
