/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.lang.AssertionError;
import java.lang.Integer;
import java.util.ArrayList;
import java.util.Base64;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
 
public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;
    
    public static HandshakeMessage fromCLIENT;
    public static HandshakeMessage fromFORWARD;
    public static HandshakeMessage sess;
    public static HandshakeMessage serhello;
    private static X509Certificate cert1;
    private static X509Certificate cert2;
    private static X509Certificate cert3;
    private static PublicKey key1;
    private static PublicKey key2;
    private static SecretKey key3;
    private static Cipher cipher;
    private static IvParameterSpec h1;
    private static byte[] a;
    private static byte[] c;
    private int keylength=128;

    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        fromCLIENT = new HandshakeMessage();
        fromCLIENT.recv(clientSocket);
        if (fromCLIENT.getParameter("MessageType").equals("ClientHello"))
     {  String a=fromCLIENT.getParameter("Certificate");
        byte[] decodedCertificate = Base64.getDecoder().decode(a);
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is2 = new FileInputStream (arguments.get("cacert"));
        cert1 = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(decodedCertificate));
        cert2 = (X509Certificate) fact.generateCertificate(is2);
        key1=cert1.getPublicKey();
        key2=cert2.getPublicKey();
        cert1.verify(key2);
        cert1.checkValidity();
		cert2.verify(key2);
		cert2.checkValidity();
        X500Principal dn1 = cert1.getSubjectX500Principal();;    
        System.out.println("ForwardClient DN:" + dn1.getName());
        }
        
        serhello = new HandshakeMessage();
        serhello.putParameter("MessageType", "ServerHello");
        FileInputStream is3 = new FileInputStream (arguments.get("usercert"));
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
		cert3 = (X509Certificate) fact.generateCertificate(is3);
		byte[] Cert1 = cert3.getEncoded();
		String encodedCertificate1 = Base64.getEncoder().encodeToString(Cert1);
        serhello.putParameter("Certificate",encodedCertificate1 );
        serhello.send(clientSocket);
		cert3.verify(key2);
		cert3.checkValidity();
        
        fromFORWARD = new HandshakeMessage();
        fromFORWARD.recv(clientSocket);
        if (fromFORWARD.getParameter("MessageType").equals("Forward"))
        {    targetHost=fromFORWARD.getParameter("TargetHost");
             targetPort=Integer.parseInt(fromFORWARD.getParameter("TargetPort"));
        }
        
        sess = new HandshakeMessage();
        sess.putParameter("MessageType","Session");
        KeyGenerator keyGenerator;
        keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();	     
	    keyGenerator.init(keylength, secureRandom);
	    key3 = keyGenerator.generateKey();	    
	    cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE,key1);
		a=cipher.doFinal(key3.getEncoded());
		String encodedKey = Base64.getEncoder().encodeToString(a); 
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[16];
		randomSecureRandom.nextBytes(iv);
		h1 = new IvParameterSpec(iv);
	    c=cipher.doFinal(iv);
	    String encodedIV = Base64.getEncoder().encodeToString(c);
	    String serverPort = Integer.toString(Handshake.serverPort);
	    sess.putParameter("SessionKey",encodedKey);
        sess.putParameter("SessionIV",encodedIV);
        sess.putParameter("ServerHost",Handshake.serverHost);
        sess.putParameter("ServerPort",serverPort);
        sess.send(clientSocket);
        
        
        clientSocket.close();       

        /*
         * Fake the handshake result with static parameters. 
         */

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
            
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
        {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
           throw new IOException("Unable to bind to port " + port);
        }
 
        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
           try {
			   			           CertificateFactory fact = CertificateFactory.getInstance("X.509");
			   FileInputStream is3 = new FileInputStream (arguments.get("usercert"));
			   cert3 = (X509Certificate) fact.generateCertificate(is3);
			           FileInputStream is2 = new FileInputStream (arguments.get("cacert"));
				cert2 = (X509Certificate) fact.generateCertificate(is2);
				key2=cert2.getPublicKey();
				cert3.verify(key2);
				cert3.checkValidity();

				
               doHandshake();

               forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
               forwardThread.setSecretKey(key3,h1);
               forwardThread.start();
           } catch (IOException e) {
               throw e;
           }
        }}
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        try {
           srv.startForwardServer();
        } catch (Exception e) {
           e.printStackTrace();
        }
    }
 
}