/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import java.lang.AssertionError;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
 
public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    
    public static HandshakeMessage clientHELLO;
    public static HandshakeMessage fromSERVER;
    public static HandshakeMessage forward;
    public static HandshakeMessage fromSESSION;
    private static X509Certificate cert3;
    private static X509Certificate cert4;
    private static PublicKey key3;
    private static PrivateKey myPrivKey;
    private static Cipher cipher;
    private static byte [] c;
    private static byte [] d;
    private static SecretKey originalKey;
    private static IvParameterSpec ivParams;
    private static X509Certificate cert1;
    
   

    private static void doHandshake() throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        clientHELLO= new HandshakeMessage();
		clientHELLO.putParameter("MessageType", "ClientHello");
		FileInputStream is1 = new FileInputStream (arguments.get("usercert"));
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		cert1 = (X509Certificate) fact.generateCertificate(is1);
		byte[] Cert = cert1.getEncoded();
		String encodedCertificate = Base64.getEncoder().encodeToString(Cert);
        clientHELLO.putParameter("Certificate",encodedCertificate );
        clientHELLO.send(socket);
        
        fromSERVER = new HandshakeMessage();
        fromSERVER.recv(socket);
        if (fromSERVER.getParameter("MessageType").equals("ServerHello"))
     {  byte[] decodedCertificate1 = Base64.getDecoder().decode(fromSERVER.getParameter("Certificate"));
        String g=arguments.get("cacert");
        FileInputStream is4 = new FileInputStream (g);
        cert3 = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(decodedCertificate1));
        cert4 = (X509Certificate) fact.generateCertificate(is4);
        key3=cert4.getPublicKey();
		cert4.verify(key3);
		cert4.checkValidity();
        cert3.verify(key3);
        cert3.checkValidity();
        X500Principal dn2 = cert3.getSubjectX500Principal();;    
        System.out.println("ForwardServer DN:" + dn2.getName());
        }
        
        forward= new HandshakeMessage();
        forward.putParameter("MessageType", "Forward");
        forward.putParameter("TargetHost",arguments.get("targethost") );
        forward.putParameter("TargetPort",arguments.get("targetport") );
        forward.send(socket);
        
        fromSESSION =new HandshakeMessage();
        fromSESSION.recv(socket);
        if (fromSESSION.getParameter("MessageType").equals("Session"))
      { 
        byte[] decodedKey = Base64.getDecoder().decode(fromSESSION.getParameter("SessionKey"));
        byte[] decodedIV = Base64.getDecoder().decode(fromSESSION.getParameter("SessionIV"));
        Path path = Paths.get(arguments.get("key"));
        byte[] privKeyByteArray = Files.readAllBytes(path);
   	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
   	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
   	    myPrivKey = keyFactory.generatePrivate(keySpec);
   	    
   	    cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE,myPrivKey);
		c=cipher.doFinal(decodedKey);
		d=cipher.doFinal(decodedIV);
		originalKey = new SecretKeySpec(c,"AES");
		ivParams = new IvParameterSpec(d);
		}

        socket.close();
        //System.out.println("Client forwarder to target localhost: "+arguments.get("targetport"));
        //System.out.println("Waiting for incoming connections at 130.237.11.12:51953");

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;        
    }
    

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    			CertificateFactory fact = CertificateFactory.getInstance("X.509");
				FileInputStream is1 = new FileInputStream (arguments.get("usercert"));
						cert1 = (X509Certificate) fact.generateCertificate(is1);

	String g=arguments.get("cacert");
        FileInputStream is4 = new FileInputStream (g);
		cert4 = (X509Certificate) fact.generateCertificate(is4);
        key3=cert4.getPublicKey();
		cert4.verify(key3);
		cert4.checkValidity();
		cert1.checkValidity();
        
        doHandshake();
        // Wait for client. Accept one connection.
        
        
        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            
            listensocket.bind(null); 
            /* Tell the user, so the user knows where to connect */ 
            tellUser(listensocket);
            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            
            log("Accepted client from " + clientHostPort);
            
            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.setSecretKey(originalKey,ivParams);
            forwardThread.start();
            
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

	/**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
*/
    public static void main(String[] args)
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
       
            try {
				startForwardClient();
			} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
					| SignatureException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException
					| BadPaddingException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}      
}}