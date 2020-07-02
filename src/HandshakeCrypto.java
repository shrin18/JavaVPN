import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class HandshakeCrypto {

	private static final URI PRIVATEKEYFILE = null;
	private static final String CERTFILE = null;
	static Cipher cipher;
	Key key;
	static SecretKey secretKey;
	PublicKey publicKey;
	private static String plaintext;

	
	public static byte[] encrypt(byte[] plaintext, Key key) throws Exception 
	{

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);

	}

	public static byte[] decrypt(byte[] ciphertext, Key key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
//		System.out.println("plain : " + new String(plaintext));
//		byte[] encodedBytes = null;
//		byte[] originalString = Base64.getDecoder().decode(encodedBytes);
//		return originalString;
		return cipher.doFinal(ciphertext);

	}
	
	public static PublicKey getPublicKeyFromCertFile(String certfile)
			throws CertificateException, FileNotFoundException 
	{
				
		CertificateFactory cf          = CertificateFactory.getInstance("X.509");
		FileInputStream    file        = new FileInputStream(certfile);
		X509Certificate    certificate = (X509Certificate) cf.generateCertificate(file);
		
		return certificate.getPublicKey();
		
	}
	
	public static PrivateKey getPrivateKeyFromKeyFile(String keyfile)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		Path path = Paths.get(keyfile);
		byte[] privKeyByteArray = Files.readAllBytes(path);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
		return myPrivKey;
	}

	public static void main(String[] args) throws Exception 
   {
	final String CERTFILE = "shrincert.pem"; 
	final String PRIVATEKEYFILE = "privatekeypcs8.der";
	final String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
	final String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */
	PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);
	PrivateKey privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);
	System.out.println("public key: "+publickey);
	System.out.println("private key: "+privatekey);
	
	/* Encode string as bytes */
    byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
    
    /* Encrypt it */
    byte[] cipher = HandshakeCrypto.encrypt(plaininputbytes, publickey);		
	System.out.println("EncryptedBytes: "+cipher);
	String plaininput = new String(cipher, ENCODING);
	System.out.println("EncryptedText: "+plaininput);
	
	 /* Then decrypt back */
    byte[] plainoutputbytes = HandshakeCrypto.decrypt(cipher, privatekey);
    System.out.println("DecryptedByte: "+plainoutputbytes);
    String plainoutput = new String(plainoutputbytes, ENCODING);
    System.out.println("DecryptedText: "+plainoutput);
    
    //Test
    if (plainoutput.equals(PLAINTEXT)) {
        System.out.println("Pass. Input and output strings are the same: \"" + PLAINTEXT + "\"");
    }
    else {
        System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" + plainoutput + "\'");
    }
   
   }
}

