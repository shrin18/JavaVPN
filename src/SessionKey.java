import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;

public class SessionKey {

	KeyGenerator keyGenerator;
	SecretKey secretKey;

	public SessionKey(Integer keylength) throws NoSuchAlgorithmException {

		keyGenerator = KeyGenerator.getInstance("AES");
		this.secretKey = keyGenerator.generateKey();
	}

	public SessionKey(String encodedkey) throws NoSuchAlgorithmException {
		this.secretKey = new SecretKeySpec(this.decodeKey(encodedkey), "AES");
	}

	public SecretKey getSecretKey() throws NoSuchAlgorithmException {
			return this.secretKey;
	}

	public String encodeKey() throws UnsupportedEncodingException {

		String base64encodedString = Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
		return base64encodedString;
	}

	//public byte[] decodeKey(String base64encodedString) {
	public byte[] decodeKey(String base64encodedString) {

		//byte[] base64decodedBytes = Base64.getDecoder().decode(base64encodedString);
		//return base64decodedBytes;	
		byte[] decoded = Base64.getDecoder().decode(base64encodedString);
		return decoded;	

	}

	/*
	 * public static void main(String[] args) throws NoSuchAlgorithmException,
	 * UnsupportedEncodingException {
	 * 
	 * SessionKey key1 = new SessionKey(128); SessionKey key2 = new
	 * SessionKey(key1.encodeKey());
	 * 
	 * if (key1.getSecretKey().equals(key2.getSecretKey())) {
	 * System.out.println("Pass"); System.out.println(key1.getSecretKey());
	 * System.out.println(key2.getSecretKey());
	 * System.out.println(key2.encodeKey()); System.out.println(key1.encodeKey());
	 * 
	 * } else { System.out.println("Fail"); } }
	 */
}
