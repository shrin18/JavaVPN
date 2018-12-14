import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;


public class RunCode {

	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		
		SessionKey key1 = new SessionKey(128);
		SessionKey key2 = new SessionKey(key1.encodeKey());
		
		
		if (key1.getSecretKey().equals(key2.getSecretKey())) {
			
			System.out.println("Pass");
			System.out.println(key1.getSecretKey());
			System.out.println(key2.getSecretKey());
			System.out.println(key2.encodeKey());
			System.out.println(key1.encodeKey());
		} 
		
		else {
			System.out.println("Fail");
		}
	}
}
