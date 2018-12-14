import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import keygen.keyGenerator;

public class Base64 {
	
	public void trycode() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 256;
		keyGenerator.init(keyBitSize, secureRandom);

		SecretKey secretKey = keyGenerator.generateKey();
	}
}
