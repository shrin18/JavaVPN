import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SessionEncrypter {
	static SessionKey sessionKey;
	SecretKey secretKey;
	IvParameterSpec ctrIv;
	byte[] counter;
	Cipher cipherText;

	public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, UnsupportedEncodingException,
			InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {
		// TODO Auto-generated constructor stub
		SessionKey key = new SessionKey(keylength);
		secretKey      = key.getSecretKey();
		counter        = new byte[keylength/8];
		SecureRandom srandom = new SecureRandom();
		srandom.nextBytes(counter);
		ctrIv          = new IvParameterSpec(counter);
		cipherText     = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipherText.init(Cipher.ENCRYPT_MODE, secretKey, ctrIv);

	}

	public String encodeKey() throws NoSuchAlgorithmException, UnsupportedEncodingException {
//		sessionKey.getSecretKey();
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());

		// String base64encoded = sessionKey.encodeKey();
		// return base64encoded;
	}

	public String encodeIV() throws UnsupportedEncodingException {
		System.out.println(counter);
		return Base64.getEncoder().encodeToString(counter);

		// String encoded_IV = Base64.getEncoder().encodeToString(this.counter);
		// return encoded_IV;
	}

	public CipherOutputStream openCipherOutputStream(FileOutputStream fileOut)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnsupportedEncodingException {
		return new CipherOutputStream(fileOut, cipherText);

		/*
		 * int cipherMode = Cipher.ENCRYPT_MODE; Cipher cipher =
		 * Cipher.getInstance("AES/CTR/NoPadding"); SessionKey sKey = new
		 * SessionKey(this.ekey); cipher.init(cipherMode,
		 * sKey.getSecretKey(),this.ctrIv); CipherOutputStream cout = new
		 * CipherOutputStream(output,cipher); return cout;
		 */
	}
}
