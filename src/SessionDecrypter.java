import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionDecrypter {

	Cipher cipherText;

	SessionDecrypter(String ekey, String eiv) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {
		SessionKey key = new SessionKey(ekey);
		byte[] ivdec = Base64.getDecoder().decode(eiv);
		IvParameterSpec ivspec = new IvParameterSpec(ivdec);
		cipherText = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipherText.init(Cipher.DECRYPT_MODE, key.getSecretKey(), ivspec);
	}

	public CipherInputStream openCipherInputStream(FileInputStream filein) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

		CipherInputStream cryptoin = new CipherInputStream(filein, cipherText);
		return cryptoin;
		/*
		 * Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); SessionKey
		 * skey = new SessionKey(secretKey); decryptCipher.init(Cipher.DECRYPT_MODE,
		 * skey.getSecretKey(), new IvParameterSpec(Base64.getDecoder().decode(iv)));
		 * return new CipherInputStream(input, decryptCipher);
		 */
	}

}
