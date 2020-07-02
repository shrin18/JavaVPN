import java.io.*;
import javax.crypto.*;

public class TestSessionCrypto {
	static String PLAININPUT = "C:\\Users\\User\\Desktop\\java\\intsec\\src\\plainin.txt.txt";
	static String PLAINOUTPUT = "C:\\Users\\User\\Desktop\\java\\intsec\\src\\plainout.txt.txt";
	static String CIPHER = "C:\\Users\\User\\Desktop\\java\\intsec\\src\\cipher.txt.txt";
	static Integer KEYLENGTH = 128;

	public static void main(String[] args) throws Exception {
		int b;
		SessionEncrypter sessionencrypter = new SessionEncrypter(KEYLENGTH);

		try (CipherOutputStream cryptoout = sessionencrypter.openCipherOutputStream(new FileOutputStream(CIPHER));
				FileInputStream plainin = new FileInputStream(PLAININPUT);) {

			while ((b = plainin.read()) != -1) {
				cryptoout.write(b);
			}
		}
		SessionDecrypter sessiondecrypter = new SessionDecrypter(sessionencrypter.encodeKey(),
				sessionencrypter.encodeIV());
		try (CipherInputStream cryptoin = sessiondecrypter.openCipherInputStream(new FileInputStream(CIPHER));
				FileOutputStream plainout = new FileOutputStream(PLAINOUTPUT);) {
			while ((b = cryptoin.read()) != -1) {
				plainout.write(b);
			}
		}

		System.out.format(
				"Encryption and decryption done. Check that \"%s\" and \"%s\" are identical!\n", PLAININPUT, PLAINOUTPUT); 	                                                                         
	}

}
