import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

public class VerifyCertificate {
	public static boolean CheckCertificate(X509Certificate CA509, X509Certificate USER509) throws InvalidKeyException,
			CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		//X500Principal issuerCA = CA509.getIssuerX500Principal();
		X500Principal subjectCA = CA509.getSubjectX500Principal();
		//X500Principal issuerUser = USER509.getIssuerX500Principal();
		X500Principal subjectUser = USER509.getSubjectX500Principal();

		PublicKey publickeyCA = CA509.getPublicKey();

		CA509.verify(publickeyCA);
		
		System.out.println("Verify CA");
		System.out.println("DN" + subjectCA);
		CA509.checkValidity();
		System.out.println("Valid CA");
		
		USER509.verify(publickeyCA);
		
		System.out.println("Verify User");
		System.out.println("DN" + subjectUser);
		USER509.checkValidity();
		System.out.println("Valid User");
		return true;
	}

	public static void main(String[] args) throws FileNotFoundException, CertificateException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		FileInputStream CAfile = new FileInputStream(args[0]);
		FileInputStream Userfile = new FileInputStream(args[1]);

		CertificateFactory cfCA = CertificateFactory.getInstance("X.509");
		CertificateFactory cfUser = CertificateFactory.getInstance("X.509");

		Certificate cCA = cfCA.generateCertificate(CAfile);
		Certificate cUser = cfUser.generateCertificate(Userfile);

		X509Certificate CA509 = (X509Certificate) cCA;
		X509Certificate USER509 = (X509Certificate) cUser;

		if (CheckCertificate(CA509, USER509) == true) {
			System.out.println("pass");

		} else {
			System.out.println("fail");
		}
	}
}
