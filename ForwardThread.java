/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */
 
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
 
public class ForwardThread extends Thread
{
private static final int READ_BUFFER_SIZE = 8192;

private  Cipher cipher;

private String a;
private  SecretKey originalKey;
private  IvParameterSpec ivParams;
 
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
 
    ForwardServerClientThread mParent = null;
 
    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream, String num)   
    {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
        a= num;		
	
    }
    public CipherOutputStream openCipherOutputStream(OutputStream output) 
    {   
  	  CipherOutputStream cout = new CipherOutputStream(output,cipher);
  	  return cout;
  	}
    public CipherInputStream openCipherInputStream(InputStream input) 
	{	
    	CipherInputStream cin = new CipherInputStream(input,cipher);
		return cin;
		}
   
    public void setSecretKey(SecretKey secretKey,IvParameterSpec iv) {
    	this.originalKey = secretKey;
    	this.ivParams=iv;
    }
    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run()
    {    
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        if (a == "1") {
        	
		try {
			cipher = Cipher.getInstance("AES/CTR/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}			
	    try {
			cipher.init(Cipher.ENCRYPT_MODE,originalKey,ivParams);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try	(CipherOutputStream cryptoout = openCipherOutputStream(mOutputStream))		           
		{      while (true) {
                int bytesRead = mInputStream.read(buffer);
                if (bytesRead == -1)
                    break; // End of stream is reached --> exit the thread
                cryptoout.write(buffer, 0, bytesRead);
            }}
         catch (IOException e) {
            // Read/write failed --> connection is broken --> exit the thread
        }}
        
        
		else if (a == "2"){
        	try {
				cipher = Cipher.getInstance("AES/CTR/NoPadding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
           try {
        	   
			   cipher.init(Cipher.DECRYPT_MODE,originalKey,ivParams);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        	
        	try(CipherInputStream cryptoin = openCipherInputStream(mInputStream))
        {
            while (true) {
                int bytesRead = cryptoin.read(buffer);
                if (bytesRead == -1)
                    break; // End of stream is reached --> exit the thread
                mOutputStream.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            // Read/write failed --> connection is broken --> exit the thread
        }
		}
        // Notify parent thread that the connection is broken and forwarding should stop
        mParent.connectionBroken();
    } 
}
