package com.cmpe273.dropbox.backend.utils;

import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.cmpe273.dropbox.backend.entity.Files;


public class DiffieHellmanSecretKey {

    private static final int AES_KEY_SIZE = 128;

    public static void main(String[] args) {
    	DiffieHellmanSecretKey dfsk = new DiffieHellmanSecretKey();
        // Generates keyPairs for Alice and Bob
        KeyPair kp1 = dfsk.genDHKeyPair();
        KeyPair kp2 = dfsk.genDHKeyPair();
        // Gets the public key of Alice(g^X mod p) and Bob (g^Y mod p)
        PublicKey pbk1 = kp1.getPublic();
        PublicKey pbk2 = kp2.getPublic();
        
        PrivateKey prk1 = kp1.getPrivate();
        PrivateKey prk2 = kp2.getPrivate();
        try {
            
            SecretKey key1 = dfsk.agreeSecretKey(prk1, pbk2,
                    true);
            SecretKey key2 = dfsk.agreeSecretKey(prk2, pbk1,
                    true);
           
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            // Init the cipher with Alice's key1
            c.init(Cipher.ENCRYPT_MODE, key1);
            // Compute the cipher text = E(key,plainText)
            byte[] ciphertext = c.doFinal("Stand and unfold yourself"
                    .getBytes());
            // prints ciphertext
            System.out.println("Encrypted: " + new String(ciphertext, "utf-8"));
            // inits the encryptionMode
            c.init(Cipher.DECRYPT_MODE, key2);
            // Decrypts and print
            System.out.println("Decrypted: "
                    + new String(c.doFinal(ciphertext), "utf-8"));
            System.out.println("Done");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPairGenerator kpg;

    static {
        try {
          
            kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public  SecretKey agreeSecretKey(PrivateKey prk_self,
            PublicKey pbk_peer, boolean lastPhase) throws Exception {
        // instantiates and inits a KeyAgreement
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(prk_self);
        // Computes the KeyAgreement
        ka.doPhase(pbk_peer, lastPhase);
        // Generates the shared secret
        byte[] secret = ka.generateSecret();

      

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); 
        byte[] bkey = Arrays.copyOf(
                sha256.digest(secret), AES_KEY_SIZE / Byte.SIZE);

        SecretKey desSpec = new SecretKeySpec(bkey, "AES");
        return desSpec;
    }

    public  KeyPair genDHKeyPair() {
        return kpg.genKeyPair();
    }
    
    public byte[] getDiffieHellmanSecretKeyToDecrypt(byte[] ciphertext, SecretKey key2) {
      
        Cipher c;
		
        
        byte[] original = null;
		try {
			c = Cipher.getInstance("AES/ECB/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE, key2);
			original = c.doFinal(ciphertext);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    
    return original;
}
    public static byte[] readAllBytes(InputStream inputStream) throws IOException {
        final int bufLen = 4 * 0x400; // 4KB
        byte[] buf = new byte[bufLen];
        int readLen;
        IOException exception = null;

        try {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                while ((readLen = inputStream.read(buf, 0, bufLen)) != -1)
                    outputStream.write(buf, 0, readLen);

                return outputStream.toByteArray();
            }
        } catch (IOException e) {
            exception = e;
            throw e;
        } finally {
            if (exception == null) inputStream.close();
            else try {
                inputStream.close();
            } catch (IOException e) {
                exception.addSuppressed(e);
            }
        }
    }
    public void decryptCipherToOriginal(InputStream fileIS, Files newFile) {
		String fn = "/Users/subashkumarsaladi/Downloads/GCS/"+newFile.getFilename();
		  File targetFile = new File(fn);
		  System.out.println("decrypt getFilename "+newFile.getFilename());
		  
		  byte[] keyBack = Base64.decodeBase64(newFile.getShared_key());
		  SecretKey desSpec = new SecretKeySpec(keyBack, "AES");
	    try (InputStream openIS = fileIS; OutputStream decryptedOutputStream = new FileOutputStream(targetFile)) {
	      while (true) {
	        try {
	          byte[] cipher = readAllBytes(openIS);
	          byte[] plainText = getDiffieHellmanSecretKeyToDecrypt(cipher, desSpec);
	          decryptedOutputStream.write(plainText);
	        } catch (EOFException e) {
	          break;
	        }
	      }
	    } catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	  
	}
}
