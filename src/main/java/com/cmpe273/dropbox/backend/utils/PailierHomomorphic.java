package com.cmpe273.dropbox.backend.utils;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import java.nio.file.Path;
import com.cmpe273.dropbox.backend.entity.Files;

import java.io.*;

public class PailierHomomorphic {
	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	private BigInteger p, q, lambda;
	/**
	* n = p*q, where p and q are two large primes.
	*/
	public BigInteger n;
	/**
	* nsquare = n*n
	*/
	public BigInteger nsquare;
	/**
	* a random integer in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
	*/
	private BigInteger g;
	/**
	* number of bits of modulus
	*/
	private int bitLength;

	
	public PailierHomomorphic(int bitLengthVal, int certainty) {
	KeyGeneration(bitLengthVal, certainty);
	}

	/**
	* Constructs an instance of the Paillier cryptosystem with 1024 or 512 bits of modulus and at least 1-2^(-64) certainty of primes generation.
	*/
	public PailierHomomorphic() {
	KeyGeneration(512, 64);
	}

	
	public void KeyGeneration(int bitLengthVal, int certainty) {
	bitLength = bitLengthVal;
	
	p = new BigInteger(bitLength / 2, certainty, new Random());
	q = new BigInteger(bitLength / 2, certainty, new Random());

	n = p.multiply(q);
	nsquare = n.multiply(n);

	g = new BigInteger("2");
	lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
	p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
	/* check whether g is good.*/
	if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
	System.out.println("g is not good. Choose g again.");
	System.exit(1);
	}
	}

	public BigInteger Encryption(BigInteger m, BigInteger r) {
	return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
	}

	
	public BigInteger Encryption(BigInteger m) {
	BigInteger r = new BigInteger(bitLength, new Random());
	return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

	}

	
	public BigInteger Decryption(BigInteger c) {
	BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
	return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
	}
	
	
	


	
	  public static void main(String[] args) throws IOException {
		Random rp = new Random(); 
			Random rq = new Random();
	   
		  PailierHomomorphic paillier = new PailierHomomorphic();

	    
	    File file = new File("/Users/subashkumarsaladi/Downloads/sam1.txt");
	    InputStream in = new FileInputStream(new File("/Users/subashkumarsaladi/Downloads/sam1.txt"));
	    if (!file.exists()) {
	      System.out.println(args[0] + " does not exist.");
	      return;
	    }
	    if (!(file.isFile() && file.canRead())) {
	      System.out.println(file.getName() + " cannot be read from.");
	      return;
	    }
	    //paillier.encryptOriginalToCipher(paillier, file);
	    //paillier.decryptOriginalToCipher(paillier, file);
	  }

	public ObjectOutputStream encryptOriginalToCipher(PailierHomomorphic paillier, InputStream fileIS, Files newFile, Path plainTextFilePath) {
		/*
		 * ByteArrayOutputStream bOut = new ByteArrayOutputStream(); try { char msg;
		 * String m1; byte[] cipher = null; int i=0; newFile.setP(p.toString());
		 * System.out.println("encrypt p "+paillier.p); newFile.setQ(q.toString());
		 * System.out.println("encrypt q "+paillier.q);
		 * newFile.setLambda(lambda.toString());
		 * System.out.println("encrypt lambda "+paillier.lambda);
		 * newFile.setN(n.toString()); System.out.println("encrypt n "+paillier.n);
		 * newFile.setNsquare(nsquare.toString());
		 * System.out.println("encrypt nsquare "+paillier.nsquare);
		 * newFile.setG(g.toString()); System.out.println("encrypt g "+paillier.g);
		 * System.out.println("encrypt bitLength "+paillier.bitLength); while
		 * (fileIS.available() > 0) { msg = (char) fileIS.read();
		 * //System.out.print(msg);
		 * 
		 * m1=Character.toString(msg); System.out.print(m1);//plain text
		 * System.out.println("m1 "+m1+" m1 bytes length "+m1.getBytes().length);
		 * BigInteger bi = new BigInteger(m1.getBytes());
		 * 
		 * BigInteger em1 = paillier.Encryption(bi);
		 * 
		 * cipher = em1.toByteArray();
		 * System.out.println("cipher.length "+cipher.length); bOut.write(cipher); }
		 * bOut.close(); } catch (IOException e) { e.printStackTrace(); } return bOut;
		 */
		
		newFile.setP(p.toString());
		 
		newFile.setQ(q.toString());
		 
		 newFile.setLambda(lambda.toString());
		 
		 newFile.setN(n.toString()); 
		 
		 newFile.setNsquare(nsquare.toString());
		 //System.out.println("encrypt nsquare "+paillier.nsquare);
		 newFile.setG(g.toString()); System.out.println("encrypt g "+paillier.g);
		 //System.out.println("encrypt bitLength "+paillier.bitLength);
		
	    try (InputStream plainTextInputStream = fileIS;
	    		ObjectOutputStream encryptedOutputStream =
	           new ObjectOutputStream(java.nio.file.Files.newOutputStream(plainTextFilePath))) {
	    	System.out.println("plainTextInputStream "+plainTextInputStream.available());
	      while (plainTextInputStream.available() > 0) {
	        char plainText = (char) plainTextInputStream.read();

	        BigInteger plainTextBigInteger =
	          new BigInteger(Character.toString(plainText).getBytes(UTF_8));

	        BigInteger encryptedContent = paillier.Encryption(plainTextBigInteger);

	        encryptedOutputStream.writeObject(encryptedContent);
	      }
	      return encryptedOutputStream;
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    return null;
	}

	public void decryptOriginalToCipher(PailierHomomorphic paillier, InputStream fileIS, Files newFile) {
		/*
		 * ByteArrayOutputStream bOut = new ByteArrayOutputStream(); try { paillier.p =
		 * new BigInteger(newFile.getP()); System.out.println("decrypt p "+paillier.p);
		 * paillier.q = new BigInteger(newFile.getQ());
		 * System.out.println("decrypt q "+paillier.q); paillier.lambda = new
		 * BigInteger(newFile.getLambda());
		 * System.out.println("decrypt lambda "+paillier.lambda); paillier.n = new
		 * BigInteger(newFile.getN()); System.out.println("decrypt n "+paillier.n);
		 * paillier.nsquare = new BigInteger(newFile.getNsquare());
		 * System.out.println("decrypt nsquare "+paillier.nsquare); paillier.g = new
		 * BigInteger(newFile.getG()); System.out.println("decrypt g "+paillier.g);
		 * System.out.println("decrypt bitLength "+paillier.bitLength);
		 * 
		 * byte[] original = new byte[128];
		 * 
		 * //FileOutputStream out = new
		
		 * ;
		 * 
		 * //File files= new
		 * File("/Users/subashkumarsaladi/Desktop/HomomorphicEncrypted.txt");
		 * //FileInputStream input= new FileInputStream(files);
		 * 
		 * byte[] bytes = new byte[128];
		 * 
		 * while((fileIS.read(bytes)) != -1) { //byte array is now filled. Do something
		 * with it. System.out.println("bytes from decryption "+bytes.length);
		 * BigInteger bi = new BigInteger(bytes); original =
		 * paillier.Decryption(bi).toByteArray();
		 * System.out.println("original bytes from decryption "+original.toString());
		 * bOut.write(original); } fileIS.close(); //out.close(); } catch (IOException
		 * e) { e.printStackTrace(); } return bOut;
		 */
		
		String fn = "/Users/satyasameeradevu/Desktop/GCS_Testing/"+newFile.getFilename();
		  File targetFile = new File(fn);
		  System.out.println("decrypt getFilename "+newFile.getFilename());
		  System.out.println("decrypt getP "+newFile.getP());
		  paillier.p =
					 new BigInteger(newFile.getP()); //System.out.println("decrypt p "+paillier.p);
					  paillier.q = new BigInteger(newFile.getQ());
					  //System.out.println("decrypt q "+paillier.q); 
					  paillier.lambda = new
					  BigInteger(newFile.getLambda());
					  //System.out.println("decrypt lambda "+paillier.lambda); 
					  paillier.n = new
					  BigInteger(newFile.getN()); 
					  System.out.println("decrypt n "+paillier.n);
					  paillier.nsquare = new BigInteger(newFile.getNsquare());
					  //System.out.println("decrypt nsquare "+paillier.nsquare); 
					  paillier.g = new
					  BigInteger(newFile.getG()); System.out.println("decrypt g "+paillier.g);
					  //System.out.println("decrypt bitLength "+paillier.bitLength);
		
	    try (ObjectInputStream encryptedInputStream =
	    		new ObjectInputStream(fileIS);
	    		OutputStream decryptedOutputStream = new FileOutputStream(targetFile)) {
	      while (true) {
	        try {
	          BigInteger bigInteger = (BigInteger) encryptedInputStream.readObject();
	          byte[] plainText = paillier.Decryption(bigInteger).toByteArray();
	          decryptedOutputStream.write(plainText);
	        } catch (EOFException e) {
	          break;
	        } catch (ClassNotFoundException e) {
	          throw new RuntimeException(e);
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
public BigInteger encryptSearchWord(PailierHomomorphic paillier, String plainText, Files newFile, boolean encrypt, BigInteger decryptNum) {
		
		
		paillier.p =
				 new BigInteger(newFile.getP()); //System.out.println("decrypt p "+paillier.p);
				  paillier.q = new BigInteger(newFile.getQ());
				  //System.out.println("decrypt q "+paillier.q); 
				  paillier.lambda = new
				  BigInteger(newFile.getLambda());
				  //System.out.println("decrypt lambda "+paillier.lambda); 
				  paillier.n = new
				  BigInteger(newFile.getN()); 
				  //System.out.println("decrypt n "+paillier.n);
				  paillier.nsquare = new BigInteger(newFile.getNsquare());
				  //System.out.println("decrypt nsquare "+paillier.nsquare); 
				  paillier.g = new
				  BigInteger(newFile.getG()); //System.out.println("decrypt g "+paillier.g);
				  //System.out.println("decrypt bitLength "+paillier.bitLength);
		
	    
	    	
				  BigInteger returnedValue;
	        

	        if (encrypt) {
	        	int i = Integer.valueOf(plainText);
	        	 returnedValue = paillier.Encryption(BigInteger.valueOf(i));
	        } else {
	        	 returnedValue = paillier.Decryption(decryptNum);
	        }
	        
	      return returnedValue;
	    
	}

}
