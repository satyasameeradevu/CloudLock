package com.cmpe273.dropbox.backend.controller;

import com.cmpe273.dropbox.backend.entity.Userfiles;
import com.cmpe273.dropbox.backend.entity.Userlog;
import com.cmpe273.dropbox.backend.entity.Users;
import com.cmpe273.dropbox.backend.service.FileService;
import com.cmpe273.dropbox.backend.service.KeywordService;
import com.cmpe273.dropbox.backend.service.StorageFactoryService;
import com.cmpe273.dropbox.backend.service.UserFilesService;
import com.cmpe273.dropbox.backend.service.UserLogService;
import com.cmpe273.dropbox.backend.service.UserService;
import com.google.api.gax.paging.Page;
import com.google.api.services.storage.model.Objects;
import com.google.api.services.storage.model.StorageObject;
import com.google.auth.Credentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Acl;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.Acl.Role;
import com.google.cloud.storage.Acl.User;
import com.google.gson.Gson;
import com.cmpe273.dropbox.backend.utils.DiffieHellmanSecretKey;
import com.cmpe273.dropbox.backend.utils.PailierHomomorphic;
import com.cmpe273.dropbox.backend.utils.StorageUtils;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties.Hibernate;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Part;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.util.Base64;
import com.google.api.client.http.InputStreamContent;
import java.util.*;
import java.math.BigInteger;


@Controller    // This means that this class is a Controller
@CrossOrigin(origins = "http://localhost:3000")
@RequestMapping(path="/files") // This means URL's start with /demo (after Application path)
public class FileController {
    @Autowired
    private FileService fileService;

    @Autowired
    private UserFilesService userFilesService;

    @Autowired
    private UserLogService userLogService;

    @Autowired
    private UserService userService;
    
    @Autowired
    private KeywordService keywordService;
    
    private static final String metadataEmail = "email";
    private static final String metadataEmailValue = "subashskumar@hmail.com";
    private Map<String, String> newMetadata;
    
    
    

    
    private static String UPLOADED_FOLDER = /*System.getProperty("user.dir") + */"./public/uploads/";
    
    


    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = "application/json")
    public ResponseEntity<com.cmpe273.dropbox.backend.entity.Files> fileupload(@RequestParam("file") MultipartFile multipartFile,
                                                                               @RequestParam("fileparent") String fileparent, HttpSession session) throws JSONException, GeneralSecurityException {

        String email = (String) session.getAttribute("email");
       

        com.cmpe273.dropbox.backend.entity.Files newFile = new com.cmpe273.dropbox.backend.entity.Files();
        newMetadata = new HashMap<>();
        newMetadata.put(metadataEmail, email);
	    
	    String projectId = "arboreal-height-273317";

	    
	    String bucketName = "project-sam";
	    
        try {      	 
        	String filepath = "";
            if(!StringUtils.isEmpty(fileparent)){

                filepath = fileparent+"/" + multipartFile.getOriginalFilename();

            }
            else{
            	
                filepath =  email.split("\\.")[0] + "/" + multipartFile.getOriginalFilename();

            }

            
            
            /** uncomment this if you need to write file in selected folder
            byte[] bytes = multipartFile.getBytes();
            Path path = Paths.get(filepath);
            Files.write(path, bytes);**/
            Path tempFile = Files.createTempFile("tempfiles", ".txt");

            newFile.setFilename(multipartFile.getOriginalFilename());
            //System.out.println("upload file  filename " + newFile.getFilename());
            newFile.setFileparent(fileparent);
            newFile.setIsfile("T");
            newFile.setOwner(email);
            newFile.setSharedcount(0);
            newFile.setStarred("F");
            newFile.setFilepath(filepath);
    		 InputStream fileInputStreams = multipartFile.getInputStream();
    		 
    		 
    		 
    		
    		 PailierHomomorphic pailierHomomorphic = new PailierHomomorphic();
    		
    		 Path path = Paths.get(filepath);
    		 ObjectOutputStream bOutput  = pailierHomomorphic.encryptOriginalToCipher(pailierHomomorphic, fileInputStreams, newFile, tempFile);
    		 System.out.println("upload file  tempFile "+tempFile); 
    		 ObjectInputStream encryptedInputStream =
    		           new ObjectInputStream(Files.newInputStream(tempFile));
    		 
    		 InputStream fileInputStreamsFromPailier = Files.newInputStream(tempFile);
    		 System.out.println("fileInputStreamsFromPailier before GCS "+fileInputStreamsFromPailier.available());
    		 InputStream fileInputStreamsDB = multipartFile.getInputStream();
    		 
    		 Set<String> wordList = getDistinctWords(fileInputStreamsDB);
    		 
    		 int i = 1;
    		 
 	        for (String str : wordList) {
 	        	str.toLowerCase();
 	        	String wordIDFromDB = keywordService.findKeywordID(str);
 	        	if (wordIDFromDB == null || wordIDFromDB == "") {
 	        		 String largestIDFromDB = keywordService.findLargestID();
 	        		if(largestIDFromDB == null || largestIDFromDB == "") {
 	      			 i = i+1;
 	      			 System.out.println("largestIDFromDB is null");
 	      		 } else {
 	      			 i = Integer.valueOf(largestIDFromDB);
 	      			 System.out.println("largestIDFromDB is "+largestIDFromDB);
 	      			 i++;
 	      		 }
 	        		com.cmpe273.dropbox.backend.entity.Keywords kw = new com.cmpe273.dropbox.backend.entity.Keywords();
 	 	        	kw.setId(String.valueOf(i));
 	 	        	kw.setName(str);
 	 	        	keywordService.saveKeyword(kw);
 	 	        	newMetadata.put(String.valueOf(i), pailierHomomorphic.Encryption(BigInteger.valueOf(i)).toString());
 	 	        	i++;
 	        	} else {
 	        		 i = Integer.valueOf(wordIDFromDB);
 	        		newMetadata.put(String.valueOf(i), pailierHomomorphic.Encryption(BigInteger.valueOf(i)).toString());
 	        	    i++;
 	        	}
 	        }
  		    
             

             Credentials credentials = GoogleCredentials.fromStream(new FileInputStream("/Users/satyasameeradevu/Desktop/arboreal-height-273317-57289372ded5.json"));
				
             InputStreamContent mediaContent = new InputStreamContent("text/plain", fileInputStreamsFromPailier);
             com.google.api.services.storage.model.StorageObject content = new com.google.api.services.storage.model.StorageObject();
             content.setMetadata(newMetadata);
             com.google.api.services.storage.Storage storage = StorageFactoryService.getService();
             
             com.google.api.services.storage.Storage.Objects.Insert insertObject =
                 storage.objects().insert(bucketName, content, mediaContent).setName(newFile.getFilename());
             
             insertObject.getMediaHttpUploader().setDisableGZipContent(true);

            
             KeyGenerator keyGen = KeyGenerator.getInstance("AES");
             keyGen.init(256);
             SecretKey skey = keyGen.generateKey();
             String encryption_key = Base64.encodeBase64String(skey.getEncoded());
             MessageDigest digest = MessageDigest.getInstance("SHA-256");
             String encryption_key_sha256 = Base64.encodeBase64String(digest.digest(skey.getEncoded()));
             newFile.setEncryption_key(encryption_key);
             newFile.setEncryption_key_sha256(encryption_key_sha256);

         
             final  com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
             httpHeaders.set("x-goog-encryption-algorithm", "AES256");
             httpHeaders.set("x-goog-encryption-key", encryption_key);
             httpHeaders.set("x-goog-encryption-key-sha256", encryption_key_sha256);
             
             insertObject.setRequestHeaders(httpHeaders);

             try {
               insertObject.execute();
               //System.out.println("insertObject email: " + insertObject.get(metadataEmail));
             } catch (GoogleJsonResponseException e) {
               System.out.println("Error uploading: " + e.getContent());
               System.exit(1);
             }
              newFile.setFileContent(multipartFile.getBytes());
              fileService.uploadFile(newFile);
    		  
    		  Userfiles userfiles = new Userfiles();
    		  
    		  userfiles.setEmail(email); userfiles.setFilepath(filepath);
    		  
    		  
    		  userFilesService.addUserFile(userfiles);
    		  
    		  Userlog userlog = new Userlog();
    		  
    		  userlog.setAction("File Upload"); userlog.setEmail(email);
    		  userlog.setFilename(multipartFile.getOriginalFilename());
    		  userlog.setFilepath(filepath); userlog.setIsfile("F");
    		  userlog.setActiontime(new Date().toString());
    		  
    		  userLogService.addUserLog(userlog);
             
         } catch (IOException e) {
           
            e.printStackTrace();
            System.out.println("exception in servlet processing ");
            
                return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);

        } 
     // GCS end
        newFile.setFileContent(null);

        return new ResponseEntity<com.cmpe273.dropbox.backend.entity.Files>(newFile, HttpStatus.OK);
    }
    
    
    public static String saveFileContent(
    		   InputStream fis,
    		   String          encoding) throws IOException
    		 {
    		   try( BufferedReader br =
    		           new BufferedReader( new InputStreamReader(fis, encoding )))
    		   {
    		      StringBuilder sb = new StringBuilder();
    		      String line;
    		      while(( line = br.readLine()) != null ) {
    		         sb.append( line );
    		         sb.append( '\n' );
    		      }
    		      return sb.toString();
    		   }
    		   
    		}

    @GetMapping(path = "/getfolderfiles", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<com.cmpe273.dropbox.backend.entity.Files>> getFilesInFolder(@RequestParam String filepath) {

      

        List<com.cmpe273.dropbox.backend.entity.Files> filesList = fileService.getFileByFileparent(filepath);

        return new ResponseEntity(filesList, HttpStatus.OK);
    }

    @GetMapping(path = "/", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<com.cmpe273.dropbox.backend.entity.Files>> getUserFiles(HttpSession session) throws FileNotFoundException, IOException {

        String email = (String) session.getAttribute("email");
        if(email==null){
            return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);
        }
     
        
        

        List<String> objectsList = new ArrayList<>();
            
   		try {
   			String bucketNameNew = "project-sam";		 
   	   		com.google.api.services.storage.Storage storageNew = StorageFactoryService.getService();
   	   	objectsList = listObjects(storageNew, bucketNameNew, email);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
                    
        
        
        
        
		
		  List<Userfiles> userFilesList = userFilesService.getUserFilesByEmail(email);
		  
		  List<com.cmpe273.dropbox.backend.entity.Files> filesList = new ArrayList<>();
		  for (Userfiles userfiles : userFilesList) {
		  
		 com.cmpe273.dropbox.backend.entity.Files file =
		 fileService.getFileByFilepath(userfiles.getFilepath(), ""); if(file!=null)
		  filesList.add(file); }

		  Set<com.cmpe273.dropbox.backend.entity.Files> finalFilesList = new HashSet<>();
		  for(com.cmpe273.dropbox.backend.entity.Files dbFile : filesList) {
			  if(objectsList.contains(dbFile.getFilename())) {
				  dbFile.setFileContent(null);
				  finalFilesList.add(dbFile);
			  } 
		  }
		 

        return new ResponseEntity(finalFilesList, HttpStatus.OK);
    }

    
    
    @GetMapping(path = "/search", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<com.cmpe273.dropbox.backend.entity.Files>> searchUserFiles(@RequestParam String searchStr, HttpSession session) throws FileNotFoundException, IOException {

        String email = (String) session.getAttribute("email");
        if (searchStr == null || searchStr.isEmpty() ) {
        	return new ResponseEntity(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        if (searchStr.length() > 20) {
        	searchStr = searchStr.substring(0, 20);
        }
        searchStr.toLowerCase();
        // String wordIDFromDB = keywordService.findKeywordID(searchStr);
        
        //string split based on space 
        String[] multiWordSearch = searchStr.split("\\s+");
        
       
        
       
        
        if(email==null){
            return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);
        }
        
        
        List<String> objectsList = new ArrayList<>();
        String bucketNameNew = "project-sam";		 
	   		com.google.api.services.storage.Storage storageNew = null;
            
   		try {
   			storageNew =  StorageFactoryService.getService();
   	   	objectsList = listObjects(storageNew, bucketNameNew, email);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
   		System.out.println("objectsList size "+objectsList.size());
		
		  List<Userfiles> userFilesList = userFilesService.getUserFilesByEmail(email);
		  
		  List<com.cmpe273.dropbox.backend.entity.Files> filesList = new ArrayList<>();
			for (Userfiles userfiles : userFilesList) {

				com.cmpe273.dropbox.backend.entity.Files file = fileService.getFileByFilepath(userfiles.getFilepath(),
						"");
				if (file != null)
					filesList.add(file);
			}
		  
		  //System.out.println("filesList size "+filesList.size());

		  Set<com.cmpe273.dropbox.backend.entity.Files> finalFilesList = new HashSet<>();
		  for(int i=0;i<multiWordSearch.length;i++) {
			  String wordIDFromDB = keywordService.findKeywordIDBySubstring(multiWordSearch[i]);
			  System.out.println("multiWordSearch "+multiWordSearch[i]+" wordIDFromDB "+wordIDFromDB);
			  if (wordIDFromDB == null) {
		        	return new ResponseEntity(null, HttpStatus.INTERNAL_SERVER_ERROR);
		        }
			  for(com.cmpe273.dropbox.backend.entity.Files dbFile : filesList) {
				  if(objectsList.contains(dbFile.getFilename())) {
					  //listObjectsFromGCS(storageNew, bucketNameNew, email);
					  //check for filename match and get the p,q, r properties
					  boolean matchFound = false;
					try {
						matchFound = searchWordInlistObjects(listObjectsFromGCS(storageNew, bucketNameNew, email), email, wordIDFromDB, dbFile);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					  if (matchFound) {
						  finalFilesList.add(dbFile);
					  }
					  
				  } 
			  }
	        }
		  
		  
		  System.out.println("search list size"+finalFilesList.size());
		  for(com.cmpe273.dropbox.backend.entity.Files file : finalFilesList) {
			  fileService.updateSearchCount(file.getFilepath(), file.getSearchCount() + 1);
		  		if (file.getSearchCount() == 5) {
		  			//String bucketName = "project-sam";	
		         		try {
							deleteObject(storageNew, bucketNameNew, file.getFilename() , file.getEncryption_key(), file.getEncryption_key_sha256());
							System.out.println("file deleted since file searched 5 times  ");
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		         	    userFilesService.deleteUserFilesByFilepath(file.getFilepath());
		              fileService.deleteFile(file.getFilepath());
		  		}
		  }
		  
		  

        return new ResponseEntity(finalFilesList, HttpStatus.OK);
    }
    
    @PostMapping(path = "/delete", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> deleteFile(@RequestBody com.cmpe273.dropbox.backend.entity.Files file, HttpSession session) throws JSONException {
        System.out.println(file.getFilepath());

        String email = (String) session.getAttribute("email");

        if(email==null){
            return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);
        }

        //String filepath = UPLOADED_FOLDER + file.getOwner().split("\\.")[0] + "/" + file.getFilename();
        //filepath =  email.split("\\.")[0] + "/" + multipartFile.getOriginalFilename();
        String filepath = email.split("\\.")[0] + "/" + file.getFilename();
        //System.out.println("file controller  delete method filepath **** "+filepath);
        Path path = Paths.get(filepath);
        
        
        // The ID of your GCP project
	    String projectId = "arboreal-height-273317";

	    // The ID of your GCS bucket
	    String bucketName = "project-sam";

        // The ID of your GCS object
        // String objectName = "your-object-name";
        
        

        if (file.getOwner().equals(email)) {

            try {
            	//String bucketName = "project-sam";		 
           		com.google.api.services.storage.Storage storage = StorageFactoryService.getService();
           		deleteObject(storage, bucketName, file.getFilename() , file.getEncryption_key(), file.getEncryption_key_sha256());
            	


                Userlog userlog = new Userlog();


                userlog.setEmail(email);
                userlog.setFilename(file.getFilename());
                userlog.setFilepath(filepath);
                if(file.getIsfile().equals("T"))
                    userlog.setAction("File Delete");

                else
                    userlog.setAction("Folder Delete");

                userlog.setActiontime(new Date().toString());
                userlog.setIsfile(file.getIsfile());
                userLogService.addUserLog(userlog);
                
                

            } catch (IOException e) {
                e.printStackTrace();

                    return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);

            } catch (Exception e) {         	 
                e.printStackTrace();
                System.out.println("exception in servlet processing ");
                
            }
        } else {

            userFilesService.deleteUserFilesByEmailAndFilepath(file.getFilepath(), email);
            fileService.updateSharedCount(file.getFilepath(), file.getSharedcount() - 1);

        }

        return new ResponseEntity(null, HttpStatus.OK);

    }

    @PostMapping(path = "/sharefile", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> shareFile(@RequestBody String data, HttpSession session) throws JSONException {

        JSONObject jObject = new JSONObject(data);
        Gson gson = new Gson();
        JSONObject filedata = (JSONObject) jObject.get("filedata");
        com.cmpe273.dropbox.backend.entity.Files file = gson.fromJson(filedata.toString(), com.cmpe273.dropbox.backend.entity.Files.class);
        

        String email = (String) session.getAttribute("email");

        if(email==null){
            return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);
        }

		
        
        
        try {
   		 String bucketName = "project-sam";		 
   		com.google.api.services.storage.Storage storage = StorageFactoryService.getService();

     
            
            InputStream objectData =
                    downloadObject(storage, bucketName, file.getFilename() , file.getEncryption_key(), file.getEncryption_key_sha256());
            System.out.println("file received from GCS objectData ");
            PailierHomomorphic pailierHomomorphic = new PailierHomomorphic();
            
            		
            		if (file.getSharedcount()>=1) {
            			DiffieHellmanSecretKey dfsk = new DiffieHellmanSecretKey();
            			dfsk.decryptCipherToOriginal(objectData, file);
            			fileService.updateSharedCount(file.getFilepath(), file.getSharedcount() + 1);
                		if (file.getSharedcount() == 3) {
                			//String bucketName = "project-sam";	
                			System.out.println("shared file deleted since downloaded twice ");
                       		deleteObject(storage, bucketName, file.getFilename() , file.getEncryption_key(), file.getEncryption_key_sha256());
                       	    userFilesService.deleteUserFilesByFilepath(file.getFilepath());
                            fileService.deleteFile(file.getFilepath());
                		}
            		} else {
            			pailierHomomorphic.decryptOriginalToCipher(pailierHomomorphic, objectData, file);
            		}
            		
            
         } catch (Exception e) {         	 
             e.printStackTrace();
             System.out.println("exception in servlet processing ");
             
             
             
         }
   		

        return new ResponseEntity(null, HttpStatus.OK);

    }
    
    
    @PostMapping(path = "/sharefileEncryption", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> shareFileEncryption(@RequestBody String data, HttpSession session) throws JSONException {
    	long startTime = System.nanoTime();
    	System.out.println("File sharefileEncryption at client called successfully");
    	
    	System.out.println("Start time");
        JSONObject jObject = new JSONObject(data);
        Gson gson = new Gson();
        JSONObject filedata = (JSONObject) jObject.get("filedata");
        //String multipartFile = jObject.getString("file");
        com.cmpe273.dropbox.backend.entity.Files shareFile = gson.fromJson(filedata.toString(), com.cmpe273.dropbox.backend.entity.Files.class);
        String shareEmail = jObject.getString("shareEmail");
     // The ID of your GCS bucket
	    String bucketName = "project-sam";
	    String objectName = shareFile.getFilename();
	    String projectId = "arboreal-height-273317";

        Users user = userService.getUserDetails(shareEmail);
        com.cmpe273.dropbox.backend.entity.Files shareFileDB = null;
        
        if(user==null){

               return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);

        }

        String email = (String) session.getAttribute("email");

        if(email==null){
            return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);
        }
        String sharedFileName = null;
        try {
           
        	 shareFileDB = fileService.getFileByFilepath(shareFile.getFilepath(), shareFile.getFileparent());
        	 List<SecretKey> skList = getDiffieHellmanSecretKeys();
             
             SecretKey diffieHellmanSecretKeyToEncrypt = skList.get(0);
             SecretKey diffieHellmanSecretKeyToDecrypt = skList.get(1); 
             String shared_key_decrypt = Base64.encodeBase64String(diffieHellmanSecretKeyToDecrypt.getEncoded());
             byte[] cipher = getDiffieHellmanSecretKeyToEncrypt(shareFileDB.getFileContent(),diffieHellmanSecretKeyToEncrypt);
        InputStream fileInputStreamsDB = new ByteArrayInputStream(cipher);
        InputStreamContent mediaContent = new InputStreamContent("text/plain", fileInputStreamsDB);
        com.google.api.services.storage.model.StorageObject content = new com.google.api.services.storage.model.StorageObject();
        newMetadata = new HashMap<>();
        newMetadata.put(metadataEmail, shareEmail);
        content.setMetadata(newMetadata);
        com.google.api.services.storage.Storage storage = StorageFactoryService.getService();
        sharedFileName = "Shared_"+shareFileDB.getFilename();
        com.google.api.services.storage.Storage.Objects.Insert insertObject;
		
			insertObject = storage.objects().insert(bucketName, content, mediaContent).setName(sharedFileName);
		
        
        insertObject.getMediaHttpUploader().setDisableGZipContent(true);
        
 
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey skey = keyGen.generateKey();
        String encryption_key = Base64.encodeBase64String(skey.getEncoded());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String encryption_key_sha256 = Base64.encodeBase64String(digest.digest(skey.getEncoded()));
        
     
        final  com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
        httpHeaders.set("x-goog-encryption-algorithm", "AES256");
        httpHeaders.set("x-goog-encryption-key", encryption_key);
        httpHeaders.set("x-goog-encryption-key-sha256", encryption_key_sha256);
        
        insertObject.setRequestHeaders(httpHeaders);

        try {
          insertObject.execute();
          System.out.println("file uploaded succesfully ");
          
          com.cmpe273.dropbox.backend.entity.Files shareFileToSaveInDB = new com.cmpe273.dropbox.backend.entity.Files();
		  shareFileToSaveInDB.setEncryption_key(email);
		  shareFileToSaveInDB.setFilename(sharedFileName);
        
		  shareFileToSaveInDB.setFileparent(shareFileDB.getFileparent());
		  shareFileToSaveInDB.setIsfile("T");
		  shareFileToSaveInDB.setOwner(shareEmail);
		  shareFileToSaveInDB.setSharedcount(1);
		  shareFileToSaveInDB.setStarred("F");
		  shareFileToSaveInDB.setFilepath(shareEmail+sharedFileName);
		  shareFileToSaveInDB.setEncryption_key(encryption_key);
		  shareFileToSaveInDB.setEncryption_key_sha256(encryption_key_sha256);
		  shareFileToSaveInDB.setShared_key(shared_key_decrypt);
		  fileService.uploadFile(shareFileToSaveInDB);
          
        } catch (GoogleJsonResponseException e) {
          System.out.println("Error uploading: " + e.getContent());
          System.exit(1);
        }
        } catch (IOException | GeneralSecurityException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
//     
        
		  Userfiles userfiles = new Userfiles();
		  
		  userfiles.setEmail(shareEmail); userfiles.setFilepath(shareEmail+sharedFileName);
		  
		  userFilesService.addUserFile(userfiles);
		  
		  fileService.updateSharedCount(shareEmail+sharedFileName, shareFile.getSharedcount() + 1);
		  
		 
		  
		 Userlog userlog = new Userlog();
		 
		 userlog.setEmail(email); userlog.setFilename(sharedFileName);
		 userlog.setFilepath(shareEmail+sharedFileName); if(shareFile.getIsfile().equals("T"))
		 userlog.setAction("File shared with "+shareEmail);
		 
		 else userlog.setAction("Folder shared with "+shareEmail);
		 
		 userlog.setActiontime(new Date().toString());
		 userlog.setIsfile(shareFile.getIsfile()); userLogService.addUserLog(userlog);
		 long endTime = System.nanoTime();
		 System.out.println("end time"+endTime);
		 System.out.println("total time"+(endTime-startTime));
        return new ResponseEntity(null, HttpStatus.OK);

    }
    
    public List<SecretKey> getDiffieHellmanSecretKeys() {
    	DiffieHellmanSecretKey dfsk = new DiffieHellmanSecretKey();
        // Generates keyPairs for Alice and Bob
        KeyPair kp1 = dfsk.genDHKeyPair();
        KeyPair kp2 = dfsk.genDHKeyPair();
        // Gets the public key of Alice(g^X mod p) and Bob (g^Y mod p)
        PublicKey pbk1 = kp1.getPublic();
        PublicKey pbk2 = kp2.getPublic();
        // Gets the private key of Alice X and Bob Y
        PrivateKey prk1 = kp1.getPrivate();
        PrivateKey prk2 = kp2.getPrivate();
        SecretKey key1 = null;
        SecretKey key2 = null;
        List<SecretKey> skList = new ArrayList<>();
        try {
            
             key1 = dfsk.agreeSecretKey(prk1, pbk2,
                    true);
             key2 = dfsk.agreeSecretKey(prk2, pbk1,
                    true);
  
            skList.add(key1);
            skList.add(key2);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return skList;
    }
    
    public byte[] getDiffieHellmanSecretKeyToEncrypt(byte[] originalData, SecretKey key1) {
    	byte[] ciphertext = null;
    	try {    
    	
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
           
            c.init(Cipher.ENCRYPT_MODE, key1);
            
            ciphertext = c.doFinal(originalData);
           
            System.out.println("Encrypted: " + new String(ciphertext, "utf-8"));
    	} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        return ciphertext;
    }
    
    
    

    public Set<String> getDistinctWords(InputStream fileIS) {

        Set<String> wordSet = new HashSet<>();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(fileIS))) {

            String line;

            while ((line = br.readLine()) != null) {

                StringTokenizer st = new StringTokenizer(line, " ,.;:\"");

                while (st.hasMoreTokens()) {

                    wordSet.add(st.nextToken().toLowerCase());

                }

            }

        } catch (IOException e) {

           e.printStackTrace();

        }

        return wordSet;

    }
    
    public static InputStream downloadObject(
    		com.google.api.services.storage.Storage storage,
    	      String bucketName,
    	      String objectName,
    	      String base64CseKey,
    	      String base64CseKeyHash)
    	      throws Exception {

    	   
    	    final com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
    	    httpHeaders.set("x-goog-encryption-algorithm", "AES256");
    	    httpHeaders.set("x-goog-encryption-key", base64CseKey);
    	    httpHeaders.set("x-goog-encryption-key-sha256", base64CseKeyHash);

    	    com.google.api.services.storage.Storage.Objects.Get getObject = storage.objects().get(bucketName, objectName);
    	    

    	    getObject.setRequestHeaders(httpHeaders);
    	 

    	    try {
    	      return getObject.executeMediaAsInputStream();
    	    } catch (GoogleJsonResponseException e) {
    	      System.out.println("Error downloading: " + e.getContent());
    	      System.exit(1);
    	      return null;
    	    }
    	  }
    
    public static void deleteObject(
    		com.google.api.services.storage.Storage storage,
    	      String bucketName,
    	      String objectName,
    	      String base64CseKey,
    	      String base64CseKeyHash)
    	      throws Exception {

    	  
    	    final com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
    	    httpHeaders.set("x-goog-encryption-algorithm", "AES256");
    	    httpHeaders.set("x-goog-encryption-key", base64CseKey);
    	    httpHeaders.set("x-goog-encryption-key-sha256", base64CseKeyHash);

    	    com.google.api.services.storage.Storage.Objects.Delete deleteObject = storage.objects().delete(bucketName, objectName);

    	   

    	    deleteObject.setRequestHeaders(httpHeaders);

    	    try {
    	       deleteObject.execute();
    	    } catch (GoogleJsonResponseException e) {
    	      System.out.println("Error downloading: " + e.getContent());
    	      System.exit(1);
    	    }
    	  }
    
    public static List<String> listObjects(
    		com.google.api.services.storage.Storage storage,
    	      String bucketName, String userEmail)
    	      throws Exception {

    	    // Set the CSEK headers
    	    final com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
    	    httpHeaders.set("x-goog-encryption-algorithm", "AES256");
    	   

    	    com.google.api.services.storage.Storage.Objects.List listOfObjects = storage.objects().list(bucketName);

    	    
    	    List<String> filesList = new ArrayList<String>();
    	    Objects finalListObjects =new Objects();

    	    try {
    	    	Objects returnedObjects = listOfObjects.execute();
    	    	for (StorageObject obj : returnedObjects.getItems()) {
    	           
    	              if(null != obj.getMetadata()) {
    	            	  
    	            	  if((obj.getMetadata().get("email")!=null && obj.getMetadata().get("email").equalsIgnoreCase(userEmail))||(obj.getMetadata().get("sharedEmail")!=null &&  obj.getMetadata().get("sharedEmail").equalsIgnoreCase(userEmail))) {
    	            		  filesList.add(obj.getName());
    	            		  
    	            	  }
    	            	  
    	              }
    	              
    	            }
    	    	
    	    } catch (GoogleJsonResponseException e) {
    	      System.out.println("Error downloading: " + e.getContent());
    	      System.exit(1);
    	    }
    	    return filesList;
    	  }
    
    public static List<String> getlistObjectsForShare(
    		com.google.api.services.storage.Storage storage,
    	      String bucketName, String userEmail)
    	      throws Exception {

    	   
    	    final com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
    	    httpHeaders.set("x-goog-encryption-algorithm", "AES256");
    	

    	    com.google.api.services.storage.Storage.Objects.List listOfObjects = storage.objects().list(bucketName);

    	    
    	    
    	    List<String> filesList = new ArrayList<String>();
    	    Objects finalListObjects =new Objects();

    	    try {
    	    	Objects returnedObjects = listOfObjects.execute();
    	    	for (StorageObject obj : returnedObjects.getItems()) {
    	          
    	              if(null != obj.getMetadata()) {
    	            	  //System.out.println("metaData from list key ** "+ obj.getMetadata().get("email"));
    	            	  if(obj.getMetadata().get("email").equalsIgnoreCase(userEmail)) {
    	            		  filesList.add(obj.getName());
    	            		  //finalListObjects.getItems().add(obj);
    	            	  }
    	            	  
    	              }
    	              
    	            }
    	    	
    	    } catch (GoogleJsonResponseException e) {
    	      System.out.println("Error downloading: " + e.getContent());
    	      System.exit(1);
    	    }
    	    return filesList;
    	  }
    
    public static com.google.api.services.storage.model.Objects listObjectsFromGCS(
    		com.google.api.services.storage.Storage storage,
    	      String bucketName, String userEmail)
    	      throws Exception {
    	Objects returnedObjects = null;

    	    // Set the CSEK headers
    	    final com.google.api.client.http.HttpHeaders httpHeaders = new com.google.api.client.http.HttpHeaders();
    	    httpHeaders.set("x-goog-encryption-algorithm", "AES256");
    	   
    	    com.google.api.services.storage.Storage.Objects.List listOfObjects = storage.objects().list(bucketName);

    	    
    	    List<String> filesList = new ArrayList<String>();

    	    try {
    	    	 returnedObjects = listOfObjects.execute();
    	    	
    	    } catch (GoogleJsonResponseException e) {
    	      System.out.println("Error downloading: " + e.getContent());
    	      System.exit(1);
    	    }
    	    System.out.println("returnedObjects size "+returnedObjects.size());
    	    return returnedObjects;
    	  }
    
    public static boolean searchWordInlistObjects(com.google.api.services.storage.model.Objects listOfObjectsFromGCS,
    		String userEmail, String wordIDFromDB, com.cmpe273.dropbox.backend.entity.Files fileDB)
    	      throws Exception {

    	Objects returnedObjects = listOfObjectsFromGCS;
    	List<StorageObject> userObjects = new ArrayList<StorageObject>();
    	    
    	    boolean matchFound = false;

    	    try {
    	    	for (StorageObject obj : returnedObjects.getItems()) {
    	              if(null != obj.getMetadata()) {
    	            	  if(obj.getMetadata().get("email").equalsIgnoreCase(userEmail)) {
    	            		  userObjects.add(obj);
    	            	  }
    	              }
    	            }
    	    	System.out.println("userObjects size "+userObjects.size());
    	    	 PailierHomomorphic pailierHomomorphic = new PailierHomomorphic();
    	    	BigInteger EncryptedSearchWord = pailierHomomorphic.encryptSearchWord(pailierHomomorphic, wordIDFromDB, fileDB, true, null );
    	    	for (StorageObject obj : userObjects) {
  	              //System.out.println(obj.getName());
  	              //System.out.println("email from list key ** "+ obj.get("email"));
  	              if(null != obj.getMetadata()) {
  	            	  //System.out.println("metaData from list key ** "+ obj.getMetadata().get("email"));
  	            	  if(obj.getName().equalsIgnoreCase(fileDB.getFilename())) {
  	            		  //get file p,q,r
  	            		if(obj.getMetadata().get(wordIDFromDB) != null) {
    	            		  //System.out.println("metaData from list key ** "+ obj.getMetadata().get(wordIDFromDB));
    	            		  BigInteger EncryptedFileWord = new BigInteger(obj.getMetadata().get(wordIDFromDB));
    	            		  //Calculating the product with the i
    	            		  BigInteger nsquare = new BigInteger(fileDB.getNsquare());
    	            		  BigInteger i = new BigInteger(wordIDFromDB);
    	            	        BigInteger prod2=EncryptedFileWord.modPow(i, nsquare).mod(nsquare);
    	            	        BigInteger prod=EncryptedSearchWord.modPow(i, nsquare).mod(nsquare);
    	            	        BigInteger multiplication2=pailierHomomorphic.encryptSearchWord(pailierHomomorphic, wordIDFromDB, fileDB, false, prod2);
    	            	        BigInteger multiplication1=pailierHomomorphic.encryptSearchWord(pailierHomomorphic, wordIDFromDB, fileDB, false, prod);
    	            	        int multi1=multiplication1.intValue();
    	            	        int multi2=multiplication2.intValue();
    	            	        System.out.println("multi1 "+multi1);
    	            	        System.out.println("multi2 "+multi2);
    	            	        if(multi1 == multi2) {
    	            	        	matchFound = true;
    	            	        	break;
    	            	        }
    	            	  }
  	            
  	            	  }
  	              }
  	              
  	            }
    	    	
    	    } catch (Exception e) {
    	      e.printStackTrace();
    	      System.exit(1);
    	    }
    	    return matchFound;
    	  }

    @PostMapping(path = "/makefolder", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<com.cmpe273.dropbox.backend.entity.Files> makeFolder(@RequestBody String data, HttpSession session) throws JSONException, IOException {

        JSONObject jObject = new JSONObject(data);
        String folderName = jObject.getString("filename");
        String folderparent = jObject.getString("fileparent");
        String email = (String) session.getAttribute("email");

        if(email==null){
            return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);
        }

        //String folderpath = UPLOADED_FOLDER + email.split("\\.")[0]+"/"+folderName;
        String folderpath =  email.split("\\.")[0]+"/"+folderName;

        com.cmpe273.dropbox.backend.entity.Files file= new com.cmpe273.dropbox.backend.entity.Files();

        file.setFilename(folderName);
        file.setFilepath(folderpath);
        file.setSharedcount(0);
        file.setOwner(email);
        file.setFileparent(folderparent);
        file.setStarred("F");
        file.setIsfile("F");

        Path path = Paths.get(folderpath);
        Files.createDirectories(path);

        fileService.uploadFile(file);

        Userfiles userfiles = new Userfiles();

        userfiles.setEmail(email);
        userfiles.setFilepath(folderpath);

        userFilesService.addUserFile(userfiles);

        Userlog userlog = new Userlog();

        userlog.setEmail(email);
        userlog.setFilename(file.getFilename());
        userlog.setFilepath(file.getFilepath());
        userlog.setAction("Make Folder");
        userlog.setActiontime(new Date().toString());
        userlog.setIsfile("F");
        userLogService.addUserLog(userlog);


        return new ResponseEntity(file, HttpStatus.OK);

    }

    @PostMapping(path = "/star", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> starFile(@RequestBody String data) throws JSONException {

        JSONObject jObject = new JSONObject(data);
        String filepath = jObject.getString("filepath");
        String starred = jObject.getString("starred");

        fileService.markStar(filepath, starred);
        return new ResponseEntity(null, HttpStatus.OK);

    }

    @GetMapping(path = "/{filename}"/*, produces = MediaType.APPLICATION_JSON_VALUE*/)
    public ResponseEntity<InputStreamResource> downloadFile(@RequestParam String filepath, @PathVariable("filename") String filename) {

        File file2Upload = new File(filepath);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
        headers.set(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=" + filename.replace(" ", "_"));
        headers.add("Pragma", "no-cache");
        headers.add("Expires", "0");
        InputStreamResource resource = null;
        try {
            resource = new InputStreamResource(new FileInputStream(file2Upload));
        } catch (FileNotFoundException e) {
            e.printStackTrace();

                return new ResponseEntity(null, HttpStatus.UNAUTHORIZED);

        }

        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(file2Upload.length())
                .contentType(MediaType.parseMediaType("application/octet-stream"))
                .body(resource);
    }

}