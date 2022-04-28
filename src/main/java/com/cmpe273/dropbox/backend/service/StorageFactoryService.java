package com.cmpe273.dropbox.backend.service;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.storage.Storage;
import com.google.api.services.storage.StorageScopes;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;

/** This class manages the details of creating a Storage service, including auth. */
// [START authentication_application_default_credentials]
public class StorageFactoryService {
  private static Storage instance = null;

  public static synchronized Storage getService() throws IOException, GeneralSecurityException {
    if (instance == null) {
      instance = buildService();
    }
    return instance;
  }

  private static Storage buildService() throws IOException, GeneralSecurityException {
    HttpTransport transport = GoogleNetHttpTransport.newTrustedTransport();
    JsonFactory jsonFactory = new JacksonFactory();
    //GoogleCredentials credential = GoogleCredentials.getApplicationDefault();
    GoogleCredentials credential = GoogleCredentials.fromStream(new FileInputStream("/Users/satyasameeradevu/Desktop/arboreal-height-273317-57289372ded5.json"));

   
    if (credential.createScopedRequired()) {
      Collection<String> scopes = StorageScopes.all();
      credential = credential.createScoped(scopes);
    }

    return new Storage.Builder(transport, jsonFactory, new HttpCredentialsAdapter(credential))
        .setApplicationName("arboreal-height-273317")
        .build();
  }
}
