package com.cmpe273.dropbox.backend.entity;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.util.Random;
import java.io.InputStream;
import java.sql.Blob;

@Entity
public class Files {

    String filename;

    @Id
    String filepath;

    String fileparent;

    String isfile;

    String owner;

    String starred;

    Integer sharedcount;
    
    Integer searchcount;
    
    String encryption_key;
    
    String encryption_key_sha256;
    
    byte[] fileContent;
    
    String p;

	String q;
	
	String g;

	String n;
	
	String lambda;

	String nsquare;
	
	 String shared_key;

	public String getShared_key() {
		return shared_key;
	}

	public void setShared_key(String shared_key) {
		this.shared_key = shared_key;
	}

	public String getP() {
		return p;
	}

	public void setP(String p) {
		this.p = p;
	}

	public String getQ() {
		return q;
	}

	public void setQ(String q) {
		this.q = q;
	}

	public String getG() {
		return g;
	}

	public void setG(String g) {
		this.g = g;
	}

	public String getN() {
		return n;
	}

	public void setN(String n) {
		this.n = n;
	}

	public String getLambda() {
		return lambda;
	}

	public void setLambda(String lambda) {
		this.lambda = lambda;
	}

	public String getNsquare() {
		return nsquare;
	}

	public void setNsquare(String nsquare) {
		this.nsquare = nsquare;
	}

	public byte[] getFileContent() {
		return fileContent;
	}

	public void setFileContent(byte[] fileContent) {
		this.fileContent = fileContent;
	}

	public String getEncryption_key() {
		return encryption_key;
	}

	public void setEncryption_key(String encryption_key) {
		this.encryption_key = encryption_key;
	}

	public String getEncryption_key_sha256() {
		return encryption_key_sha256;
	}

	public void setEncryption_key_sha256(String encryption_key_sha256) {
		this.encryption_key_sha256 = encryption_key_sha256;
	}

	public String getStarred() {
        return starred;
    }

    public Integer getSharedcount() {
        return sharedcount;
    }

    public void setSharedcount(Integer sharedcount) {
        this.sharedcount = sharedcount;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public void setStarred(String starred) {
        this.starred = starred;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getFilepath() {
        return filepath;
    }

    public void setFilepath(String filepath) {
        this.filepath = filepath;
    }

    public String getFileparent() {
        return fileparent;
    }

    public void setFileparent(String fileparent) {
        this.fileparent = fileparent;
    }

    public String getIsfile() {
        return isfile;
    }

    public void setIsfile(String isfile) {
        this.isfile = isfile;
    }

	public Integer getSearchCount() {
		return searchcount;
	}

	public void setSearchCount(Integer searchCount) {
		this.searchcount = searchCount;
	}
}