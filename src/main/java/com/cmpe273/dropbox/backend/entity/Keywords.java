package com.cmpe273.dropbox.backend.entity;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Keywords {

	@Id
    String id;
	
	String name;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	
}
