package com.cmpe273.dropbox.backend.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cmpe273.dropbox.backend.entity.Keywords;
import com.cmpe273.dropbox.backend.repository.KeywordsRepository;

@Service
public class KeywordService {
	@Autowired
    private KeywordsRepository keywordsRepository;

    public void saveKeyword(Keywords file){
    	keywordsRepository.save(file);
    }
    
    public String findLargestID(){
    	return keywordsRepository.findLargestID();
    }
    
    public String findKeywordID(String keyword){
    	return keywordsRepository.findKeywordID(keyword);
    }
    
    public String findKeywordIDBySubstring(String keyword) {
    	return keywordsRepository.findKeywordIDBySubstring(keyword);
    }
}
