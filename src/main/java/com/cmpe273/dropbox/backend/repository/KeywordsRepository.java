package com.cmpe273.dropbox.backend.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.cmpe273.dropbox.backend.entity.Keywords;

public interface KeywordsRepository extends CrudRepository<Keywords, Long>{
	
	@Transactional
    @Query(value = "SELECT id FROM cmpe273.keywords order by id desc limit 1", nativeQuery = true)
    String findLargestID();
	
	@Transactional
    @Query(value = "SELECT id FROM cmpe273.keywords k where k.name = :keyword", nativeQuery = true)
	String findKeywordID(@Param("keyword") String keyword);
	
	@Transactional
    @Query(value = "SELECT id FROM cmpe273.keywords k where k.name like %:keyword%", nativeQuery = true)
	String findKeywordIDBySubstring(@Param("keyword") String keyword);

}
