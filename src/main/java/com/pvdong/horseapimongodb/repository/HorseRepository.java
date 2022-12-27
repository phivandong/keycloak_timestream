package com.pvdong.horseapimongodb.repository;

import com.pvdong.horseapimongodb.entity.Horse;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HorseRepository extends MongoRepository<Horse, String> {
    boolean existsByName(String name);
    Horse getByName(String name);
}
