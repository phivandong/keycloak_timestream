package com.pvdong.horseapimongodb.service;

import com.pvdong.horseapimongodb.dto.HorseDto;
import com.pvdong.horseapimongodb.entity.Horse;

import java.util.List;

public interface HorseService {
    List<Horse> findAllHorses();
    Horse createHorse(HorseDto horseDto);
    Horse findHorseById(String id);
    Horse update(String id, HorseDto horseDto);
    void deleteHorseById(String id);
}
