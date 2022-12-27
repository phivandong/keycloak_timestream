package com.pvdong.horseapimongodb.controller;

import com.pvdong.horseapimongodb.dto.HorseDto;
import com.pvdong.horseapimongodb.entity.Horse;
import com.pvdong.horseapimongodb.service.HorseService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(path = "/api/horse")
@RequiredArgsConstructor
public class HorseController {
    private final HorseService horseService;

    @GetMapping(path = "/all")
    public ResponseEntity<List<Horse>> getAllHorse() {
        return new ResponseEntity<>(horseService.findAllHorses(), HttpStatus.OK);
    }

    @PostMapping(path = "/create")
    public ResponseEntity<Horse> createHorse(@RequestBody HorseDto horseDto) {
        return new ResponseEntity<>(horseService.createHorse(horseDto), HttpStatus.CREATED);
    }
}
