package com.pvdong.horseapimongodb.service;

import com.pvdong.horseapimongodb.dto.HorseDto;
import com.pvdong.horseapimongodb.entity.Horse;
import com.pvdong.horseapimongodb.entity.User;
import com.pvdong.horseapimongodb.repository.HorseRepository;
import com.pvdong.horseapimongodb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class HorseServiceImpl implements HorseService {
    private final HorseRepository horseRepository;
    private final UserRepository userRepository;

    @Override
    public List<Horse> findAllHorses() {
        return userRepository.findByUsername(getCurrentUsername()).getHorses();
    }

    @Override
    public Horse createHorse(HorseDto horseDto) {
        User user = userRepository.findByUsername(getCurrentUsername());
        Horse horse = new Horse();
        horse.setName(horseDto.getName());
        horse.setFoaled(horseDto.getFoaled());
        Horse savedHorse = horseRepository.save(horse);
        List<Horse> horseList = user.getHorses();
        if (horseList == null) {
            horseList = new ArrayList<>();
        }
        horseList.add(savedHorse);
        user.setHorses(horseList);
        userRepository.save(user);
        return savedHorse;
    }

    @Override
    public Horse findHorseById(String id) {
        return horseRepository.findById(id).orElseThrow(() -> new RuntimeException("Not found horse"));
    }

    @Override
    public Horse update(String id, HorseDto horseDto) {
        Horse horse = findHorseById(id);
        horse.setName(horseDto.getName());
        horse.setFoaled(horseDto.getFoaled());
        return horseRepository.save(horse);
    }

    @Override
    public void deleteHorseById(String id) {
        horseRepository.delete(findHorseById(id));
    }

    private String getCurrentUsername() {
        KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        Principal principal = (Principal) authentication.getPrincipal();
        if (principal instanceof KeycloakPrincipal) {
            return principal.getName();
        } else {
            throw new RuntimeException("No user");
        }
    }
}
