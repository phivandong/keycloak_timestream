package com.pvdong.horseapimongodb.controller;

import com.pvdong.horseapimongodb.dto.ActivityResponse;
import com.pvdong.horseapimongodb.dto.ChangePasswordRequest;
import com.pvdong.horseapimongodb.dto.LoginRequest;
import com.pvdong.horseapimongodb.dto.SignupRequest;
import com.pvdong.horseapimongodb.entity.User;
import com.pvdong.horseapimongodb.service.UserService;
import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping(path = "/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping(path = "/{id}")
    public ResponseEntity<User> getAccountById(@PathVariable String id) {
        return new ResponseEntity<>(userService.findUserById(id), HttpStatus.OK);
    }

    @PostMapping(path = "/create")
    public ResponseEntity<User> registration(@RequestBody SignupRequest signupRequest) {
        return new ResponseEntity<>(userService.registration(signupRequest), HttpStatus.CREATED);
    }

    @PostMapping(path = "/register/{role}")
    public ResponseEntity<User> registrationBySocial(@PathVariable("role") String role) throws IOException {
        return new ResponseEntity<>(userService.registerUser(role), HttpStatus.CREATED);
    }

    @PutMapping(path = "/change-password")
    public ResponseEntity<User> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest) {
        return new ResponseEntity<>(userService.changePassword(changePasswordRequest), HttpStatus.ACCEPTED);
    }

    @PostMapping(path = "/login")
    public ResponseEntity<AccessTokenResponse> login(@RequestBody LoginRequest loginRequest) {
        return new ResponseEntity<>(userService.login(loginRequest), HttpStatus.OK);
    }

    @DeleteMapping(path = "/delete/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void hello(@PathVariable("id") String id) {
        userService.deleteUser(id);
    }

    @GetMapping(value = "/logout/{refresh_token}", produces = MediaType.APPLICATION_JSON_VALUE)
    public void logout(@PathVariable String refresh_token) {
        userService.logout(refresh_token);
    }

    @GetMapping(value = "/activity-history")
    public ResponseEntity<List<ActivityResponse>> getActivityHistory() {
        return new ResponseEntity<>(userService.getUserActivity(), HttpStatus.OK);
    }

    @GetMapping(value = "/google-login")
    public String googleLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        return userService.googleLogin(request);
//        response.sendRedirect(requestGot);
//        response.addCookie(new Cookie("OAuth_Token_Request_State", requestGot.substring(177, 213)));
    }

    @GetMapping(value = "/facebook-login")
    public void facebookLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(userService.facebookLogin(request));
    }
}
