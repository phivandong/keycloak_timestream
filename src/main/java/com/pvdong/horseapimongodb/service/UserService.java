package com.pvdong.horseapimongodb.service;

import com.pvdong.horseapimongodb.dto.ActivityResponse;
import com.pvdong.horseapimongodb.dto.ChangePasswordRequest;
import com.pvdong.horseapimongodb.dto.LoginRequest;
import com.pvdong.horseapimongodb.dto.SignupRequest;
import com.pvdong.horseapimongodb.entity.User;
import org.keycloak.representations.AccessTokenResponse;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

public interface UserService {
    User findUserById(String id);
    User registration(SignupRequest signupRequest);
    User changePassword(ChangePasswordRequest changePasswordRequest);
    void deleteUser(String id);
    AccessTokenResponse login(LoginRequest jwtRequest);
    void logout(String refreshToken);
    List<ActivityResponse> getUserActivity();
    User registerUser(String role) throws IOException;
    String googleLogin(HttpServletRequest request);
    String facebookLogin(HttpServletRequest request);
}
