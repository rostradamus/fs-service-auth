package com.fitsight.fsserviceauth.controller;

import com.fitsight.fsserviceauth.messageq.envelop.UserMessage;
import com.fitsight.fsserviceauth.controller.payload.JWTResponse;
import com.fitsight.fsserviceauth.controller.payload.LoginRequest;
import com.fitsight.fsserviceauth.controller.payload.RegistrationRequest;
import com.fitsight.fsserviceauth.model.ERole;
import com.fitsight.fsserviceauth.model.RefreshToken;
import com.fitsight.fsserviceauth.model.User;
import com.fitsight.fsserviceauth.security.jwt.JWTUtils;
import com.fitsight.fsserviceauth.security.service.UserDetailsImpl;
import com.fitsight.fsserviceauth.security.service.UserDetailsServiceImpl;
import com.mongodb.lang.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@Slf4j
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JWTUtils jwtUtils;
    @Autowired
    MongoTemplate mongoTemplate;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    @Autowired
    KafkaTemplate<String, UserMessage> userKafkaTemplate;

    @PostMapping
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            String jwt;
            try {
                jwt = jwtUtils.generateJwtToken(userDetails);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            User user = mongoTemplate.findById(userDetails.getId(), User.class);
            this.processRefreshToken(response, userDetails.getUsername());
            return ResponseEntity.ok(new JWTResponse(jwt, userDetails.getId(), userDetails.getUsername(), roles, user));
        } catch (AuthenticationException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }

    @DeleteMapping
    public ResponseEntity<?> logout(@Nullable @CookieValue(value = "refresh_token") String refreshTokenId, HttpServletResponse response) {
        if (refreshTokenId != null) {
            mongoTemplate.remove(Query.query(Criteria.where("id").is(refreshTokenId)), RefreshToken.class);
            Cookie refreshTokenCookie = new Cookie("refresh_token", null);
            refreshTokenCookie.setMaxAge(0); // immediately expire
            refreshTokenCookie.setPath("/");
            response.addCookie(refreshTokenCookie);
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
        if (mongoTemplate.exists(Query.query(Criteria.where("email").is(registrationRequest.getEmail())), User.class)) {
            return ResponseEntity.unprocessableEntity().build();
        }
        User user = User
                .builder()
                .email(registrationRequest.getEmail())
                .password(passwordEncoder.encode(registrationRequest.getPassword()))
                .roles(new HashSet<>(Collections.singletonList(ERole.ROLE_USER)))
                .build();

        mongoTemplate.insert(user);

        userKafkaTemplate.send("fs-user-topic", registrationRequest.toMessage());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@CookieValue(value = "refresh_token") String refreshTokenId,
                                          HttpServletRequest request, HttpServletResponse response) {
        if (refreshTokenId != null) {
            RefreshToken existingToken = mongoTemplate.findById(refreshTokenId, RefreshToken.class);

            String username = Objects.requireNonNull(existingToken).getUsername();
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt;
            try {
                jwt = jwtUtils.generateJwtToken(userDetails);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            mongoTemplate.remove(Query.query(Criteria.where("id").is(refreshTokenId)), RefreshToken.class);
            this.processRefreshToken(response, username);
            User user = mongoTemplate.findById(userDetails.getId(), User.class);

            return ResponseEntity.ok(new JWTResponse(jwt, userDetails.getId(), userDetails.getUsername(), roles, user));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    private void processRefreshToken(HttpServletResponse response, String jwtId) {
        RefreshToken refreshToken = mongoTemplate.insert(new RefreshToken(jwtId));
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken.getId());
        refreshTokenCookie.setMaxAge(24 * 60 * 60); // expires in 7 days
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
//    refreshTokenCookie.setSecure(true); // TODO: Enable this when deploy to production is ready
        response.addCookie(refreshTokenCookie);
    }
}
