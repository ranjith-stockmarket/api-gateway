package com.stockmarket.apigateway;

import com.stockmarket.apigateway.JWT.AuthenticationRequest;
import com.stockmarket.apigateway.JWT.AuthenticationResponse;
import com.stockmarket.apigateway.JWT.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {
    private final AuthenticationManager authenticationManager;
    private final UserService userDetailService;
    private final JwtUtil jwtUtil;

    public UserController(AuthenticationManager authenticationManager, UserService userDetailService, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userDetailService = userDetailService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/home")
    public ResponseEntity<?> home(){
        Map<String, String> res = new HashMap<>();
        res.put("status","Successful");
        return ResponseEntity.ok(res);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (BadCredentialsException badCredentialsException){
            return ResponseEntity.badRequest().body("Incorrect username or password");
        }

        final UserDetails userDetails = userDetailService.loadUserByUsername(authenticationRequest.getUsername());
        final String JWT = jwtUtil.generateToken(userDetails);

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setJwt(JWT);
        authenticationResponse.setUsername(userDetails.getUsername());
        authenticationResponse.setAdmin(userDetailService.getRoleByUsername(userDetails.getUsername()));
        return ResponseEntity.ok(authenticationResponse);
    }
}
