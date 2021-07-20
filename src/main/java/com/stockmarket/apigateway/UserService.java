package com.stockmarket.apigateway;

import com.stockmarket.apigateway.DAO.User;
import com.stockmarket.apigateway.Repository.UserRepository;
import com.stockmarket.apigateway.Security.UserPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isPresent()){
            return new UserPrincipal(optionalUser.get());
        }
        throw new UsernameNotFoundException(null);
    }
}
