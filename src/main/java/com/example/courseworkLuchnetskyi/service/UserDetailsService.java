package com.example.courseworkLuchnetskyi.service;

import com.example.courseworkLuchnetskyi.model.User;
import com.example.courseworkLuchnetskyi.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;
import java.util.List;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("Loading user by username: " + username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    System.out.println("User not found with username: " + username);
                    return new UsernameNotFoundException("User not found with username: " + username);
                });

        System.out.println("User found: " + user.getUsername() + ", password hash: " + user.getPassword());

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                List.of()
        );
    }
}
