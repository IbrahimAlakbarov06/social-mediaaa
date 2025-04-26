package org.example.socialmediabackend.service;

import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.repository.UserRepository;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    public OAuth2UserService(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oauth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        // Get attributes from the OAuth provider
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        // Check if user exists in our database
        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            // User exists, update their information if needed
            user = userOptional.get();
        } else {
            // Create a new user
            user = createUser(email, name);
        }

        return oAuth2User;
    }

    private User createUser(String email, String name) {
        User user = new User();

        // Generate a username from email if name is not available
        String username = name != null ? name.replaceAll("\\s+", "_").toLowerCase() :
                email.substring(0, email.indexOf('@'));

        // Ensure username is unique by adding random suffix if needed
        if (userRepository.findByUsername(username).isPresent()) {
            username = username + "_" + UUID.randomUUID().toString().substring(0, 8);
        }

        user.setEmail(email);
        user.setUsername(username);
        // Generate a random secure password
        user.setPassword(UUID.randomUUID().toString());
        user.setEnabled(true);

        return userRepository.save(user);
    }

    public String generateTokenForOAuth2User(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return jwtService.generateToken(user);
    }
}