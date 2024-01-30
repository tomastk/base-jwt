package tomastk.jwt.auth;

import lombok.RequiredArgsConstructor;
import org.aspectj.apache.bcel.classfile.ExceptionTable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tomastk.jwt.jwtconfig.TokenService;
import tomastk.jwt.user.Role;
import tomastk.jwt.user.User;
import tomastk.jwt.user.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;


    public AuthResponse register(RegisterRequest registerDetails) {

        User userToRegister = User.builder()
                .username(registerDetails.getUsername())
                .password(passwordEncoder.encode(registerDetails.getPassword()))
                .country(registerDetails.getCountry())
                .firstName(registerDetails.getFirstName())
                .lastName(registerDetails.getLastName())
                .role(Role.USER)
                .build();

        Optional<User> userExisting = userRepository.findByUsername(userToRegister.getUsername());


        try {
            userRepository.save(userToRegister);
        } catch (RuntimeException ex){
            return AuthResponse.builder()
                    .token(null)
                    .build();
        }
        return AuthResponse.builder()
                .token(tokenService.getToken(userToRegister))
                .build();

    }

    public AuthResponse login(LoginRequest loginDetails) {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDetails.getUsername(), loginDetails.getPassword()));
        } catch (RuntimeException ex) {
            return AuthResponse.builder()
                .token(null)
                .authError(ex.getMessage())
                .build();
        }

        UserDetails userToGetLogged = userRepository.findByUsername(loginDetails.getUsername()).orElseThrow();
        String token = tokenService.getToken(userToGetLogged);
        return AuthResponse.builder()
                .token(token)
                .build();
    }
}
