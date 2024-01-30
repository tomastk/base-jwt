package tomastk.jwt.auth;

import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginHandler(@RequestBody LoginRequest loginDetails){
        AuthResponse response = authService.login(loginDetails);
        if (response.token == null) {
            return ResponseEntity.badRequest().body(response);
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> registerHandler(@RequestBody RegisterRequest registerDetails){
        AuthResponse response = authService.register(registerDetails);
        if (response.token == null) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(response);
    }

}