package tomastk.jwt.jwtconfig;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;



@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String token = getTokenFromRequest(request);
        final String username;

        if (token==null){
            filterChain.doFilter(request, response);
            return;
        }

        try {
            username = tokenService.getUsernameFromToken(token);
        } catch (RuntimeException ex) {
            setTokenError(response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails;
            try {
                 userDetails = userDetailsService.loadUserByUsername(username);
            } catch (RuntimeException ex) {
                setTokenError(response);
                return;
            }

            if (tokenService.isTokenValid(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                setTokenError(response);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private static void setTokenError(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Token Invalid\"}");
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            System.out.println(authHeader.substring(7));
            return authHeader.substring(7);
        }
        return null;
    }
}
