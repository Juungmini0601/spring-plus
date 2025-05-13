package org.example.expert.domain.auth.service;

import java.util.Collection;

import org.example.expert.config.JwtUtil;
import org.example.expert.domain.auth.model.CustomUserDetails;
import org.example.expert.domain.auth.model.JwtAuthenticationToken;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationProvider(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            JwtAuthenticationToken authToken = (JwtAuthenticationToken) authentication;
            String jwt = (String) authToken.getCredentials();

            try {
                Claims claims = jwtUtil.extractClaims(jwt);
                Long id = Long.parseLong(claims.getSubject());
                String email = claims.get("email", String.class);
                String nickname = claims.get("nickname", String.class);
                UserRole role = UserRole.valueOf(claims.get("userRole", String.class));

                UserDetails userDetails = new CustomUserDetails(new User(id, email, null, nickname, role));
                Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

                    return JwtAuthenticationToken.authenticated(userDetails, authorities);
            } catch (SecurityException | MalformedJwtException e) {
                log.warn("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
                throw new BadCredentialsException("유효하지 않은 JWT 서명 입니다.", e);
            } catch (ExpiredJwtException e) {
                log.warn("Expired JWT token, 만료된 JWT token 입니다.", e);
                throw new CredentialsExpiredException("만료된 JWT 토큰입니다.", e);
            } catch (UnsupportedJwtException e) {
                log.warn("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
                throw new BadCredentialsException("지원되지 않는 JWT 토큰입니다.", e);
            } catch (Exception e) {
                log.error("Internal server error", e);
                throw e;
            }
        }
        
        @Override
        public boolean supports(Class<?> authentication) {
            return JwtAuthenticationToken.class.isAssignableFrom(authentication);
        }
}