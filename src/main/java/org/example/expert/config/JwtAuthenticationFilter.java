package org.example.expert.config;

import java.io.IOException;

import org.example.expert.domain.auth.model.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * 이 필터는 모든 엔드포인트에 노출시킨다.
 * 만일 여기서 SecurityContext에 필요한 정보가 없으면 인증 실패, 인가 실패 응답이 나갈 것이다.
 */
@Slf4j
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private final JwtUtil jwtUtil;
	private final AuthenticationManager authenticationManager;

	public JwtAuthenticationFilter(JwtUtil jwtUtil, AuthenticationManager authenticationManager) {
		// 걍 싹다 걸어버림
		super("/**");
		this.jwtUtil = jwtUtil;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException{
		// 토큰이 null이면 애초에 여기 로직이 호출안됨
		String bearerJwt = request.getHeader("Authorization");
		String jwt = jwtUtil.substringToken(bearerJwt);
		try {
			JwtAuthenticationToken authToken = JwtAuthenticationToken.unauthenticated(jwt);
			log.info("url: {}", request.getRequestURI());
			return authenticationManager.authenticate(authToken);
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
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		FilterChain chain, Authentication authResult)
		throws IOException, ServletException {
		// 성공 시 계속 진행 (기본 리다이렉트 방지)
		// SecurityContext를 여기서 넣어줘야함.
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authResult);
		SecurityContextHolder.setContext(securityContext);

		chain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException failed)
		throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		super.getFailureHandler().onAuthenticationFailure(request, response, failed);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		String bearerJwt = request.getHeader("Authorization");
		return bearerJwt != null && bearerJwt.startsWith("Bearer ");
	}
}
