package org.example.expert.config;

import java.io.IOException;

import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.model.CustomUserDetails;
import org.example.expert.domain.user.entity.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomSigninFilter extends UsernamePasswordAuthenticationFilter {
	private final JwtUtil jwtUtil;
	private final ObjectMapper objectMapper;

	public CustomSigninFilter(JwtUtil jwtUtil, AuthenticationManager authenticationManager, ObjectMapper objectMapper) {
		super(authenticationManager);
		setFilterProcessesUrl("/auth/signin");
		this.jwtUtil = jwtUtil;
		this.objectMapper = objectMapper;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		try {
			SigninRequest signinRequest = objectMapper.readValue(request.getInputStream(), SigninRequest.class);
			UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(signinRequest.getEmail(), signinRequest.getPassword());

			return getAuthenticationManager().authenticate(authRequest);
		} catch (IOException e) {
			throw new AuthenticationServiceException("로그인 요청 파싱 실패", e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)  {
		CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();
		User user = userDetails.getUser();
		String token = jwtUtil.createToken(user.getId(), user.getEmail(), user.getNickname(), user.getUserRole());

		response.setHeader("Authorization", token);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException failed)
		throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		super.getFailureHandler().onAuthenticationFailure(request, response, failed);
	}
}
