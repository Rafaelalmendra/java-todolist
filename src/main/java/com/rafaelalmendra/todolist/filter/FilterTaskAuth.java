package com.rafaelalmendra.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.rafaelalmendra.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {
    
      // get auth
    var authorization = request.getHeader("Authorization");

    if (authorization == null || !authorization.startsWith("Basic")) {
      throw new ServletException("Authorization header missing or invalid");
    }

    var authEncoded = authorization.substring("Basic".length()).trim();
    byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
    var authString = new String(authDecoded);

    String[] credentials = authString.split(":");
    String username = credentials[0];
    String password = credentials[1];

    // validate auth
    var user = this.userRepository.findByUsername(username);
    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

    if (user == null || !passwordVerify.verified) {
      response.sendError(401);
      return;
    }

    filterChain.doFilter(request, response);
  }

}
