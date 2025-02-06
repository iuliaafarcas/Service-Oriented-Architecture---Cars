# Service-Oriented-Architecture---Cars

Tutorial: Securing a Spring Boot REST API with JWT (JSON Web Tokens)

Introduction

In modern application development, securing APIs is essential for protecting sensitive data and user interactions. One of the most widely used techniques for securing REST APIs is by using JSON Web Tokens (JWT). JWT provides a compact, URL-safe way of transferring claims between parties and can be used for stateless authentication.

This tutorial will walk you through integrating JWT authentication into a Spring Boot REST API. We'll explore how to generate tokens, protect endpoints, and verify token authenticity.

**Prerequisites:**

- Java 11 or higher

- Gradle

- A working knowledge of Spring Boot

**Project Setup**

If you don't already have a Spring Boot project, generate one using Spring Initializr with the following dependencies:

* Spring Web

* Spring Security

* Spring Boot DevTools

* JJwt (JSON Web Tokens)

Step 1: Understanding JWT Token Generation and Validation

A key part of integrating JWT involves generating tokens after user authentication and validating these tokens in subsequent requests.

JWT Structure

A JWT consists of three parts:

1. Header: Metadata about the token, typically specifying the signing algorithm.

2. Payload: Contains claims about the user, such as username and roles.

3. Signature: Ensures the token's integrity.

Generating Tokens

The following code in JwtProvider.java handles token creation:

    public String generateToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

    return Jwts.builder()
            .setSubject(authentication.getName())
            .claim(AUTHORITIES_KEY, authorities)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000))
            .signWith(getSigningKey())
            .compact();
}

Tokens are signed using a secure key defined in the application properties.

**Validating Tokens**

Token validation ensures that only valid and non-expired tokens can access protected endpoints:

        public boolean validateToken(String token, UserDetails userDetails) {
            String username = getUsernameFromToken(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        }

This method checks if the token's username matches the expected value and ensures the token has not expired.

**Step 2: Implementing a JWT Filter**

The JwtAuthenticationFilter intercepts incoming requests to validate JWT tokens and sets the security context if validation is successful.

Key Responsibilities

1. Extract the token from the request header.

2. Validate the token.

3. Set the security context if the token is valid.

Code Breakdown

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            String header = request.getHeader(HEADER_STRING);
            String token = null;
            String username = null;

    if (header != null && header.startsWith(TOKEN_PREFIX)) {
        token = header.replace(TOKEN_PREFIX + " ", "");
        try {
            username = jwtProvider.getUsernameFromToken(token);
        } catch (Exception e) {
            logger.warn("Token validation error: " + e.getMessage());
        }
    }

    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (jwtProvider.validateToken(token, userDetails)) {
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }
    filterChain.doFilter(request, response);
}

The filter ensures that only authenticated requests are allowed to access protected resources.

**Step 3: Handling Unauthorized Access**

To handle scenarios where a request lacks a valid JWT or is otherwise unauthorized, an entry point component is used.

**Code Explanation**

The UnauthorizedEntryPoint component responds with a 401 Unauthorized status when access is denied.

    @Component
    public class UnauthorizedEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthenticated");
    }
    }

This component ensures that clients receive clear feedback when their requests are unauthorized.

**Conclusion**

This tutorial demonstrated how to secure a Spring Boot REST API using JWT. We covered token generation, request filtering, and handling unauthorized access. By implementing these steps, you can create a robust and scalable security layer for your APIs.

To explore the complete working example, visit the GitHub Repository.

Suggested Enhancements

- Role-based access control (RBAC): Restrict access to specific endpoints based on user roles.

- Encrypted configurations: Secure sensitive application properties.

JWT provides a stateless, scalable solution for securing REST APIs and is a critical tool for modern microservice architectures.


