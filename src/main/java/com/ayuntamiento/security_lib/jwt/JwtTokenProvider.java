package com.ayuntamiento.security_lib.jwt;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;

@Component
public class JwtTokenProvider {
	
    @Value("${jwt.rsa.public-key:}")
    private String publicKeyBase64;
    
    private PublicKey publicKey;
    
    @PostConstruct
    public void initKeys() throws Exception {
    	if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
            throw new IllegalArgumentException("ERROR CRÍTICO: No se encontró la llave pública en el application.properties");
        }
    	publicKeyBase64 = publicKeyBase64.replaceAll("\\s+", "");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }
    
    /**
     * LEER EL TOKEN
     */
    public String obtenerUsernameDelToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
                
        return claims.getSubject();
    }

    /**
     * VALIDAR EL TOKEN
     */
    public boolean validarToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
    /*
    public Collection<? extends GrantedAuthority> obtenerAutoridadesDelToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // Buscamos el claim "rol"
        Object rolesObj = claims.get("rol"); 

        if (rolesObj == null) {
            return Collections.emptyList();
        }

        // Convertimos el objeto a String y lo separamos si hubiera varios
        String rolesString = rolesObj.toString();
        
        // Si el token ya trae "ROLE_ADMIN", SimpleGrantedAuthority lo tomará
        return Arrays.stream(rolesString.split(","))
                .map(role -> new SimpleGrantedAuthority(role.trim()))
                .collect(Collectors.toList());
    }*/
    
    /**
     * LEER ROL Y PERMISOS DEL TOKEN
     */
    public Collection<? extends GrantedAuthority> obtenerAutoridadesDelToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        List<GrantedAuthority> autoridades = new ArrayList<>();

        // 1. Extraemos y procesamos el Rol (Asegurando el prefijo ROLE_)
        Object rolesObj = claims.get("rol"); 
        if (rolesObj != null) {
            String rolesString = rolesObj.toString();
            
            List<SimpleGrantedAuthority> roles = Arrays.stream(rolesString.split(","))
                    .map(role -> {
                        String rolLimpio = role.trim();
                        // Tu excelente validación
                        if (!rolLimpio.startsWith("ROLE_")) {
                            rolLimpio = "ROLE_" + rolLimpio;
                        }
                        return new SimpleGrantedAuthority(rolLimpio);
                    })
                    .collect(Collectors.toList());
                    
            autoridades.addAll(roles);
        }

        // 2. Extraemos y procesamos los Permisos (Estos van directos, sin prefijos)
        List<String> permisos = claims.get("permisos", List.class);
        if (permisos != null && !permisos.isEmpty()) {
            List<SimpleGrantedAuthority> autoridadesPermisos = permisos.stream()
                    .map(SimpleGrantedAuthority::new) // Convierte cada string en autoridad
                    .collect(Collectors.toList());
                    
            autoridades.addAll(autoridadesPermisos);
        }

        return autoridades;
    }
}