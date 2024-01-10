package com.jwt.token.generator;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.modelmapper.ModelMapper;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.security.Key;
import java.util.Date;
import java.util.logging.Logger;

public class JwtTokenGenerator {
    private static final Logger LOGGER = Logger.getLogger(JwtTokenGenerator.class.getName());
    private final String jwtKey;
    private final long expirationInMillis;


    public JwtTokenGenerator(String jwtKey, long expirationInMillis) {
        this.jwtKey = jwtKey;
        this.expirationInMillis = expirationInMillis;
    }
    public String generateJwtTokenWithInfo(String issuer,String id, Object claimSource) {
        JwtBuilder builder = Jwts.builder()
                .id(id)
                .issuer(issuer)
                .issuedAt(new Date(System.currentTimeMillis()))
                .signWith(this.getSecretKey(),Jwts.SIG.HS256);

        if (claimSource!=null){
            Class<?> claimSourceClass = claimSource.getClass();
            Field[] fields = claimSourceClass.getDeclaredFields();

            for (Field field : fields) {
                field.setAccessible(true);
                try {
                    builder.claim(field.getName(), field.get(claimSource));
                } catch (IllegalAccessException e) {
                    LOGGER.warning(e.toString());
                }
            }

        }


        if (expirationInMillis >= 0) {
            long expMillis = System.currentTimeMillis() + expirationInMillis;
            Date exp = new Date(expMillis);
            builder.expiration(exp);
        }

        return builder.compact();
    }



    private SecretKey getSecretKey(){
       return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtKey));
    }

    public <T> T verifyTokenAndReturnDetails(String token, Class<T> claimTargetClass) {
        Claims body = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(this.getSecretKey().getEncoded()))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return convertClass(body, claimTargetClass);
    }
    private  <T> T convertClass(Object source, Class<T> targetClass){
        ModelMapper modelMapper = new ModelMapper();
        return modelMapper.map(source,targetClass);
    }

}
