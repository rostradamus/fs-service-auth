package com.fitsight.fsserviceauth.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Component
@Slf4j
public class JWTUtils {
  private static final String ROLE_CLAIM_NAME = "ath";
  @Value("${fs.service.jwt.rsa-private-key}")
  private String rsaPrivateKeyValue;
  @Value("${fs.service.jwt.rsa-public-key}")
  private String rsaPublicKeyValue;
  @Value("${fs.service.jwt.duration}")
  private int duration;

  public String generateJwtToken(UserDetails userDetails) throws InvalidKeySpecException, NoSuchAlgorithmException {
    return this.generateJwtToken(userDetails.getUsername(),
            userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray(String[]::new));
  }

  private String generateJwtToken(String username, String[] authorities)
          throws InvalidKeySpecException, NoSuchAlgorithmException {
    return JWT.create()
            .withJWTId(UUID.randomUUID().toString())
            .withSubject(username)
            .withIssuer(JWTConstants.TOKEN_ISSUER)
            .withAudience(JWTConstants.TOKEN_AUDIENCE)
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(new Date().getTime() + duration))
            .withArrayClaim(ROLE_CLAIM_NAME, authorities)
            .sign(Algorithm.RSA256(loadPublicKey(), loadPrivateKey()));
  }

  public String getUsernameFromJwtToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException {
    return JWT.require(Algorithm.RSA256(loadPublicKey(), loadPrivateKey())).build().verify(token).getSubject();
  }

  public String parseJwtFrom(String header) {
    if (StringUtils.hasText(header) && header.startsWith(JWTConstants.TOKEN_PREFIX)) {
      return header.replace(JWTConstants.TOKEN_PREFIX, "");
    }
    return null;
  }

  private RSAPublicKey loadPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    String publicKeyString = rsaPublicKeyValue;
    publicKeyString = publicKeyString
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+","");
    byte[] x590EncodedBytes = Base64.getDecoder().decode(publicKeyString);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x590EncodedBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
  }

  private RSAPrivateKey loadPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    String privateKeyString = rsaPrivateKeyValue;
    privateKeyString = privateKeyString
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+","");
    byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(privateKeyString);
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
  }
}
