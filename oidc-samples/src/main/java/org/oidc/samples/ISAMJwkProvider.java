package org.oidc.samples;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;

//@Component
public class ISAMJwkProvider implements JwkProvider {
	
	@Autowired
	private RestTemplate restTemplate;
	
	private String accessToken;
	
	private String jwkUri;
	
	

	

	public void setRestTemplate(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}





	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}





	public void setJwkUri(String jwkUri) {
		this.jwkUri = jwkUri;
	}





	@Override
	public Jwk get(String keyId) throws JwkException {
		
		
		
		
		return null;
	}

}
