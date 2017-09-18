package org.wso2.identity.token.generator;

import java.util.Map;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.io.Charsets;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;

import com.google.gson.Gson;


public class CustomTokenGenerator extends OauthTokenIssuerImpl {
	
	private static final Logger log = LoggerFactory.getLogger(CustomTokenGenerator.class);
    
    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
    	
    	String accessToken = super.accessToken(tokReqMsgCtx);
    	
    	
    	//Customizing the access token and appending location information.
    	log.info("Using CustomTokenGenerator to generate the access token");
    	
        Map<ClaimMapping, String> userAttributes = TokenUtils.getUserAttributesFromCache(tokReqMsgCtx
                .getOauth2AccessTokenReqDTO().getAuthorizationCode());  
        String localClaimValue = TokenUtils.getLocaleClaim(userAttributes);
                
        TokenResponse response = new TokenResponse();
        response.setAccess_token(accessToken);
        response.setLocation(localClaimValue);
        
        Gson gson = new Gson();
        String tokenToEncode = gson.toJson(response).toString();
        log.info("Token String" + tokenToEncode);
        
        return Base64Utils.encode(tokenToEncode.getBytes(Charsets.UTF_8));
    }
}
