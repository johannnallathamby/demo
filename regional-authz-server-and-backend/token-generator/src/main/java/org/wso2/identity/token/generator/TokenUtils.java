package org.wso2.identity.token.generator;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.MapUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;

public class TokenUtils {

    /**
     * Get user attribute from cache
     *
     * @param accessToken
     *            Access token
     * @return User attributes
     */
    public static Map<ClaimMapping, String> getUserAttributesFromCache(String accessToken) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = (AuthorizationGrantCacheEntry) AuthorizationGrantCache.getInstance()
                                                                             .getValueFromCacheByToken(cacheKey);
        if (cacheEntry == null) {
            return new HashMap<ClaimMapping, String>();
        }
        return cacheEntry.getUserAttributes();
    }

    /**
     * Get claims map
     *
     * @param userAttributes
     *            User Attributes
     * @return User attribute map
     */
    public static String getLocaleClaim(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap();
        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if ("locale".equals(entry.getKey().getRemoteClaim().getClaimUri())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

}
