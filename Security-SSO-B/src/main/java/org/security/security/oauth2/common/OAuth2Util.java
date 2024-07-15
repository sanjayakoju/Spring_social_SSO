package org.security.security.oauth2.common;

import org.security.security.oauth2.user.FacebookOAuth2UserInfo;
import org.security.security.oauth2.user.GithubOAuth2UserInfo;
import org.security.security.oauth2.user.GoogleOAuth2UserInfo;
import org.security.security.oauth2.user.OAuth2UserInfo;
import org.springframework.security.authentication.InternalAuthenticationServiceException;

import java.util.Map;

public class OAuth2Util {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";

    // UI-App/Web-Client will use this param to redirect flow to appropriate pag

    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    public static final String ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME = "original_request_uri";

    /**
     * Populate CustomAbstractOAuth2UserInfo for specific OAuthProvider
     */
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId,
                                                   Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(SecurityEnums.AuthProviderId.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SecurityEnums.AuthProviderId.facebook.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SecurityEnums.AuthProviderId.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new InternalAuthenticationServiceException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
