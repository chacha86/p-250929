package com.back.global.security;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String oauthUserId = oAuth2User.getName();
        String providerTypeCode = userRequest.getClientRegistration().getRegistrationId().toUpperCase();

        Map<String, Object> attributes = oAuth2User.getAttributes();
        Map<String, Object> attributesProperties = (Map<String, Object>) attributes.get("properties");

        String userNicknameAttributeName = "nickname";
        String profileImgUrlAttributeName = "profile_image";

        String nickname = (String) attributesProperties.get(userNicknameAttributeName);
        String profileImgUrl = (String) attributesProperties.get(profileImgUrlAttributeName);
        String username = providerTypeCode + "__%s".formatted(oauthUserId);
        String password = "";
        // Member member = memberService.modifyOrJoin(username, password, nickname, profileImgUrl).data();

        return new DefaultOAuth2User(List.of(),
                attributes,
                userRequest
                        .getClientRegistration()
                        .getProviderDetails()
                        .getUserInfoEndpoint()
                        .getUserNameAttributeName()
        );
    }
}
