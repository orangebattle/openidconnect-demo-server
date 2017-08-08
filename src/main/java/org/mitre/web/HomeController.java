/*******************************************************************************
 * Copyright 2014 The MITRE Corporation
 *   and the MIT Kerberos and Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitre.web;

import java.security.Principal;
import java.text.ParseException;
import java.util.Locale;
import java.util.Set;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Handles requests for the application home page.
 */
@Controller
public class HomeController {

	private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

	// filter reference so we can get class names and things like that.
	@Autowired
	private OIDCAuthenticationFilter filter;
	
	/**
	 * Simply selects the home view to render by returning its name.
	 */
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String home(Locale locale, Model model, Principal p) {

		model.addAttribute("issuerServiceClass", filter.getIssuerService().getClass().getSimpleName());
		model.addAttribute("serverConfigurationServiceClass", filter.getServerConfigurationService().getClass().getSimpleName());
		model.addAttribute("clientConfigurationServiceClass", filter.getClientConfigurationService().getClass().getSimpleName());
		model.addAttribute("authRequestOptionsServiceClass", filter.getAuthRequestOptionsService().getClass().getSimpleName());
		model.addAttribute("authRequestUriBuilderClass", filter.getAuthRequestUrlBuilder().getClass().getSimpleName());

		return "home";
	}

	@RequestMapping("/user")
	@PreAuthorize("hasRole('ROLE_USER')")
	public String user(Principal p) {
		return "user";
	}


	@RequestMapping("/logout")
	@PreAuthorize("hasRole('ROLE_USER')")
	public String logout(Principal p) {

		OIDCAuthenticationToken token = (OIDCAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

		String idToken = token.getIdToken().serialize();

		String sessionEndpoint = getEndSessionEndpoint(token);

		String postLogoutRedirectUri = getPostLogoutRedirectUri(token);


		return "redirect:" +
				sessionEndpoint +
				"?id_token_hint=" + idToken +
				"&post_logout_redirect_uri=" +
				postLogoutRedirectUri;
	}

	private String getPostLogoutRedirectUri(OIDCAuthenticationToken token) {
		Set<String> postLogoutRedirectUris = filter.getClientConfigurationService()
				.getClientConfiguration(
						filter.getServerConfigurationService().getServerConfiguration(getIssuer(token.getIdToken())))
				.getPostLogoutRedirectUris();

		String postLogoutRedirectUri = "";
		for (String uri : postLogoutRedirectUris) {
			postLogoutRedirectUri = uri;
		}
		return postLogoutRedirectUri;
	}

	private String getEndSessionEndpoint(OIDCAuthenticationToken token) {
		return filter.getServerConfigurationService()
				.getServerConfiguration(getIssuer(token.getIdToken()))
				.getEndSessionEndpoint();
	}

	private String getIssuer(JWT jwt) {
		try {
			return jwt.getJWTClaimsSet().getIssuer();
		} catch (ParseException e) {
			throw new RuntimeException();
		}
	}

}
