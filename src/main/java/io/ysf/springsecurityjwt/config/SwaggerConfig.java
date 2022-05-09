package io.ysf.springsecurityjwt.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.Contact;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

@Configuration
public class SwaggerConfig {
	private String headerLit = "header";

	@Bean
	public Docket api() {
		Docket docket = new Docket(DocumentationType.SWAGGER_2)
				.apiInfo(apiInfo())
				.securityContexts(Arrays.asList(securityContext()))
				.securitySchemes(Arrays.asList(apiKey())).select()
				.apis(RequestHandlerSelectors.any()).paths(PathSelectors.any())
				.build();
		// List<RequestParameter> globalRequestParameters = new ArrayList<>();
		// RequestParameter globalRequestParameter = new
		// RequestParameterBuilder()
		// .name("CLIENT_ID").description("GEC").required(true)
		// .in(headerLit)
		// .accepts(Collections.singleton(MediaType.APPLICATION_JSON))
		// .build();
		// globalRequestParameters.add(globalRequestParameter);
		// globalRequestParameter = new RequestParameterBuilder()
		// .name("Authorization")
		// .description(
		// "Bearer
		// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJERVYifQ.uOFB7h7_Aw6jbA1HSqVJ44tKMO7E1ljz1kV_JddeKL64YCOH57-l1ZX2Lly-Jnhdnxk3xMAeW5FawAgymEaMKA")
		// .required(true).in(headerLit)
		// .accepts(Collections.singleton(MediaType.APPLICATION_JSON))
		// .build();
		// globalRequestParameters.add(globalRequestParameter);
		// docket.globalRequestParameters(globalRequestParameters);
		return docket;
	}

	private ApiKey apiKey() {
		return new ApiKey("JWT", "Authorization", headerLit);
	}

	private List<SecurityReference> defaultAuth() {
		AuthorizationScope authorizationScope = new AuthorizationScope("global",
				"accessEverything");
		AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
		authorizationScopes[0] = authorizationScope;
		return Arrays.asList(new SecurityReference("JWT", authorizationScopes));
	}

	private SecurityContext securityContext() {
		return SecurityContext.builder().securityReferences(defaultAuth())
				.build();
	}

	private ApiInfo apiInfo() {
		return new ApiInfo("SalesForceService API Documentation",
				"SalesForceService.Use token to Authorize Once for calling the API",
				"1.0", "Terms of service",
				new Contact("XYZ", "www.systemax.com", "xyz@gmail.com"),
				"License of API", "API license URL");
	}

}
