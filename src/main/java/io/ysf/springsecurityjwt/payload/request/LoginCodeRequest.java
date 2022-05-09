package io.ysf.springsecurityjwt.payload.request;

import javax.validation.constraints.NotBlank;

public class LoginCodeRequest {
	@NotBlank
	private String code;

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

}
