package org.bspv.security.jwt.tokenwriter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

/**
 * 
 *
 */
@Slf4j
public class PayloadTokenWriter implements TokenWriter {

	@Autowired
	private ObjectMapper mapper;
	
	/*
	 * (non-Javadoc)
	 * @see org.bspv.security.jwt.tokenwriter.TokenWriter#write(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public void write(String token, HttpServletResponse response) {
		Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("jwt", token);
		response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try {
			mapper.writeValue(response.getWriter(), tokenMap);
		} catch (IOException e) {
			log.error("Error writing the JWT token in the response body.", e);
		}
	}

}
