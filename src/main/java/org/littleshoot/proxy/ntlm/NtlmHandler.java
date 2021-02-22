package org.littleshoot.proxy.ntlm;

import org.littleshoot.proxy.ChainedProxy;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

/**
 * This serves as an extension to {@link ChainedProxy} which requires
 * NTLM authentication. Implementation should set negotiate (Type-11)
 * and challenge (Type-3) Proxy-Authorization headers to the request.
 */
public interface NtlmHandler {

	void negotiate(HttpRequest httpRequest);

	void challenge(HttpResponse httpResponse);

	void authenticate(HttpRequest httpRequest);

	boolean isChallenged();

}
