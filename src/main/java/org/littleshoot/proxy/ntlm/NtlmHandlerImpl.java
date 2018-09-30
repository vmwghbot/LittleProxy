package org.littleshoot.proxy.ntlm;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

import static com.google.common.base.Preconditions.checkState;
import static com.google.common.io.BaseEncoding.base64;
import static io.netty.handler.codec.http.HttpHeaders.Names.PROXY_AUTHENTICATE;
import static io.netty.handler.codec.http.HttpHeaders.Names.PROXY_AUTHORIZATION;
import static io.netty.handler.codec.http.HttpHeaders.isKeepAlive;
import static org.apache.commons.lang3.StringUtils.substringAfter;

/**
 * This class is responsible for writing and reading NTLM related request and
 * response headers respectively. It delegates the creating of NTLM messages to
 * a provider.
 */
public class NtlmHandlerImpl implements NtlmHandler {

	private final NtlmProvider provider;

	private boolean challenged;

	public NtlmHandlerImpl(NtlmProvider provider) {
		this.provider = provider;
	}

	@Override
	public void negotiate(HttpRequest httpRequest) {
		assertChallengeNotRead();
		writeNegotiation(httpRequest);
	}

	@Override
	public void challenge(HttpResponse httpResponse) {
		assertPersistentConnection(httpResponse);
		assertChallengeNotRead();
		readChallenge(httpResponse);
		assertChallengeRead();
	}

	@Override
	public void authenticate(HttpRequest httpRequest) {
		assertChallengeRead();
		writeAuthentication(httpRequest);
	}

	@Override
	public boolean isChallenged() {
		return challenged;
	}

	private void writeNegotiation(HttpRequest httpRequest) {
		byte[] type1 = provider.getType1();
		setAuthHeader(httpRequest, type1);
	}

	private void readChallenge(HttpResponse httpResponse) {
		String proxyAuth = httpResponse.headers().get(PROXY_AUTHENTICATE);
		String authChallenge = substringAfter(proxyAuth, "NTLM ");
		challenged = provider.setType2(base64().decode(authChallenge));
	}

	private void writeAuthentication(HttpRequest httpRequest) {
		byte[] type3 = provider.getType3();
		setAuthHeader(httpRequest, type3);
	}

	private static void assertPersistentConnection(HttpResponse httpResponse) {
		checkState(isKeepAlive(httpResponse), "Connection closed during NTLM handshake");
	}

	private void assertChallengeNotRead() {
		checkState(!challenged, "NTLM challenge already read");
	}

	private void assertChallengeRead() {
		checkState(challenged, "Failed to read NTLM challenge");
	}

	private static void setAuthHeader(HttpRequest httpRequest, byte[] msg) {
		httpRequest.headers().set(PROXY_AUTHORIZATION, "NTLM " + base64().encode(msg));
	}

}
