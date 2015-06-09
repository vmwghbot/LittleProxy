package org.littleshoot.proxy.ntlm;

import static com.google.common.base.Preconditions.checkState;
import static io.netty.handler.codec.http.HttpHeaders.isKeepAlive;
import static io.netty.handler.codec.http.HttpHeaders.Names.PROXY_AUTHENTICATE;
import static io.netty.handler.codec.http.HttpHeaders.Names.PROXY_AUTHORIZATION;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import static org.apache.commons.lang3.StringUtils.substringAfter;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

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
		challenged = provider.setType2(decodeBase64(authChallenge));
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
		httpRequest.headers().set(PROXY_AUTHORIZATION, "NTLM " + encodeBase64String(msg));
	}

}
