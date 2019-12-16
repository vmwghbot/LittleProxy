package org.littleshoot.proxy.ntlm;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;

import static com.google.common.base.Preconditions.checkNotNull;
import static jcifs.ntlmssp.Type3Message.getDefaultFlags;
import static org.apache.commons.lang3.StringUtils.EMPTY;

/**
 * Reference implementation of {@link NtlmProvider}
 */
public class JcifsNtlmProvider implements NtlmProvider {

	private static final Logger LOG = LoggerFactory.getLogger(JcifsNtlmProvider.class);

	private final int flags;

	private final String user;

	private final String password;

	private final String domain;

	private final String workstation;

	private Type2Message type2;

	public JcifsNtlmProvider(int flags, String user, String password, String domain, String workstation) {
		this.flags = flags > 0 ? flags : getDefaultFlags();
		this.user = checkNotNull(user);
		this.password = checkNotNull(password);
		this.domain = checkNotNull(domain);
		this.workstation = checkNotNull(workstation);
	}

	public JcifsNtlmProvider(String user, String password, String domain) {
		this(0, user, password, domain, EMPTY);
	}

	@Override
	public byte[] getType1() {
		NtlmMessage type1 = new Type1Message(flags, domain, workstation);
		LOG.debug("NTLM {}", type1);
		return type1.toByteArray();
	}

	@Override
	public boolean setType2(byte[] material) {
		try {
			type2 = new Type2Message(material);
			LOG.debug("NTLM {}", type2);
			return true;
		} catch (IOException e) {
			LOG.warn("Unable to parse NTLM Type2 message", e);
			return false;
		}
	}

	@Override
	public byte[] getType3() {
		NtlmMessage type3 = new Type3Message(type2, password, domain, user, workstation, type2.getFlags());
		LOG.debug("NTLM {}", type3);
		return type3.toByteArray();
	}
}
