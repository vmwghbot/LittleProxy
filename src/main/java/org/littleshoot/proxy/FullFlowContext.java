package org.littleshoot.proxy;

import org.littleshoot.proxy.impl.ClientToProxyConnection;
import org.littleshoot.proxy.impl.ProxyToServerConnection;

import io.netty.channel.ChannelHandlerContext;

/**
 * Extension of {@link FlowContext} that provides additional information (which
 * we know after actually processing the request from the client).
 */
public class FullFlowContext extends FlowContext {
    private final String serverHostAndPort;
    private final ChainedProxy chainedProxy;
    private final ChannelHandlerContext ctx;

    public FullFlowContext(ClientToProxyConnection clientConnection,
            ProxyToServerConnection serverConnection) {
        super(clientConnection);
        this.ctx = serverConnection.getContext();
        this.serverHostAndPort = serverConnection.getServerHostAndPort();
        this.chainedProxy = serverConnection.getChainedProxy();
    }

    /**
     * The proxy to server channel context.
     *
     * @return
     */
    public ChannelHandlerContext getProxyToServerContext() {
        return ctx;
    }

    /**
     * The host and port for the server (i.e. the ultimate endpoint).
     * 
     * @return
     */
    public String getServerHostAndPort() {
        return serverHostAndPort;
    }

    /**
     * The chained proxy (if proxy chaining).
     * 
     * @return
     */
    public ChainedProxy getChainedProxy() {
        return chainedProxy;
    }

}
