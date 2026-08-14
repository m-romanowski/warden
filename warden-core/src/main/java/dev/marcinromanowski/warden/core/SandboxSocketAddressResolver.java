package dev.marcinromanowski.warden.core;

import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import org.eclipse.jetty.util.Promise;
import org.eclipse.jetty.util.SocketAddressResolver;

// Routes the plain-HTTP forward-proxy path's outbound connections through the same
// SandboxDnsResolution used by SandboxConnectHandler.newConnectAddress - without this,
// ProxyHandler.Forward's own inherited resolution has no private/loopback rejection at all, which
// a real end-to-end test proved reachable (a forward-proxied request to an allowlisted host that
// happens to resolve to loopback would otherwise succeed, while the identical CONNECT-tunneled
// request to the same host correctly fails). Installed via ProxyHandler.configureHttpClient.
final class SandboxSocketAddressResolver implements SocketAddressResolver {

  @Override
  public void resolve(String host, int port, Map<String, Object> context, Promise<List<InetSocketAddress>> promise) {
    try {
      InetAddress resolved = SandboxDnsResolution.resolveAndValidate(host);
      promise.succeeded(List.of(new InetSocketAddress(resolved, port)));
    } catch (UncheckedIOException | SecurityException e) {
      // The two exception types SandboxDnsResolution.resolveAndValidate actually throws -
      // unresolvable host and private/loopback rejection, respectively.
      promise.failed(e);
    }
  }
}
