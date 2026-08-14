package dev.marcinromanowski.warden.core;

import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

// Resolves a proxy target hostname exactly once and validates the resolved address before it is
// ever used to open a real connection - the caller must reuse the returned InetAddress for the
// actual connect (e.g. via the InetSocketAddress(InetAddress, int) constructor, not the
// hostname-based one) rather than re-resolving by name a second time. Re-resolving at connect
// time would reopen a classic DNS-rebinding gap: a malicious authoritative server could return a
// safe address for this check and a private/loopback address for the real connection.
final class SandboxDnsResolution {

  // IPv4 CGNAT (RFC 6598) and benchmarking (RFC 2544) ranges - not covered by
  // InetAddress.isSiteLocalAddress()/isLinkLocalAddress(), which only recognize RFC 1918 and
  // RFC 3927 respectively.
  private static final int CGNAT_FIRST_OCTET = 100;
  private static final int CGNAT_SECOND_OCTET_BASE = 64;
  private static final int CGNAT_SECOND_OCTET_MASK = 0xC0;
  private static final int BENCHMARK_FIRST_OCTET = 198;
  private static final int BENCHMARK_SECOND_OCTET_BASE = 18;
  private static final int BENCHMARK_SECOND_OCTET_MASK = 0xFE;
  // IPv6 Unique Local Addresses, fc00::/7 (RFC 4193) - InetAddress.isSiteLocalAddress() only
  // recognizes the deprecated fec0::/10 site-local range, not the fc00::/fd00:: range everything
  // actually uses today.
  private static final int ULA_PREFIX = 0xFC;
  private static final int ULA_PREFIX_MASK = 0xFE;
  private static final int IPV4_ADDRESS_LENGTH = 4;
  private static final int IPV6_ADDRESS_LENGTH = 16;

  private SandboxDnsResolution() {
  }

  static InetAddress resolveAndValidate(String host) {
    String requiredHost = Preconditions.nonBlank(host, "host");
    InetAddress[] resolved;
    try {
      resolved = InetAddress.getAllByName(requiredHost);
    } catch (UnknownHostException e) {
      throw new UncheckedIOException("Cannot resolve sandbox proxy target host: " + host, e);
    }
    // A host with mixed public/private records must not be allowed or denied by luck of which
    // address happened to be used - reject if any resolved address is private/local, not just
    // the one this call happens to pin.
    for (InetAddress candidate : resolved) {
      if (isPrivateOrLocal(candidate)) {
        String message = "Sandbox proxy target " + host + " resolved to a private/loopback/link-local"
            + " address (" + candidate.getHostAddress() + "), refusing to connect";
        throw new SecurityException(message);
      }
    }
    return resolved[0];
  }

  static boolean isPrivateOrLocal(InetAddress address) {
    if (address.isLoopbackAddress()
        || address.isSiteLocalAddress()
        || address.isLinkLocalAddress()
        || address.isAnyLocalAddress()
        || address.isMulticastAddress()) {
      return true;
    }
    byte[] bytes = address.getAddress();
    if (bytes.length == IPV4_ADDRESS_LENGTH) {
      return isCgnatOrBenchmark(bytes);
    }
    if (bytes.length == IPV6_ADDRESS_LENGTH) {
      return isIpv6UniqueLocal(bytes);
    }
    return false;
  }

  private static boolean isCgnatOrBenchmark(byte[] ipv4) {
    int firstOctet = Byte.toUnsignedInt(ipv4[0]);
    int secondOctet = Byte.toUnsignedInt(ipv4[1]);
    boolean isCgnat = firstOctet == CGNAT_FIRST_OCTET
        && (secondOctet & CGNAT_SECOND_OCTET_MASK) == CGNAT_SECOND_OCTET_BASE;
    boolean isBenchmark = firstOctet == BENCHMARK_FIRST_OCTET
        && (secondOctet & BENCHMARK_SECOND_OCTET_MASK) == BENCHMARK_SECOND_OCTET_BASE;
    return isCgnat || isBenchmark;
  }

  private static boolean isIpv6UniqueLocal(byte[] ipv6) {
    int firstByte = Byte.toUnsignedInt(ipv6[0]);
    return (firstByte & ULA_PREFIX_MASK) == ULA_PREFIX;
  }
}
