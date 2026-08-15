package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

// Measures exactly what ControlPlaneRelay actually does in production: a real TCP client talks to
// the relay's real TCP listener, which relays over a real Unix domain socket to a real UDS server
// standing in for the sandboxed process's own control-plane endpoint - three-hop path
// (TCP-in -> relay -> UDS -> UDS server).
@Tag("benchmark")
class ControlPlaneRelayLatencyBenchmarkTest {

  private static final int WARMUP_ITERATIONS = 20;
  private static final int MEASURED_ITERATIONS = 200;
  private static final byte[] REQUEST_PAYLOAD = "GET /health HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8);
  private static final byte[] RESPONSE_PAYLOAD =
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".getBytes(StandardCharsets.UTF_8);
  private static final Duration MAX_ACCEPTABLE_MEAN = Duration.ofSeconds(1);

  private Path udsPath;
  private ServerSocketChannel udsServer;
  private ControlPlaneRelay relay;

  @BeforeEach
  void startUdsServerAndRelay() throws IOException {
    long currentPid = ProcessHandle.current()
        .pid();
    Path benchDirectory = Path.of("/tmp", "warden-bench-" + currentPid);
    Files.createDirectories(benchDirectory);
    udsPath = benchDirectory.resolve("cp.sock");
    udsServer = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        .bind(UnixDomainSocketAddress.of(udsPath));
    Thread udsServerThread = SandboxThreads.namedDaemonThread(
        "warden-benchmark-uds-server", this::acceptAndEchoLoop
    );
    udsServerThread.start();
    relay = ControlPlaneRelay.start(udsPath, _ -> {});
  }

  @AfterEach
  void stopRelayAndUdsServer() throws IOException {
    relay.close();
    udsServer.close();
    Files.deleteIfExists(udsPath);
    Files.deleteIfExists(udsPath.getParent());
  }

  @Test
  void measuresRealRoundTripLatencyThroughTheRealRelay() throws IOException {
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
      roundTrip();
    }

    List<Duration> samples = new ArrayList<>(MEASURED_ITERATIONS);
    for (int i = 0; i < MEASURED_ITERATIONS; i++) {
      samples.add(roundTrip());
    }

    LatencyReport report = LatencyReport.of(samples);
    System.out.println(
        report.formatted("ControlPlaneRelay round-trip latency", MEASURED_ITERATIONS, WARMUP_ITERATIONS)
    );

    assertThat(report.mean())
        .as("a real regression (not machine variance) should blow well past this loose bound")
        .isLessThan(MAX_ACCEPTABLE_MEAN);
  }

  private Duration roundTrip() throws IOException {
    long startNanos = System.nanoTime();
    try (Socket connection = new Socket()) {
      connection.connect(new InetSocketAddress("127.0.0.1", relay.port()));
      connection.getOutputStream()
          .write(REQUEST_PAYLOAD);
      byte[] buffer = new byte[RESPONSE_PAYLOAD.length];
      readFully(connection, buffer);
    }
    return Duration.ofNanos(System.nanoTime() - startNanos);
  }

  private static void readFully(Socket connection, byte[] buffer) throws IOException {
    int totalRead = 0;
    while (totalRead < buffer.length) {
      int read = connection.getInputStream()
          .read(buffer, totalRead, buffer.length - totalRead);
      if (read < 0) {
        throw new IOException("Connection closed before the full response was read");
      }
      totalRead += read;
    }
  }

  private void acceptAndEchoLoop() {
    while (true) {
      try (SocketChannel connection = udsServer.accept()) {
        ByteBuffer requestBuffer = ByteBuffer.allocate(REQUEST_PAYLOAD.length);
        while (requestBuffer.hasRemaining()) {
          if (connection.read(requestBuffer) < 0) {
            break;
          }
        }
        connection.write(ByteBuffer.wrap(RESPONSE_PAYLOAD));
      } catch (IOException _) {
        return;
      }
    }
  }
}
