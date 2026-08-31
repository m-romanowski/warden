package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxLaunchRequestBuilder;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

@EnabledOnOs(OS.LINUX)
class OsSandboxedProcessLauncherLinuxProcessLifetimeTest {

  private static final Duration LAUNCH_TIMEOUT = Duration.ofSeconds(30);
  private static final Duration BRIDGE_TIMEOUT = Duration.ofSeconds(20);
  private static final Duration TEARDOWN_GRACE = Duration.ofSeconds(5);
  private static final Duration POLL_INTERVAL = Duration.ofMillis(100);
  private static final String PAYLOAD_MARKER = "PAYLOAD-RUNNING";
  private static final String BRIDGE_COMMAND_NAME = "socat";
  private static final URI CONTROL_PLANE_HINT = URI.create("http://127.0.0.1:9876");
  private static final int EGRESS_BRIDGE_ONLY = 1;
  private static final int EGRESS_AND_CONTROL_PLANE_BRIDGES = 2;
  private static final String SANDBOX_INIT_PID = "1";
  private static final String HOST_PID_RESULT = "HOST-PID-SIGNAL";
  private static final String SANDBOX_PID_RESULT = "SANDBOX-PID-SIGNAL";

  @Test
  void leavesNothingRunningInTheSessionNamespaceOnceThePayloadExits(
      @TempDir Path tempDirParameter
  ) throws IOException {
    assertTheSessionNamespaceEmptiesOut(tempDirParameter, Optional.empty(), EGRESS_BRIDGE_ONLY);
  }

  @Test
  void leavesNothingRunningWhenTheSessionAlsoBridgesItsControlPlane(
      @TempDir Path tempDirParameter
  ) throws IOException {
    assertTheSessionNamespaceEmptiesOut(
        tempDirParameter,
        Optional.of(CONTROL_PLANE_HINT),
        EGRESS_AND_CONTROL_PLANE_BRIDGES
    );
  }

  @Test
  void leavesNothingRunningWhenTheCallerTearsTheSessionDownForcibly(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-lifetime-forcible-", ".log");
    String namespace;

    try (SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, Optional.empty(), "sleep 60")) {
      namespace = awaitSessionNamespace(process, logFile);
      assertThat(bridgesIn(namespace))
          .as("the bridge must be running for this test to assert anything about it")
          .isNotEmpty();
      process.destroyForcibly();
      assertThat(process.waitFor(LAUNCH_TIMEOUT))
          .as("the sandboxed process did not terminate in time")
          .isTrue();
    }

    assertThat(remainingMembersOf(namespace))
        .as("a forcible teardown leaves nothing in the sandbox running to do the cleaning up, so"
            + " nothing may depend on something in there having done it")
        .isEmpty();
  }

  @Test
  void leavesNoHostProcessNameableFromInsideTheSandbox(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-lifetime-pid-space-", ".log");
    long hostPid = ProcessHandle.current()
        .pid();
    String probe = String.join(
        "; ",
        "kill -0 " + hostPid + " 2>/dev/null",
        "echo " + HOST_PID_RESULT + "=$?",
        "kill -0 " + SANDBOX_INIT_PID + " 2>/dev/null",
        "echo " + SANDBOX_PID_RESULT + "=$?"
    );

    try (SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, Optional.empty(), probe)) {
      assertThat(process.waitFor(LAUNCH_TIMEOUT))
          .as("the sandboxed process did not terminate in time")
          .isTrue();
    }

    String output = Files.readString(logFile);
    assertThat(output)
        .as("a pid the host is running has to name nothing inside the sandbox, so what keeps a"
            + " signal from reaching a host process is the pid namespace and not a loaded policy")
        .contains(HOST_PID_RESULT + "=1");
    assertThat(output)
        .as("signalling is not refused wholesale in there - the sandbox's own init answers, which is"
            + " what makes the refusal above a statement about the pid space")
        .contains(SANDBOX_PID_RESULT + "=0");
  }

  private static void assertTheSessionNamespaceEmptiesOut(
      Path tempDirParameter,
      Optional<URI> controlPlaneHint,
      int expectedBridgeCount
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-lifetime-", ".log");

    try (SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, controlPlaneHint, "sleep 3")) {
      String namespace = awaitSessionNamespace(process, logFile);
      assertThat(bridgesIn(namespace))
          .as("every bridge this session asked for must be running while the payload is, or the"
              + " count taken after it exits proves nothing")
          .hasSize(expectedBridgeCount);
      assertThat(process.waitFor(LAUNCH_TIMEOUT))
          .as("the sandboxed process did not terminate in time, output so far: %s", Files.readString(logFile))
          .isTrue();
      assertThat(remainingMembersOf(namespace))
          .as("the payload has exited, so the session is over and nothing it started may outlive it")
          .isEmpty();
    }
  }

  private static SandboxedProcess launch(
      Path workspaceRoot,
      Path logFile,
      Optional<URI> controlPlaneHint,
      String payload
  ) {
    SandboxLaunchRequestBuilder builder =
        SandboxLaunchRequest.command("/bin/sh", "-c", "echo " + PAYLOAD_MARKER + "; " + payload)
            .sandboxRoot(workspaceRoot)
            .logFile(logFile.toFile());
    controlPlaneHint.ifPresent(builder::controlPlaneHint);
    return new OsSandboxedProcessLauncher()
        .launch(builder.build());
  }

  private static String awaitSessionNamespace(SandboxedProcess process, Path logFile) throws IOException {
    Instant deadline = Instant.now()
        .plus(BRIDGE_TIMEOUT);
    while (Instant.now()
        .isBefore(deadline)) {
      if (Files.readString(logFile)
          .contains(PAYLOAD_MARKER)) {
        Optional<String> namespace = sessionNamespaceOf(process);
        if (namespace.isPresent()) {
          return namespace.get();
        }
      }
      sleep();
    }
    String output = Files.readString(logFile);
    throw new AssertionError("the session's network namespace never became observable, payload output: " + output);
  }

  private static Optional<String> sessionNamespaceOf(SandboxedProcess process) {
    Optional<String> own = LinuxNetworkNamespaces.of(ProcessHandle.current()
        .pid());
    return ProcessHandle.of(process.pid())
        .stream()
        .flatMap(ProcessHandle::descendants)
        .map(handle -> LinuxNetworkNamespaces.of(handle.pid()))
        .flatMap(Optional::stream)
        .filter(namespace -> !own.equals(Optional.of(namespace)))
        .findFirst();
  }

  private static List<String> bridgesIn(String namespace) {
    return LinuxNetworkNamespaces.membersOf(namespace)
        .stream()
        .filter(member -> BRIDGE_COMMAND_NAME.equals(member.executableName()))
        .map(NetworkNamespaceMember::commandLine)
        .distinct()
        .toList();
  }

  private static List<NetworkNamespaceMember> remainingMembersOf(String namespace) {
    Instant deadline = Instant.now()
        .plus(TEARDOWN_GRACE);
    List<NetworkNamespaceMember> members = LinuxNetworkNamespaces.membersOf(namespace);
    while (!members.isEmpty() && Instant.now()
        .isBefore(deadline)) {
      sleep();
      members = LinuxNetworkNamespaces.membersOf(namespace);
    }
    return members;
  }

  private static void sleep() {
    try {
      Thread.sleep(POLL_INTERVAL.toMillis());
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
    }
  }
}
