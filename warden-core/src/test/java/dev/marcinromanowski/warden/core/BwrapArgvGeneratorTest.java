package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.PathMount;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class BwrapArgvGeneratorTest {

  private static final Path SANDBOX_ROOT = Path.of("/workspace");
  private static final Path SESSION_DIRECTORY = Path.of("/session");
  private static final Path TARGET_BINARY = SESSION_DIRECTORY.resolve("target-shell");
  private static final Path PROFILE_DIRECTORY = Path.of("/home/agent/.config/tool");
  private static final Path CACHE_DIRECTORY = Path.of("/home/agent/.cache/tool");
  private static final BwrapBridgeMount BRIDGE_MOUNT =
      new BwrapBridgeMount(SESSION_DIRECTORY, Path.of("/run/warden-bridge"));
  private static final List<String> COMMAND = List.of("/bin/sh", "-c", "true");

  @Test
  void emitsNoDeclaredMountArgumentsWhenNoneAreDeclared() {
    List<String> argv = generate(List.of());

    // The only non-try binds left are the essential ones: the target binary read-only, the
    // sandbox root and the network bridge read-write.
    assertThat(argv)
        .filteredOn("--ro-bind"::equals)
        .hasSize(1);
    assertThat(argv)
        .filteredOn("--bind"::equals)
        .hasSize(2);
  }

  @Test
  void emitsReadOnlyMountsAsRoBindAtTheIdenticalSourceAndDestination() {
    List<String> argv = generate(List.of(PathMount.readOnly(PROFILE_DIRECTORY)));

    assertThat(argv)
        .containsSequence("--ro-bind", PROFILE_DIRECTORY.toString(), PROFILE_DIRECTORY.toString());
  }

  @Test
  void emitsReadWriteMountsAsBindAtTheIdenticalSourceAndDestination() {
    List<String> argv = generate(List.of(PathMount.readWrite(CACHE_DIRECTORY)));

    assertThat(argv)
        .containsSequence("--bind", CACHE_DIRECTORY.toString(), CACHE_DIRECTORY.toString());
  }

  @Test
  void emitsDeclaredMountsAfterTheSandboxRootBindAndBeforeTheTargetBinaryBind() {
    List<String> argv = generate(List.of(PathMount.readWrite(CACHE_DIRECTORY)));

    assertThat(argv)
        .containsSubsequence(
            SANDBOX_ROOT.toString(),
            CACHE_DIRECTORY.toString(),
            TARGET_BINARY.toString()
        );
  }

  @Test
  void emitsDeclaredMountsInDeclarationOrder() {
    List<PathMount> mounts = List.of(
        PathMount.readOnly(PROFILE_DIRECTORY),
        PathMount.readWrite(CACHE_DIRECTORY)
    );

    List<String> argv = generate(mounts);

    assertThat(argv)
        .containsSubsequence(
            "--ro-bind",
            PROFILE_DIRECTORY.toString(),
            "--bind",
            CACHE_DIRECTORY.toString()
        );
  }

  @Test
  void keepsTheCommandLastBehindTheArgumentSeparator() {
    List<String> argv = generate(List.of(PathMount.readOnly(PROFILE_DIRECTORY)));

    assertThat(argv.subList(argv.indexOf("--") + 1, argv.size()))
        .isEqualTo(COMMAND);
  }

  @Test
  void refusesMountsThatWouldReplaceThePrivateTemporaryFilesystem() {
    assertThatThrownBy(() -> generate(List.of(PathMount.readWrite(Path.of("/tmp")))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("/tmp");
  }

  @Test
  void refusesMountsThatWouldReplaceTheReadOnlyBootstrap() {
    assertThatThrownBy(() -> generate(List.of(PathMount.readWrite(Path.of("/etc")))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("/etc");
  }

  @Test
  void refusesMountsSittingAboveReservedPaths() {
    assertThatThrownBy(() -> generate(List.of(PathMount.readOnly(Path.of("/usr")))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("/usr");
  }

  private static List<String> generate(List<PathMount> pathMounts) {
    return BwrapArgvGenerator.generate(SANDBOX_ROOT, pathMounts, TARGET_BINARY, BRIDGE_MOUNT, COMMAND);
  }
}
