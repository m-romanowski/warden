package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.MountAccess;
import dev.marcinromanowski.warden.api.PathMount;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

// Assembles the real bwrap argv. bwrap does not do fine-grained filesystem access control at all
// here - that is AppArmor's job, evaluated lazily by the kernel against the profile
// AppArmorProfile loads separately. bwrap's only remaining jobs are: (1) network namespace
// isolation (--unshare-net, a genuine kernel boundary AppArmor does not provide), and (2) making
// paths reachable at all - the sandbox root, the network bridge, the unique per-session target
// binary warden's own bwrap profile transitions through, and every caller-declared PathMount. A
// single broad bind of the sandbox root is deliberate, not an oversight - the fine-grained
// ALLOW/DENY carve-outs within it are enforced by the AppArmor profile the sandboxed process runs
// under, not by which paths bwrap chooses to mount.
final class BwrapArgvGenerator {

  private static final List<String> BOOTSTRAP_READ_ONLY_PATHS =
      List.of("/bin", "/usr/bin", "/usr/lib", "/usr/share", "/lib", "/lib64", "/etc");
  private static final List<Path> RESERVED_PATHS = reservedPaths();

  private BwrapArgvGenerator() {
  }

  static List<String> generate(
      Path sandboxRoot,
      List<PathMount> pathMounts,
      Path uniqueTargetBinary,
      BwrapBridgeMount bridgeMount,
      List<String> command
  ) {
    List<String> argv = new ArrayList<>();
    argv.add("bwrap");
    appendNamespaceAndBootstrap(argv);
    appendSandboxRootBind(argv, sandboxRoot);
    appendDeclaredMounts(argv, pathMounts);
    appendTargetBinaryBind(argv, uniqueTargetBinary);
    appendBridgeMount(argv, bridgeMount);
    argv.add("--die-with-parent");
    argv.add("--");
    argv.addAll(requireCommand(command));
    return argv;
  }

  private static void appendNamespaceAndBootstrap(List<String> argv) {
    argv.add("--unshare-net");
    argv.add("--tmpfs");
    argv.add("/");
    argv.add("--proc");
    argv.add("/proc");
    argv.add("--dev");
    argv.add("/dev");
    argv.add("--tmpfs");
    argv.add("/tmp");
    for (String bootstrapPath : BOOTSTRAP_READ_ONLY_PATHS) {
      argv.add("--ro-bind-try");
      argv.add(bootstrapPath);
      argv.add(bootstrapPath);
    }
  }

  private static void appendSandboxRootBind(List<String> argv, Path sandboxRoot) {
    Path required = Preconditions.nonNull(sandboxRoot, "sandboxRoot");
    argv.add("--bind");
    argv.add(required.toString());
    argv.add(required.toString());
  }

  private static void appendDeclaredMounts(List<String> argv, List<PathMount> pathMounts) {
    for (PathMount mount : Preconditions.nonNull(pathMounts, "pathMounts")) {
      rejectIfItShadowsThisGeneratorsOwnSetup(mount.path());
      String path = mount.path()
          .toString();
      argv.add(bindFlag(mount.access()));
      argv.add(path);
      argv.add(path);
    }
  }

  private static void rejectIfItShadowsThisGeneratorsOwnSetup(Path mountPath) {
    for (Path reserved : RESERVED_PATHS) {
      if (reserved.startsWith(mountPath)) {
        throw new IllegalArgumentException(
            "path mount " + mountPath + " would replace the sandbox's own " + reserved
        );
      }
    }
  }

  private static List<Path> reservedPaths() {
    List<Path> reserved = new ArrayList<>();
    reserved.add(Path.of("/"));
    reserved.add(Path.of("/proc"));
    reserved.add(Path.of("/dev"));
    reserved.add(Path.of("/tmp"));
    for (String bootstrapPath : BOOTSTRAP_READ_ONLY_PATHS) {
      reserved.add(Path.of(bootstrapPath));
    }
    return List.copyOf(reserved);
  }

  private static String bindFlag(MountAccess access) {
    return switch (access) {
      case READ_ONLY -> "--ro-bind";
      case READ_WRITE -> "--bind";
    };
  }

  private static void appendTargetBinaryBind(List<String> argv, Path uniqueTargetBinary) {
    Path required = Preconditions.nonNull(uniqueTargetBinary, "uniqueTargetBinary");
    argv.add("--ro-bind");
    argv.add(required.toString());
    argv.add(required.toString());
  }

  private static void appendBridgeMount(List<String> argv, BwrapBridgeMount bridgeMount) {
    BwrapBridgeMount required = Preconditions.nonNull(bridgeMount, "bridgeMount");
    argv.add("--bind");
    argv.add(
        required.hostSessionDirectory()
            .toString()
    );
    argv.add(
        required.inSandboxPath()
            .toString()
    );
  }

  private static List<String> requireCommand(List<String> command) {
    List<String> requiredCommand = List.copyOf(Preconditions.nonNull(command, "command"));
    if (requiredCommand.isEmpty()) {
      throw new IllegalArgumentException("command must not be empty");
    }
    return requiredCommand;
  }
}
