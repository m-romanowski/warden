package dev.marcinromanowski.warden.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

// Assembles the real bwrap argv. bwrap does not do fine-grained filesystem access control at all
// here - that is AppArmor's job, evaluated lazily by the kernel against the profile
// AppArmorBwrapAttachment loads separately. bwrap's only remaining jobs are: (1) network
// namespace isolation (--unshare-net, a genuine kernel boundary AppArmor does not provide), and
// (2) making the sandbox root, the network bridge, and the unique per-session target binary
// AppArmorBwrapAttachment's px stacking rule matches, reachable at all. A single broad bind of the
// sandbox root is deliberate, not an oversight - the fine-grained ALLOW/DENY carve-outs within it
// are enforced by the AppArmor profile the sandboxed process runs under, not by which paths bwrap
// chooses to mount.
final class BwrapArgvGenerator {

  private static final List<String> BOOTSTRAP_READ_ONLY_PATHS =
      List.of("/bin", "/usr/bin", "/usr/lib", "/usr/share", "/lib", "/lib64", "/etc");

  private BwrapArgvGenerator() {
  }

  static List<String> generate(
      Path sandboxRoot,
      Path uniqueTargetBinary,
      BwrapBridgeMount bridgeMount,
      List<String> command
  ) {
    List<String> argv = new ArrayList<>();
    argv.add("bwrap");
    appendNamespaceAndBootstrap(argv);
    appendSandboxRootBind(argv, sandboxRoot);
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
