package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

// Resolves bwrap/socat/apparmor_parser/aa-exec by name. Defaults to a plain PATH scan (this
// project's own tests and enforcement checks already rely on exactly this resolution shape). The
// constructor-injected resolver function is the seam a stricter embedder (e.g. one that only
// trusts its own vendored/Managed-Tool binaries, never PATH) can supply instead.
final class LinuxTools {

  private final Function<String, Path> resolver;

  LinuxTools() {
    this(LinuxTools::resolveFromPath);
  }

  LinuxTools(Function<String, Path> resolver) {
    this.resolver = Preconditions.nonNull(resolver, "resolver");
  }

  Path resolveExecutable(String name) {
    return resolver.apply(Preconditions.nonBlank(name, "name"));
  }

  private static Path resolveFromPath(String name) {
    String pathValue = System.getenv("PATH");
    if (pathValue == null || pathValue.isBlank()) {
      throw missing(name);
    }
    for (String entry : pathValue.split(File.pathSeparator)) {
      if (entry.isBlank()) {
        continue;
      }
      Path candidate = Path.of(entry)
          .resolve(name)
          .toAbsolutePath()
          .normalize();
      if (Files.isExecutable(candidate)) {
        return candidate;
      }
    }
    throw missing(name);
  }

  private static SandboxEstablishmentException missing(String name) {
    return new SandboxEstablishmentException(
        name + " not found on PATH - required for Linux sandbox enforcement; install it or add it to PATH."
    );
  }
}
