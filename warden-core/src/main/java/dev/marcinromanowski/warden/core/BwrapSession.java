package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxTimeouts;
import java.nio.file.Path;

record BwrapSession(
    Path root,
    BwrapSessionLock lock,
    SandboxTimeouts timeouts
) implements AutoCloseable {

  private static final String SESSION_SUBDIRECTORY = "session";
  private static final String TOOLS_SUBDIRECTORY = "tools";

  Path sessionDirectory() {
    return root.resolve(SESSION_SUBDIRECTORY);
  }

  Path toolsDirectory() {
    return root.resolve(TOOLS_SUBDIRECTORY);
  }

  @Override
  public void close() {
    AppArmorSessionPolicy.unload(
        root.getFileName()
            .toString(),
        timeouts
    );
    SandboxSessionDirectories.deleteQuietly(root);
    lock.close();
  }
}
