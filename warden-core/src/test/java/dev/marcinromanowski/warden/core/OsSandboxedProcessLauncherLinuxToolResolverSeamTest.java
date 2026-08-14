package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

// Portable (no real Linux/bwrap needed): spoofs os.name/os.arch so the Linux branch of
// OsSandboxedProcessLauncher.launch() runs on any host, then proves the injected resolver - not
// this module's own PATH-scan default - is what LinuxTools/BwrapSandboxedProcessLauncher actually
// calls, by making it throw a distinctive exception the very first time it is asked to resolve
// "bwrap" and asserting that exact exception propagates out of launch().
class OsSandboxedProcessLauncherLinuxToolResolverSeamTest {

  private static final String OS_NAME_PROPERTY = "os.name";
  private static final String OS_ARCH_PROPERTY = "os.arch";

  @Test
  void usesTheInjectedLinuxToolResolverInsteadOfThePathDefault(@TempDir Path tempDirParameter) throws IOException {
    Path workspaceRoot = tempDirParameter.toRealPath();
    File logFile = Files.createTempFile("warden-linux-resolver-seam-", ".log")
        .toFile();
    SandboxLaunchRequest request = SandboxLaunchRequest.command("/bin/sh", "-c", "true")
        .sandboxRoot(workspaceRoot)
        .logFile(logFile)
        .build();
    OsSandboxedProcessLauncher launcher = new OsSandboxedProcessLauncher(
        _ -> {},
        name -> {
          throw new IllegalStateException("injected resolver reached for " + name);
        }
    );

    withSpoofedLinuxPlatform(
        () -> assertThatThrownBy(() -> launcher.launch(request))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("injected resolver reached for bwrap")
    );
  }

  private static void withSpoofedLinuxPlatform(Runnable body) {
    String originalOsName = System.getProperty(OS_NAME_PROPERTY);
    String originalOsArch = System.getProperty(OS_ARCH_PROPERTY);
    System.setProperty(OS_NAME_PROPERTY, "Linux");
    System.setProperty(OS_ARCH_PROPERTY, "amd64");
    try {
      body.run();
    } finally {
      System.setProperty(OS_NAME_PROPERTY, originalOsName);
      System.setProperty(OS_ARCH_PROPERTY, originalOsArch);
    }
  }
}
