package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.FilesystemRule;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

// Ties a loaded profile's kernel-visible name to the exact file apparmor_parser needs to unload
// it again - both -r (load) and -R (remove) take the same file-path argument, not the profile's
// own declared name. Confirmed empirically (real Lima VM): passing the bare profile name to
// -R fails silently ("File <name> not found, skipping...", non-zero exit) rather than removing
// anything, which would leak every test's profile in the kernel's loaded-profile table forever
// without ever failing a test outright (each test uses a unique name, so nothing collides - the
// loaded profiles just pile up silently).
final class LoadedAppArmorProfile implements AutoCloseable {

  private final String profileName;
  private final Path profilePath;

  private LoadedAppArmorProfile(String profileName, Path profilePath) {
    this.profileName = profileName;
    this.profilePath = profilePath;
  }

  static LoadedAppArmorProfile load(List<FilesystemRule> rules) throws IOException {
    String profileName = "warden-enforcement-test-" + UUID.randomUUID()
        .toString()
        .replace("-", "");
    String profileText = AppArmorProfileGenerator.generate(profileName, rules);
    Path profilePath = Files.createTempFile(profileName, ".profile");
    Files.writeString(profilePath, profileText);
    TestProcesses.run(List.of("sudo", "apparmor_parser", "-r", profilePath.toString()));
    return new LoadedAppArmorProfile(profileName, profilePath);
  }

  SandboxExecResult run(String... command) throws IOException {
    List<String> fullCommand = new ArrayList<>();
    fullCommand.add("aa-exec");
    fullCommand.add("-p");
    fullCommand.add(profileName);
    fullCommand.add("--");
    fullCommand.addAll(List.of(command));
    return TestProcesses.run(fullCommand);
  }

  @Override
  public void close() {
    try {
      TestProcesses.run(List.of("sudo", "apparmor_parser", "-R", profilePath.toString()));
      Files.deleteIfExists(profilePath);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to unload AppArmor test profile " + profileName, e);
    }
  }
}
