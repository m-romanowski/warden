package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.FilesystemRule;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class LoadedAppArmorProfile implements AutoCloseable {

  private final AppArmorSessionProfileNames names;

  private LoadedAppArmorProfile(AppArmorSessionProfileNames names) {
    this.names = names;
  }

  static LoadedAppArmorProfile load(List<FilesystemRule> rules) throws IOException {
    AppArmorSessionProfileNames names = AppArmorSessionProfileNames.forNewSession();
    String body = AppArmorProfileGenerator.sessionProfileBody(
        names.sessionProfile(), rules, Optional.empty(), Optional.empty(), Optional.empty()
    );
    SandboxExecResult loaded = TestProcesses.run(policyHelperCommand("load", names.sessionId()), body);
    if (loaded.exitCode() != 0) {
      throw new AssertionError("failed to load AppArmor test profile: " + loaded.output());
    }
    return new LoadedAppArmorProfile(names);
  }

  private static List<String> policyHelperCommand(String action, String sessionId) {
    return List.of("sudo", AppArmorSessionPolicy.POLICY_HELPER.toString(), action, sessionId);
  }

  SandboxExecResult run(String... command) throws IOException {
    List<String> fullCommand = new ArrayList<>();
    fullCommand.add("aa-exec");
    fullCommand.add("-p");
    fullCommand.add(names.sessionProfile());
    fullCommand.add("--");
    fullCommand.addAll(List.of(command));
    return TestProcesses.run(fullCommand);
  }

  @Override
  public void close() {
    try {
      TestProcesses.run(policyHelperCommand("unload", names.sessionId()));
    } catch (IOException e) {
      throw new UncheckedIOException("failed to unload AppArmor test profile " + names.sessionProfile(), e);
    }
  }
}
