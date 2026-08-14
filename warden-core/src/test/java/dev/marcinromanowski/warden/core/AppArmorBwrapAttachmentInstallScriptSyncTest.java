package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

// AppArmorBwrapAttachment.MANAGEMENT_SCRIPT is never read by any runtime code path - deliberately
// (see that class's own header comment for why the class never installs it itself). Its only job
// is being the canonical, version-controlled copy of what scripts/install-apparmor-bwrap-override.sh
// embeds by hand in its own heredoc. Nothing enforced the two stayed in sync until this test - a
// real, previously accepted gap, now closed.
class AppArmorBwrapAttachmentInstallScriptSyncTest {

  private static final String HEREDOC_START = "<<'MANAGEMENT_SCRIPT'";
  private static final String HEREDOC_END = "MANAGEMENT_SCRIPT";

  @Test
  void installScriptHeredocMatchesTheJavaConstantByteForByte() throws IOException {
    Path installScript = repoRoot()
        .resolve("scripts/install-apparmor-bwrap-override.sh");

    String embedded = extractHeredoc(Files.readString(installScript, StandardCharsets.UTF_8));

    assertThat(embedded)
        .as(
            "scripts/install-apparmor-bwrap-override.sh's embedded heredoc must stay byte-identical"
                + " to AppArmorBwrapAttachment.MANAGEMENT_SCRIPT - update both together"
        )
        .isEqualTo(AppArmorBwrapAttachment.MANAGEMENT_SCRIPT);
  }

  private static String extractHeredoc(String scriptContent) {
    List<String> lines = scriptContent.lines()
        .toList();
    int startIndex = indexOfLineEndingWith(lines, HEREDOC_START);
    int endIndex = indexOfLineEquals(lines, HEREDOC_END, startIndex + 1);
    return lines.subList(startIndex + 1, endIndex)
        .stream()
        .reduce("", (accumulated, line) -> accumulated + line + "\n");
  }

  private static int indexOfLineEndingWith(List<String> lines, String suffix) {
    for (int index = 0; index < lines.size(); index++) {
      if (lines.get(index)
          .endsWith(suffix)) {
        return index;
      }
    }
    throw new IllegalStateException("Could not find a line ending with " + suffix + " in the install script");
  }

  private static int indexOfLineEquals(List<String> lines, String value, int fromIndex) {
    for (int index = fromIndex; index < lines.size(); index++) {
      if (lines.get(index)
          .equals(value)) {
        return index;
      }
    }
    throw new IllegalStateException("Could not find the heredoc terminator " + value + " in the install script");
  }

  private static Path repoRoot() {
    Path candidate = Path.of(System.getProperty("user.dir"))
        .toAbsolutePath()
        .normalize();
    while (candidate != null) {
      if (Files.isRegularFile(candidate.resolve("settings.gradle.kts"))) {
        return candidate;
      }
      candidate = candidate.getParent();
    }
    throw new IllegalStateException("Could not locate the repo root (a directory containing settings.gradle.kts)");
  }
}
