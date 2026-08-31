package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.RulePath;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AppArmorPathEscapingTest {

  private static final List<String> AWKWARD_NAMES = List.of(
      "my project", "a,b", "c#d", "e{f}g", "h[i]j", "k!l", "m\tn", "o\np", "q'r", "s\\t",
      "praća", "日本", "u*v", "w?x", "y\"z", "0 1", "back\\"
  );

  @Test
  void unescapingIsTheExactInverseOfEscapingForEveryAwkwardName() {
    for (String name : AWKWARD_NAMES) {
      String path = "/workspace/" + name + "/file.txt";

      assertThat(AppArmorPathEscaping.unescape(AppArmorPathEscaping.escapeLiteralPath(path)))
          .as("round trip of %s", path)
          .isEqualTo(path);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"/workspace/src/Main.java", "/a-b_c.d/e", "/x/pem", "/y/id_rsa"})
  void leavesAPathMadeOnlyOfInertBytesExactlyAsItWas(String path) {
    assertThat(AppArmorPathEscaping.escapeLiteralPath(path))
        .isEqualTo(path);
  }

  @Test
  void escapesAWildcardLikeAnyOtherCharacterOfAPathNamedLiterally() {
    assertThat(AppArmorPathEscaping.escapeLiteralPath("/w/a b/**/*.pem"))
        .isEqualTo("/w/a\\040b/\\052\\052/\\052.pem");
  }

  @Test
  void theApiLiteralEntryPointAndTheGeneratorsOwnEscaperAgree() {
    // Two ways to say "every character of this path is literal": through the API's own entry point,
    // or through the escaper the generator uses for the paths warden names itself. A caller's rule
    // and warden's own reserved clause have to reach the same bytes, or one of them is a rule about a
    // path that does not exist.
    for (String name : AWKWARD_NAMES) {
      if (name.contains("\"")) {
        continue;
      }
      String path = "/workspace/" + name + "/file.txt";

      assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.literal(path)))
          .as("the two literal routes, for %s", name)
          .isEqualTo(AppArmorPathEscaping.escapeLiteralPath(path));
    }
  }

  @Test
  void escapesEveryByteOfAMultiByteCharacterSeparately() {
    assertThat(AppArmorPathEscaping.escapeLiteralPath("/w/praća"))
        .isEqualTo("/w/pra\\304\\207a");
  }

  @Test
  void aPatternCoversTheSamePathsAsAJavaGlobAsItDoesAsAnAppArmorPattern() {
    // The generator asks java.nio.file whether a pattern covers a real path. A brace or a bracket
    // AppArmor reads as a literal must not become group or class syntax on that side, and an escape
    // run must decode back to the character it stood for rather than to the digits it is spelled with.
    for (String name : AWKWARD_NAMES) {
      if (name.contains("\"")) {
        continue;
      }
      String escaped = AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/workspace/" + name));
      var matcher = FileSystems.getDefault()
          .getPathMatcher("glob:" + AppArmorPathEscaping.toJavaGlobPattern(escaped));

      assertThat(matcher.matches(Path.of("/workspace/" + name + "/file.txt")))
          .as("the named path, for %s", name)
          .isTrue();
      assertThat(matcher.matches(Path.of("/workspace/decoy/file.txt")))
          .as("a decoy, for %s", name)
          .isFalse();
    }
  }

  @Test
  void keepsGlobSyntaxLiveOnTheJavaSide() {
    var matcher = FileSystems.getDefault()
        .getPathMatcher(
            "glob:" + AppArmorPathEscaping.toJavaGlobPattern(
                AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/w/a b"))
            )
        );

    assertThat(matcher.matches(Path.of("/w/a b/deep/file.txt")))
        .isTrue();
    assertThat(matcher.matches(Path.of("/w/ab/deep/file.txt")))
        .isFalse();
  }
}
