package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SeatbeltGlobTranslatorTest {

  @ParameterizedTest
  @CsvSource({
      "'**/.env',/repo/project/.env,true",
      "'**/.env',/repo/project/.env.example,false",
      "'**/.env',/.env,true",
      "'**/*.pem',/repo/keys/server.pem,true",
      "'**/*.pem',/repo/keys/server.pem.bak,false",
      "'**/id_rsa*',/Users/x/.ssh/id_rsa,true",
      "'**/id_rsa*',/Users/x/.ssh/id_rsa.pub,true",
      "/workspace/**,/workspace/src/Main.java,true",
      "/workspace/**,/other/src/Main.java,false",
      // /a/**/b does NOT match /a/b - the literal '/' before 'b' in the translated regex still
      // requires at least one intermediate path segment. ** alone doesn't also absorb a leading
      // slash the way some other glob dialects' "zero-or-more segments" semantics would. Verified
      // empirically here, not assumed - an earlier version of this test guessed "true" and failed
      // against the real translator output.
      "/a/**/b,/a/b,false",
      "/a/**/b,/a/x/b,true",
      "/a/**/b,/a/x/y/b,true",
      "/a/**/b,/a/bsuffix,false",
      "**/report(final).pem,/report(final).pem,true",
      "**/report(final).pem,/reportXfinalY.pem,false",
      // Every character AppArmor needs a byte escape for is carried here by the regex escaping the
      // translation already does, so the two platforms accept the same rule list.
      "'/w/my project/**',/w/my project/src/Main.java,true",
      "'/w/my project/**',/w/myXproject/src/Main.java,false",
      "'/w/a,b/**','/w/a,b/x',true",
      "'/w/a#b/**',/w/a#b/x,true",
      // "\\" escapes the next character in a glob, so this pattern names "backslash" - the
      // directory really called "back\\slash" is named through a literal, asserted below.
      "'/w/back\\slash/**',/w/backslash/x,true",
      "'/w/back\\slash/**',/w/back\\slash/x,false"
  })
  void translatesGlobPatternsToMatchingRegex(String pattern, String candidate, boolean expectedMatch) {
    String regex = SeatbeltGlobTranslator.toRegex(RulePath.glob(pattern));

    assertThat(Pattern.matches(regex, candidate))
        .as("SBPL regex %s translated from pattern %s against %s", regex, pattern, candidate)
        .isEqualTo(expectedMatch);
  }

  @ParameterizedTest
  @CsvSource({
      "'/w/e{f}g','/w/e{f}g',true",
      "'/w/e{f}g',/w/efg,false",
      "'/w/h[i]j','/w/h[i]j',true",
      "'/w/h[i]j',/w/hij,false",
      "'/w/My*Project','/w/My*Project',true",
      "'/w/My*Project',/w/MyOtherProject,false",
      "'/w/q?r','/w/q?r',true",
      "'/w/q?r',/w/qXr,false",
      "'/w/back\\slash','/w/back\\slash',true",
      "'/w/back\\slash',/w/backslash,false"
  })
  void readsEveryCharacterOfTheLiteralPathAsItself(String path, String candidate, boolean expectedMatch) {
    String regex = SeatbeltGlobTranslator.toRegex(RulePath.literal(path));

    assertThat(Pattern.matches(regex, candidate))
        .as("SBPL regex %s translated from literal path %s against %s", regex, path, candidate)
        .isEqualTo(expectedMatch);
  }

  @Test
  void rejectsDoubleQuoteRatherThanClosingTheSbplStringLiteralEarly() {
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex(RulePath.glob("**/report\".pem")))
        .isInstanceOf(SandboxRuleRejectedException.class);
  }

  @Test
  void escapesBackslashesRatherThanLettingThemCollapse() {
    assertThat(SeatbeltGlobTranslator.toRegex(RulePath.literal("/w/back\\slash")))
        .isEqualTo("^/w/back\\\\slash$");
  }

  @Test
  void refusesNulBytesBecauseNoPathCanHoldOne() {
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex(RulePath.glob("/w/evil\0/**")))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("NUL");
  }
}
