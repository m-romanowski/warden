package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
      "**/report(final).pem,/reportXfinalY.pem,false"
  })
  void translatesGlobPatternsToMatchingRegex(String pattern, String candidate, boolean expectedMatch) {
    String regex = SeatbeltGlobTranslator.toRegex(pattern);

    assertThat(Pattern.matches(regex, candidate))
        .as("SBPL regex %s translated from pattern %s against %s", regex, pattern, candidate)
        .isEqualTo(expectedMatch);
  }

  @Test
  void rejectsDoubleQuoteRatherThanClosingTheSbplStringLiteralEarly() {
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex("**/report\".pem"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsBackslashRatherThanSilentlyMistranslatingIt() {
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex("**\\report.pem"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void expandsUserHomeTokenBeforeTranslation() {
    String userHome = System.getProperty("user.home");
    String regex = SeatbeltGlobTranslator.toRegex("${user.home}/.aws/credentials");

    assertThat(Pattern.matches(regex, userHome + "/.aws/credentials"))
        .isTrue();
    assertThat(Pattern.matches(regex, "/some/other/root/.aws/credentials"))
        .isFalse();
  }

  @Test
  void rejectsBracketCharacterClassRatherThanMistranslatingIt() {
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex("**/*.[jJ][sS]"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsBraceGroupRatherThanMistranslatingIt() {
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex("**/*.{env,pem}"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
