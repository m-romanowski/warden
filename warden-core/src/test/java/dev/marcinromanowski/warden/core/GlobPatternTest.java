package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GlobPatternTest {

  @ParameterizedTest
  @ValueSource(strings = {"**/*.{pem,key}", "**/[.]env", "/w/{a,b}/**", "/w/x[0-9].pem"})
  void refusesAConstructNeitherPolicyLanguageHas(String pattern) {
    assertThatThrownBy(() -> GlobPattern.parse(pattern))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .asInstanceOf(InstanceOfAssertFactories.type(SandboxRuleRejectedException.class))
        .extracting(SandboxRuleRejectedException::targetPattern)
        .isEqualTo(pattern);
  }

  @Test
  void bothTranslatorsRefuseTheSameConstruct() {
    RulePath braceGroup = RulePath.glob("**/*.{pem,key}");

    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern(braceGroup))
        .isInstanceOf(SandboxRuleRejectedException.class);
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex(braceGroup))
        .isInstanceOf(SandboxRuleRejectedException.class);
  }

  @Test
  void acceptsTheEscapedSpellingOfARefusedConstruct() {
    assertThat(GlobPattern.parse("/w/a\\{b"))
        .containsExactly(
            new GlobToken.Literal('/'), new GlobToken.Literal('w'), new GlobToken.Literal('/'),
            new GlobToken.Literal('a'), new GlobToken.Literal('{'), new GlobToken.Literal('b')
        );
  }

  @Test
  void readsTheSupportedWildcardsAsWildcardsAndEverythingElseAsItself() {
    assertThat(GlobPattern.parse("**/a*b?c"))
        .containsExactly(
            GlobToken.Wildcard.ANY_PATH, new GlobToken.Literal('/'), new GlobToken.Literal('a'),
            GlobToken.Wildcard.ANY_SEGMENT, new GlobToken.Literal('b'),
            GlobToken.Wildcard.SINGLE_CHARACTER, new GlobToken.Literal('c')
        );
  }

  @Test
  void readsAnEscapedWildcardAsTheCharacterItIs() {
    assertThat(GlobPattern.parse("a\\*b"))
        .containsExactly(new GlobToken.Literal('a'), new GlobToken.Literal('*'), new GlobToken.Literal('b'));
  }

  @Test
  void refusesAPatternEndingInAnEscapeWithNothingToEscape() {
    assertThatThrownBy(() -> GlobPattern.parse("/w/trailing\\"))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("backslash");
  }

  @Test
  void quotesTheHomeDirectoryItSubstitutesRatherThanSplicingIt() {
    String pattern = RulePath.glob("${user.home}/.aws/credentials").pattern();

    assertThat(GlobPattern.parse(pattern))
        .containsExactlyElementsOf(GlobPattern.parse(RulePath.literal(System.getProperty("user.home") + "/.aws/credentials").pattern()));
  }

  @Test
  void literalAndGlobDisagreeAboutAWildcardAndAboutNothingElse() {
    assertThat(GlobPattern.parse(RulePath.literal("/w/My*Project").pattern()))
        .containsExactlyElementsOf(GlobPattern.parse("/w/My\\*Project"));
    assertThat(GlobPattern.parse(RulePath.glob("/w/My*Project").pattern()))
        .contains(GlobToken.Wildcard.ANY_SEGMENT);
  }
}
