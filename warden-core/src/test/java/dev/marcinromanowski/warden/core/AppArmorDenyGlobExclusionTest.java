package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AppArmorDenyGlobExclusionTest {

  @Test
  void recursiveDenyEndingInAnExtensionExemptsExactlyTheOnePath() {
    List<String> clauses = carve("/**/*.pem", "/private/etc/ssl/cert.pem");

    List<String> stillDenied = List.of(
        "/private/etc/ssl/cert2.pem",
        "/private/etc/ssl/cert.pem.pem",
        "/private/etc/ssl/ce.pem",
        "/private/etc/ssl/cert/cert.pem",
        "/private/etc/ssl2/cert.pem",
        "/private/etc/cert.pem",
        "/tmp/other/cert.pem"
    );

    assertThat(denied(clauses, "/private/etc/ssl/cert.pem"))
        .isFalse();
    assertThat(stillDenied)
        .allMatch(path -> denied(clauses, path));
    assertThat(denied(clauses, "/private/etc/ssl/cert.pe"))
        .isFalse();
  }

  @Test
  void recursiveDenyAlsoCoversTheRootLevelDepthItsOwnPatternMisses() {
    assertThat(denied(carve("/**/*.pem", "/private/etc/ssl/cert.pem"), "/cert.pem"))
        .isTrue();
  }

  @Test
  void recursiveDenyEndingInItsWildcardExemptsExactlyTheOnePath() {
    List<String> clauses = carve("/**/.env*", "/workspace/.env.example");

    List<String> stillDenied = List.of(
        "/workspace/.env",
        "/workspace/.env.example.bak",
        "/workspace/.env.exampl",
        "/workspace/sub/.env.example",
        "/work/.env.example",
        "/workspace2/.env.example"
    );

    assertThat(denied(clauses, "/workspace/.env.example"))
        .isFalse();
    assertThat(stillDenied)
        .allMatch(path -> denied(clauses, path));
    assertThat(denied(clauses, "/workspace/readme.txt"))
        .isFalse();
  }

  @Test
  void sameNamedFileInAnotherDirectoryStaysDenied() {
    assertThat(denied(carve("/**/.env*", "/workspace/.env.example"), "/elsewhere/.env.example"))
        .isTrue();
    assertThat(denied(carve("/**/.env", "/workspace/.env"), "/elsewhere/.env"))
        .isTrue();
  }

  @Test
  void literalDirectoryDenyDoesNotReachIntoSubdirectories() {
    List<String> clauses = carve("/workspace/.env*", "/workspace/.env.example");

    assertThat(denied(clauses, "/workspace/.env.example"))
        .isFalse();
    assertThat(denied(clauses, "/workspace/.env"))
        .isTrue();
    assertThat(denied(clauses, "/workspace/sub/.env"))
        .isFalse();
  }

  @Test
  void literalDirectoryDenyExemptsTheNameThatIsOnlyItsSuffix() {
    List<String> clauses = carve("/workspace/*.pem", "/workspace/.pem");

    assertThat(denied(clauses, "/workspace/.pem"))
        .isFalse();
    assertThat(denied(clauses, "/workspace/a.pem"))
        .isTrue();
  }

  @Test
  void literalDirectoryDenyNamingOnlyTheExcludedPathLeavesNothingToDeny() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/workspace/.env", "/workspace/.env"))
        .contains(List.of());
  }

  @Test
  void globMetacharacterInTheExcludedPathIsExemptedOnlyAtItsRealName() {
    List<String> clauses = carve("/**/*.pem", "/zz/a\\052b.pem");

    List<String> stillDenied = List.of("/zz/aXb.pem", "/zz/ab.pem", "/zz/a*b.pem.pem", "/zz/a*.pem");

    assertThat(denied(clauses, "/zz/a*b.pem"))
        .isFalse();
    assertThat(stillDenied)
        .allMatch(path -> denied(clauses, path));
  }

  @Test
  void fallsBackToEmptyForAnExcludedPathThatIsNotProperlyEscaped() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.pem", "/zz/a*b.pem"))
        .isEmpty();
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.pem", "/zz/a\\05.pem"))
        .isEmpty();
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.pem", "/zz/a,b.pem"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyForDenyPatternWithNoSlashAtAll() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath(".env*", "/workspace/.env.example"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyForFilenameGlobShapesTheTrieCannotExpress() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.env*", "/workspace/foo.env.example"))
        .isEmpty();
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/.en?", "/workspace/.env"))
        .isEmpty();
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.pem/", "/workspace/cert.pem"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyForLiteralDirectoryThatDoesNotMatchTheExcludedPathsOwnDirectory() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/workspace/.env*", "/elsewhere/.env.example"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyWhenTheExcludedNameDoesNotActuallyMatchTheGlob() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/.env*", "/workspace/readme.txt"))
        .isEmpty();
  }

  @Test
  void costsRoughlyTwoClausesPerEnumeratedByteOfTheExcludedPath() {
    assertThat(carve("/**/*.pem", "/private/etc/ssl/cert.pem"))
        .hasSize(2 * "/private/etc/ssl/cert".length());
    assertThat(carve("/**/.env*", "/workspace/.env.example"))
        .hasSize(2 * "/workspace".length() - 1 + 2 * ".example".length() + 1);
  }

  private static List<String> carve(String denyPattern, String excludedLiteralPath) {
    Optional<List<String>> carved = AppArmorDenyGlobExclusion.excludeLiteralPath(denyPattern, excludedLiteralPath);
    assertThat(carved)
        .isPresent();
    return carved.get();
  }

  private static boolean denied(List<String> clauses, String path) {
    return clauses.stream()
        .anyMatch(clause -> AppArmorPatternMatcher.matches(clause, path));
  }
}
