package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.RulePath;
import java.util.ArrayList;
import java.util.List;

// Turns a RulePath into a pattern an AppArmor clause can carry.
//
// AppArmor's own path-pattern grammar spells the supported wildcards exactly as the rule language
// does ("**", "*", "?") - unlike Seatbelt's SBPL, which takes a full regex, there is no wildcard
// translation to do here. What there is to do is make the literal characters of the pattern survive
// AppArmor's unquoted, comma-terminated, comment-to-end-of-line rule syntax, which
// AppArmorPathEscaping does per byte. GlobPattern decides which characters those are, and refuses
// what neither platform can carry.
final class AppArmorGlobTranslator {

  private static final String RECURSIVE_ANYWHERE_PREFIX = "/**/";

  private AppArmorGlobTranslator() {
  }

  static String toAppArmorPattern(RulePath target) {
    StringBuilder pattern = new StringBuilder();
    RulePath required = Preconditions.nonNull(target, "target");
    for (GlobToken token : GlobPattern.parse(required.pattern())) {
      switch (token) {
        case GlobLiteral literal -> AppArmorPathEscaping.appendLiteral(pattern, literal.codePoint());
        case GlobWildcard.ANY_PATH -> pattern.append("**");
        case GlobWildcard.ANY_SEGMENT -> pattern.append('*');
        case GlobWildcard.SINGLE_CHARACTER -> pattern.append('?');
      }
    }
    return absolute(pattern.toString());
  }

  // FilesystemRule callers commonly express "this filename anywhere in the tree" as a
  // leading-"**"-without-a-slash pattern (e.g. "**/.env") - valid, meaningful glob syntax against
  // an already-absolute candidate path under java.nio.file's own PathMatcher semantics (which is
  // what these patterns are authored against), but AppArmor's own grammar requires every pattern
  // to be a genuinely absolute path starting with "/". Passing a pattern like "**/.env" straight
  // through produces a real AppArmor parser error ("Lexer found unexpected character: '*'"),
  // confirmed the first time this generator was exercised end to end with a real, non-empty rule
  // list - no earlier test here ever used a relative-looking pattern.
  //
  // The leading "/" does not preserve "anywhere" all the way up to the filesystem root. E.g., "/**/.env"
  // does not match "/.env", because AppArmor's "**" does not match the empty string between two
  // slashes. The same holds for a trailing "**" - "/x/**" does not match "/x/". So a caller's "match
  // this name anywhere" pattern covers every depth except a file sitting directly at "/".
  //
  // zeroSegmentForm below names that missing case, and AppArmorProfileGenerator emits it for DENY
  // clauses only. Under the java.nio.file PathMatcher semantics this file itself names two paragraphs
  // up, "**/config.json" does match "/config.json", so a caller writing that pattern did write the
  // root-level case, and SeatbeltProfileGenerator's own translation of it already grants exactly that
  // on macOS.
  //
  // The real reason is risk asymmetry, not authorship. Getting the zero-segment reading wrong on a
  // deny costs one more path the confined process cannot reach. Getting it wrong on an allow hands
  // out read or write at the filesystem root, where every wrong emission this generator could make
  // is maximally expensive. Deny is emitted because the cost of being wrong is bounded, and that
  // leaves an allow-side "/**/<name>" pattern granting the root-level case on macOS and not on
  // Linux - a real, deliberate divergence, recorded here because it is not otherwise visible.
  private static String absolute(String pattern) {
    return pattern.startsWith("/") ? pattern : "/" + pattern;
  }

  // The zero-segment readings of a leading "/**/" pattern - "/**/.env" also meaning "/.env" - which
  // AppArmor's own "**" does not cover, measured above.
  //
  // Every leading "/**/" is stripped, not just the first, so "/**/**/.env" yields both "/**/.env"
  // (depth one, which neither the original nor a single strip covers, since both "**" have to be
  // non-empty) and "/.env" (depth zero).
  //
  // Only the leading form is handled: it is the one this class itself manufactures out of a
  // caller's "match anywhere" pattern. An interior "**" ("/a/**/b") has the same gap, a workspace-scoped
  // "<root>/**/<name>" deny is a shape callers write, and does not cover "<root>/<name>". It is
  // left uncovered here deliberately: covering it means a clause per subset of the "**"
  // occurrences, and a caller who means the zero-depth case can name it in a rule of its own, which
  // is what the callers writing that shape already do. The leading form gets this treatment instead
  // because a caller cannot name it at all - "**/<name>" is the only spelling there is for it, and
  // it is this class that turns it into a pattern AppArmor reads as depth-one-or-more.
  //
  // A form that reduces to bare "/" is refused: "**/" as written by a caller means "any directory
  // anywhere", and turning that into a clause naming the filesystem root itself is a reach beyond
  // restating the caller's own pattern at zero depth.
  static List<String> zeroSegmentForms(String appArmorPattern) {
    List<String> forms = new ArrayList<>();
    String remaining = appArmorPattern;
    while (remaining.startsWith(RECURSIVE_ANYWHERE_PREFIX)) {
      remaining = "/" + remaining.substring(RECURSIVE_ANYWHERE_PREFIX.length());
      if (!remaining.equals("/")) {
        forms.add(remaining);
      }
    }
    return List.copyOf(forms);
  }
}
