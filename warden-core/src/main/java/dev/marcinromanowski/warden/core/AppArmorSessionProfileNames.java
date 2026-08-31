package dev.marcinromanowski.warden.core;

import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

record AppArmorSessionProfileNames(
    String sessionId,
    String bwrapProfile,
    String unprivilegedProfile,
    String sessionProfile
) {

  private static final String STACK_SEPARATOR = "//&";
  private static final Pattern SESSION_ID = Pattern.compile("[0-9a-f]{32}");

  AppArmorSessionProfileNames {
    if (!isSessionId(Preconditions.nonBlank(sessionId, "sessionId"))) {
      throw new IllegalArgumentException("Session id must be 32 lowercase hex characters: " + sessionId);
    }
    Preconditions.nonBlank(bwrapProfile, "bwrapProfile");
    Preconditions.nonBlank(unprivilegedProfile, "unprivilegedProfile");
    Preconditions.nonBlank(sessionProfile, "sessionProfile");
  }

  static AppArmorSessionProfileNames forNewSession() {
    String sessionId = UUID.randomUUID()
        .toString()
        .replace("-", "");
    return new AppArmorSessionProfileNames(
        sessionId,
        "warden-bwrap-" + sessionId,
        "warden-unpriv-" + sessionId,
        "warden-sandbox-" + sessionId
    );
  }

  static boolean isSessionId(String candidate) {
    return SESSION_ID.matcher(candidate)
        .matches();
  }

  String stackedLabel() {
    return List.of(bwrapProfile, unprivilegedProfile, sessionProfile)
        .stream()
        .sorted()
        .collect(Collectors.joining(STACK_SEPARATOR));
  }

  String transitionTarget() {
    return bwrapProfile + STACK_SEPARATOR + unprivilegedProfile + STACK_SEPARATOR + sessionProfile;
  }
}
