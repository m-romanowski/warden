package dev.marcinromanowski.warden.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class AaStatusProfiles {

  private static final Pattern PROFILES_OBJECT = Pattern.compile("\"profiles\"\\s*:\\s*\\{(.*?)\\}", Pattern.DOTALL);
  private static final Pattern ENTRY = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*\"([^\"]*)\"");

  private AaStatusProfiles() {
  }

  static Map<String, String> parse(String json) {
    Matcher object = PROFILES_OBJECT.matcher(json);
    if (!object.find()) {
      throw new AssertionError("aa-status reported no profiles object: " + json);
    }
    Map<String, String> profiles = new LinkedHashMap<>();
    Matcher entry = ENTRY.matcher(object.group(1));
    while (entry.find()) {
      profiles.put(entry.group(1)
          .replace("\\/", "/"), entry.group(2));
    }
    return Map.copyOf(profiles);
  }
}
