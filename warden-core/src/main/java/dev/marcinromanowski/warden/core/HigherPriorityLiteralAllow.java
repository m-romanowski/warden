package dev.marcinromanowski.warden.core;

record HigherPriorityLiteralAllow(String pattern, String mode) {

  boolean covers(String denyMode) {
    for (int index = 0; index < denyMode.length(); index++) {
      if (mode.indexOf(denyMode.charAt(index)) < 0) {
        return false;
      }
    }
    return true;
  }
}
