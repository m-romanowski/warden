package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AppArmorSessionProfileNamesTest {

  private static final String SESSION_ID = "0123456789abcdef0123456789abcdef";

  @Test
  void rendersTheStackedLabelInTheOrderTheKernelSortsItInto() {
    AppArmorSessionProfileNames names = new AppArmorSessionProfileNames(SESSION_ID, "zzz-bwrap", "aaa-unpriv", "mmm-session");

    assertThat(names.stackedLabel())
        .as("a signal peer= rule is matched against the label the kernel renders, which is"
            + " component-sorted - measured, with the same three names in any other order matching"
            + " nothing and the confined process unable to signal its own children")
        .isEqualTo("aaa-unpriv//&mmm-session//&zzz-bwrap");
  }

  @Test
  void startsTheTransitionTargetWithTheProfileItIsTakenFrom() {
    AppArmorSessionProfileNames names = new AppArmorSessionProfileNames(SESSION_ID, "zzz-bwrap", "aaa-unpriv", "mmm-session");

    assertThat(names.transitionTarget())
        .as("the kernel's no_new_privs exec-time rule permits the label change only when the new"
            + " stack's base component matches the profile it is taken from, which is bwrap's")
        .isEqualTo("zzz-bwrap//&aaa-unpriv//&mmm-session");
  }

  @Test
  void givesEverySessionThreeNamesNoOtherSessionShares() {
    AppArmorSessionProfileNames first = AppArmorSessionProfileNames.forNewSession();
    AppArmorSessionProfileNames second = AppArmorSessionProfileNames.forNewSession();

    assertThat(first.bwrapProfile())
        .as("two profiles attached to one exec path attach neither, measured as a launch that fails"
            + " as if it were unconfined - so a shared name is not a tidiness question")
        .isNotEqualTo(second.bwrapProfile());
    assertThat(first.unprivilegedProfile())
        .isNotEqualTo(second.unprivilegedProfile());
    assertThat(first.sessionProfile())
        .isNotEqualTo(second.sessionProfile());
  }
}
