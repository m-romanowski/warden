package dev.marcinromanowski.warden.core;

record NetworkNamespaceMember(
    long pid,
    String executableName,
    String commandLine
) {

}
