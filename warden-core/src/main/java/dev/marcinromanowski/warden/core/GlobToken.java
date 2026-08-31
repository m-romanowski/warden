package dev.marcinromanowski.warden.core;

sealed interface GlobToken permits GlobLiteral, GlobWildcard {
}
