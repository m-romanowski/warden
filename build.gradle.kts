import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.plugins.quality.CheckstyleExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.api.tasks.testing.Test
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import org.gradle.jvm.toolchain.JavaLanguageVersion

plugins {
  java
  checkstyle
  `maven-publish`
}

val libsCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")
val checkstyleVersion = libsCatalog.findVersion("checkstyle").get().requiredVersion

allprojects {
  group = "dev.marcinromanowski"
  version = rootProject.version
}

subprojects {
  val isExample = path.startsWith(":examples:")
  apply(plugin = if (isExample) "application" else "java-library")
  apply(plugin = "checkstyle")
  if (!isExample) {
    apply(plugin = "maven-publish")
  }

  repositories {
    mavenCentral()
  }

  configure<JavaPluginExtension> {
    toolchain {
      languageVersion.set(JavaLanguageVersion.of(25))
    }
    if (!isExample) {
      withSourcesJar()
      withJavadocJar()
    }
  }

  configure<CheckstyleExtension> {
    toolVersion = checkstyleVersion
    configFile = rootProject.file("checkstyle/checkstyle.xml")
    configProperties["org.checkstyle.google.suppressionfilter.config"] =
        rootProject.file("checkstyle/checkstyle-suppressions.xml").absolutePath
  }

  if (!isExample) {
    configure<PublishingExtension> {
      publications {
        create<MavenPublication>("maven") {
          from(components["java"])
        }
      }
    }
  }

  tasks.withType<Test>().configureEach {
    useJUnitPlatform()
  }

  tasks.named<Test>("test") {
    useJUnitPlatform {
      excludeTags("benchmark")
    }
  }

  tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-parameters")
  }

  tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:all,-missing", "-quiet")
  }
}
