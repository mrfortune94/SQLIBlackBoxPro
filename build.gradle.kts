// Top-level build file where you can add configuration options common to all sub-projects/modules.
buildscript {
    repositories {
        // Mirror repositories added to handle CI environments where dl.google.com may be blocked
        // Gradle tries repositories in order, so primary repositories are listed first with mirrors as fallbacks
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        // Mirror for Google Maven (Aliyun)
        maven {
            url = uri("https://maven.aliyun.com/repository/google")
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        // Mirror for Google Maven (Huawei Cloud)
        maven {
            url = uri("https://repo.huaweicloud.com/repository/maven/")
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        // Mirror for Maven Central (Aliyun)
        maven {
            url = uri("https://maven.aliyun.com/repository/central")
        }
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.2.2")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.22")
    }
}
