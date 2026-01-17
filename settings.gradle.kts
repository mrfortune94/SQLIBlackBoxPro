// Mirror repositories added to handle CI environments where dl.google.com may be blocked
// Gradle tries repositories in order, so primary repositories are listed first with mirrors as fallbacks
pluginManagement {
    repositories {
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
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
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
}

rootProject.name = "SQLiBlackBoxPro"
include(":app")
