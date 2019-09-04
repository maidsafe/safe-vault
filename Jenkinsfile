properties([
    parameters([
        string(name: "ARTIFACTS_BUCKET", defaultValue: "safe-jenkins-build-artifacts"),
        string(name: "CACHE_BRANCH", defaultValue: "master"),
        string(name: "DEPLOY_BUCKET", defaultValue: "safe-vault"),
        string(name: "DEPLOY_BRANCH", defaultValue: "master"),
        string(name: "PUBLISH_BRANCH", defaultValue: "master"),
        string(name: "CLEAN_BUILD_BRANCH", defaultValue: "master")
    ])
])

stage("build & test") {
    parallel test_linux: {
        node("safe_vault") {
            checkout(scm)
            sh("make test")
        }
    },
    test_windows: {
        node("windows") {
            checkout(scm)
            retrieveCache()
            sh("make test")
        }
    },
    test_macos: {
        node("osx") {
            checkout(scm)
            sh("make test")
        }
    },
    clippy: {
        node("safe_vault") {
            checkout(scm)
            sh("make clippy")
        }
    },
    release_linux: {
        node("safe_vault") {
            checkout(scm)
            sh("make musl")
            stripArtifacts()
            packageBuildArtifacts("linux")
            uploadBuildArtifacts()
        }
    },
    release_windows: {
        node("windows") {
            checkout(scm)
            runReleaseBuild()
            stripArtifacts()
            packageBuildArtifacts("windows")
            uploadBuildArtifacts()
        }
    },
    release_macos: {
        node("osx") {
            checkout(scm)
            runReleaseBuild()
            stripArtifacts()
            packageBuildArtifacts("macos")
            uploadBuildArtifacts()
        }
    }
}

stage('deploy') {
    node('safe_vault') {
        if (env.BRANCH_NAME == "${params.DEPLOY_BRANCH}") {
            checkout(scm)
            sh("git fetch --tags --force")
            retrieveBuildArtifacts()
            if (versionChangeCommit()) {
                version = sh(
                    returnStdout: true,
                    script: "grep '^version' < Cargo.toml | head -n 1 | awk '{ print \$3 }' | sed 's/\"//g'").trim()
                packageArtifactsForDeploy(true)
                createTag(version)
                createGithubRelease(version)
                publishCrate()
            } else {
                packageArtifactsForDeploy(false)
                uploadDeployArtifacts()
            }
        } else {
            echo("${env.BRANCH_NAME} does not match the deployment branch. Nothing to do.")
        }
    }
    if (env.BRANCH_NAME == "${params.DEPLOY_BRANCH}") {
        build(job: '../rust_cache_build-safe_vault-windows', wait: false)
        build(job: '../docker_build-safe_vault_build_container', wait: false)
    }
}

def runReleaseBuild() {
    if (env.BRANCH_NAME == "${params.CLEAN_BUILD_BRANCH}") {
        sh("make build-clean")
    } else {
        sh("make build")
    }
}

def stripArtifacts() {
    sh("make strip-artifacts")
}

def retrieveCache() {
    if (!fileExists('target')) {
        withEnv(["SAFE_VAULT_BRANCH=${params.CACHE_BRANCH}"]) {
            sh("make retrieve-cache")
        }
    }
}

def packageBuildArtifacts(os) {
    branch = env.CHANGE_ID?.trim() ?: env.BRANCH_NAME
    withEnv(["SAFE_VAULT_BRANCH=${branch}",
             "SAFE_VAULT_BUILD_NUMBER=${env.BUILD_NUMBER}",
             "SAFE_VAULT_BUILD_OS=${os}"]) {
        sh("make package-build-artifacts")
    }
}

def uploadBuildArtifacts() {
    withAWS(credentials: 'aws_jenkins_build_artifacts_user', region: 'eu-west-2') {
        def artifacts = sh(returnStdout: true, script: 'ls -1 artifacts').trim().split("\\r?\\n")
        for (artifact in artifacts) {
            s3Upload(
                bucket: "${params.ARTIFACTS_BUCKET}",
                file: artifact,
                workingDir: "${env.WORKSPACE}/artifacts",
                acl: 'PublicRead')
        }
    }
}

def retrieveBuildArtifacts() {
    branch = env.CHANGE_ID?.trim() ?: env.BRANCH_NAME
    withEnv(["SAFE_VAULT_BRANCH=${branch}",
             "SAFE_VAULT_BUILD_NUMBER=${env.BUILD_NUMBER}"]) {
        sh("make retrieve-all-build-artifacts")
    }
}

def versionChangeCommit() {
    shortCommitHash = sh(
        returnStdout: true,
        script: "git log -n 1 --no-merges --pretty=format:'%h'").trim()
    message = sh(
        returnStdout: true,
        script: "git log --format=%B -n 1 ${shortCommitHash}").trim()
    return message.startsWith("Version change")
}

def packageArtifactsForDeploy(isVersionCommit) {
    if (isVersionCommit) {
        sh("make package-version-artifacts-for-deploy")
    } else {
        sh("make package-commit_hash-artifacts-for-deploy")
    }
}

def createTag(version) {
    withCredentials(
        [usernamePassword(
            credentialsId: "github_maidsafe_qa_user_credentials",
            usernameVariable: "GIT_USER",
            passwordVariable: "GIT_PASSWORD")]) {
        sh("git config --global user.name \$GIT_USER")
        sh("git config --global user.email qa@maidsafe.net")
        sh("git config credential.username \$GIT_USER")
        sh("git config credential.helper '!f() { echo password=\$GIT_PASSWORD; }; f'")
        sh("git tag -a ${version} -m 'Creating tag for ${version}'")
        sh("GIT_ASKPASS=true git push origin --tags")
    }
}

def createGithubRelease(version) {
    withCredentials(
        [usernamePassword(
            credentialsId: "github_maidsafe_token_credentials",
            usernameVariable: "GITHUB_USER",
            passwordVariable: "GITHUB_TOKEN")]) {
        sh("make deploy-github-release")
    }
}

// This publishCrate method is only called when we've determined that we're on the branch
// we want to deploy from (usually master). However, due to the fact that crates can't be
// deleted, we need extra protections for the publish. Sometimes during testing and
// development, the deploy branch will change, but we only really want to do the publish
// for a *real* release. For this reason we introduce a PUBLISH_BRANCH parameter, though in
// practice this should probably never change from master.
def publishCrate() {
    withCredentials(
        [string(
            credentialsId: 'crates_io_token', variable: 'CRATES_IO_TOKEN')]) {
        if (env.BRANCH_NAME == "${params.PUBLISH_BRANCH}") {
            sh("make publish")
        }
    }
}

def uploadDeployArtifacts() {
    withAWS(credentials: 'aws_jenkins_deploy_artifacts_user', region: 'eu-west-2') {
        def artifacts = sh(returnStdout: true, script: 'ls -1 deploy').trim().split("\\r?\\n")
        for (artifact in artifacts) {
            s3Upload(
                bucket: "${params.DEPLOY_BUCKET}",
                file: artifact,
                workingDir: "${env.WORKSPACE}/deploy",
                acl: 'PublicRead')
        }
    }
}
