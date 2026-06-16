pipeline {
    agent any

    environment {
        HARBOR_REGISTRY = 'harbor.local'
        IMAGE_NAME = 'devsecops/vulnerable-app'
        IMAGE_TAG = "${BUILD_NUMBER}"
        SONAR_HOST = 'http://sonarqube.local:9000'

        KUBECONFIG = credentials('kubeconfig-cred')
        HARBOR_CREDS = credentials('harbor-credentials')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "Building branch: ${env.BRANCH_NAME} | commit: ${env.GIT_COMMIT}"
            }
        }

        stage('Secret Scan - TruffleHog') {
            steps {
                script {
                    def exitCode = sh(
                        script: '''
                            docker run --rm \
                              -v "${WORKSPACE}:/repo" \
                              trufflesecurity/trufflehog:latest \
                              filesystem /repo \
                              --fail \
                              --json > trufflehog-report.json

                            FOUND=$(grep -c '"SourceMetadata"' trufflehog-report.json || true)

                            echo "TruffleHog findings: $FOUND"

                            if [ "$FOUND" -gt 0 ]; then
                              echo "Secrets detected"
                              cat trufflehog-report.json
                              exit 1
                            fi
                        ''',
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        error('TruffleHog detected secrets in the repository.')
                    }
                }
            }

            post {
                always {
                    archiveArtifacts artifacts: 'trufflehog-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('Unit Tests') {
            steps {
                dir('app') {
                    sh 'npm ci'
                    sh 'npm test'
                }
            }
        }
    }

    post {
        success {
            echo 'Pipeline PASSED'
        }

        failure {
            echo 'Pipeline FAILED'
        }

        always {
            cleanWs()
        }
    }
}
