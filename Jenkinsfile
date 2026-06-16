pipeline {
agent any

```
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
                archiveArtifacts(
                    artifacts: 'trufflehog-report.json',
                    allowEmptyArchive: true
                )
            }
        }
    }

    stage('Unit Tests') {
        agent {
            docker {
                image 'node:20-alpine'
                reuseNode true
            }
        }

        steps {
            dir('app') {
                sh 'npm ci'
                sh 'npm test'
            }
        }

        post {
            always {
                junit(
                    allowEmptyResults: true,
                    testResults: 'app/coverage/junit.xml'
                )
            }
        }
    }

    stage('SAST - SonarQube') {
        steps {
            withSonarQubeEnv('SonarQube') {
                withCredentials([
                    string(
                        credentialsId: 'sonarqube-token',
                        variable: 'SONAR_TOKEN'
                    )
                ]) {

                    sh """
                        docker run --rm --network host \
                          -v ${WORKSPACE}/app:/app \
                          -e SONAR_HOST_URL=${SONAR_HOST} \
                          -e SONAR_TOKEN=${SONAR_TOKEN} \
                          sonarsource/sonar-scanner-cli:latest \
                          sonar-scanner \
                            -Dsonar.projectKey=devsecops-app \
                            -Dsonar.projectName=DevSecOps-Demo-App \
                            -Dsonar.sources=/app \
                            -Dsonar.exclusions=**/node_modules/**,**/coverage/** \
                            -Dsonar.host.url=${SONAR_HOST}
                    """
                }
            }
        }
    }

    stage('SonarQube Quality Gate') {
        steps {
            timeout(time: 10, unit: 'MINUTES') {
                waitForQualityGate abortPipeline: true
            }
        }
    }

    stage('OWASP Dependency-Check') {
        steps {
            sh """
                mkdir -p ${WORKSPACE}/odc-reports

                docker run --rm \
                  -v ${WORKSPACE}/app:/src \
                  -v ${WORKSPACE}/odc-reports:/report \
                  owasp/dependency-check:latest \
                  --scan /src \
                  --format HTML \
                  --format JSON \
                  --out /report \
                  --failOnCVSS 7 \
                  --enableRetired \
                  --project vulnerable-app
            """
        }

        post {
            always {
                publishHTML([
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'odc-reports',
                    reportFiles: 'dependency-check-report.html',
                    reportName: 'OWASP Dependency Check'
                ])

                archiveArtifacts(
                    artifacts: 'odc-reports/dependency-check-report.json',
                    allowEmptyArchive: true
                )
            }
        }
    }

    stage('Build & Push Image') {
        steps {
            sh """
                cd app

                echo "${HARBOR_CREDS_PSW}" | docker login ${HARBOR_REGISTRY} \
                    -u "${HARBOR_CREDS_USR}" \
                    --password-stdin

                docker build \
                    -t ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
                    -t ${HARBOR_REGISTRY}/${IMAGE_NAME}:latest \
                    .

                docker push ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                docker push ${HARBOR_REGISTRY}/${IMAGE_NAME}:latest
            """
        }
    }

    stage('Image Scan - Trivy') {
        steps {
            sh """
                mkdir -p ${WORKSPACE}/trivy-cache

                docker run --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  -v ${WORKSPACE}:/workspace \
                  -v ${WORKSPACE}/trivy-cache:/root/.cache/trivy \
                  aquasec/trivy:latest image \
                  --exit-code 1 \
                  --severity HIGH,CRITICAL \
                  --format json \
                  --output /workspace/trivy-report.json \
                  ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
            """
        }

        post {
            always {
                archiveArtifacts(
                    artifacts: 'trivy-report.json',
                    allowEmptyArchive: true
                )
            }

            failure {
                echo 'Trivy found HIGH or CRITICAL vulnerabilities.'
            }
        }
    }

    stage('Deploy to Kubernetes') {
        steps {
            sh """
                helm upgrade --install vulnerable-app ./helm/vulnerable-app \
                  --namespace devsecops \
                  --create-namespace \
                  --set image.repository=${HARBOR_REGISTRY}/${IMAGE_NAME} \
                  --set image.tag=${IMAGE_TAG} \
                  --wait \
                  --timeout 120s

                kubectl rollout status deployment/vulnerable-app-app \
                  -n devsecops \
                  --timeout=120s

                kubectl get pods -n devsecops
            """
        }
    }
}

post {
    success {
        echo "Pipeline PASSED - image ${IMAGE_TAG} deployed successfully."
    }

    failure {
        echo 'Pipeline FAILED. Check console output and reports.'
    }

    always {
        cleanWs()
    }
}
```

}

