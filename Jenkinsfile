pipeline {
    agent any

    environment {
        HARBOR_REGISTRY = '10.0.1.21:30002/'
        IMAGE_NAME      = 'devsecops/vulnerable-app'
        IMAGE_TAG       = "${BUILD_NUMBER}"

        SONAR_HOST      = 'http://10.0.1.21:32661/'

        KUBECONFIG      = credentials('kubeconfig-cred')
        HARBOR_CREDS    = credentials('harbor-credentials')
        NVD_API_KEY     = credentials('nvd-api-key')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
    }

    stages {

        // ─────────────────────────────────────────────
        // Stage 1 — Checkout
        // ─────────────────────────────────────────────
        stage('Checkout') {
            steps {
                checkout scm
                echo "Building branch: ${env.BRANCH_NAME} | commit: ${env.GIT_COMMIT}"
            }
        }

        // ─────────────────────────────────────────────
        // Stage 2 — Secret Scan
        // ─────────────────────────────────────────────
        stage('Secret Scan - TruffleHog') {
            steps {
                script {
                    sh '''
                        docker run --rm \
                          -v "${WORKSPACE}:/repo" \
                          trufflesecurity/trufflehog:latest \
                          filesystem /repo \
                          --json > trufflehog-report.json 2>&1 || true

                        FOUND=$(grep -c '"SourceMetadata"' trufflehog-report.json || true)

                        echo "TruffleHog findings: $FOUND"

                        if [ "$FOUND" -gt 0 ]; then
                            echo "⚠️ Potential secrets detected"
                            cat trufflehog-report.json
                        else
                            echo "✅ No secrets detected"
                        fi
                    '''

                    def found = sh(
                        script: "grep -c '\"SourceMetadata\"' trufflehog-report.json || true",
                        returnStdout: true
                    ).trim().toInteger()

                    if (found > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "Build marked UNSTABLE due to secret scan findings."
                    }
                }
            }

            post {
                always {
                    archiveArtifacts artifacts: 'trufflehog-report.json', allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 3 — Unit Tests
        // ─────────────────────────────────────────────
        stage('Unit Tests') {
            steps {
                dir('app') {
                    sh 'npm ci'
                    sh 'npm test -- --coverage'
                }
            }

            post {
                always {
                    junit allowEmptyResults: true,
                          testResults: 'app/test-results/**/*.xml'
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 4 — SonarQube Analysis
        // ─────────────────────────────────────────────
        stage('SAST - SonarQube') {
            steps {
                withSonarQubeEnv('sonarqube') {
                    dir('app') {
                        sh '''
                            npx sonar-scanner \
                              -Dsonar.projectKey=vulnerable-app \
                              -Dsonar.sources=. \
                              -Dsonar.exclusions=node_modules/**,coverage/** \
                              -Dsonar.host.url=${SONAR_HOST} \
                              -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
                        '''
                    }
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 5 — Quality Gate
        // ─────────────────────────────────────────────
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 6 — OWASP Dependency Check
        // ─────────────────────────────────────────────
        stage('SCA - OWASP Dependency Check') {
            steps {

                dependencyCheck(
                    additionalArguments: """
                        --scan app/
                        --format HTML
                        --format JSON
                        --format XML
                        --nvdApiKey ${NVD_API_KEY}
                        --out .
                        --failOnCVSS 8
                        --enableRetired
                    """,
                    odcInstallation: 'OWASP-Dependency-Check'
                )

                sh '''
                    echo "=== Dependency Check Reports ==="
                    find . -name "*dependency-check*"
                '''
            }

            post {
                always {
                    dependencyCheckPublisher(
                        pattern: '**/dependency-check-report.xml'
                    )

                    archiveArtifacts(
                        artifacts: '**/dependency-check-report.*',
                        allowEmptyArchive: true
                    )
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 7 — Build & Push Image
        // ─────────────────────────────────────────────
        stage('Build & Push Image') {
            steps {
                sh '''
                    echo ${HARBOR_CREDS_PSW} | \
                      docker login 10.0.1.21:30002 \
                      -u ${HARBOR_CREDS_USR} \
                      --password-stdin

                    docker build \
                      -t ${HARBOR_REGISTRY}${IMAGE_NAME}:${IMAGE_TAG} \
                      -t ${HARBOR_REGISTRY}${IMAGE_NAME}:latest \
                      -f app/Dockerfile .

                    docker push ${HARBOR_REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}

                    docker push ${HARBOR_REGISTRY}${IMAGE_NAME}:latest
                '''
            }
        }

        // ─────────────────────────────────────────────
        // Stage 8 — Trivy Scan
        // ─────────────────────────────────────────────
        stage('Image Scan - Trivy') {
            steps {
                script {

                    def exitCode = sh(
                        script: '''
                            docker run --rm \
                              aquasec/trivy:latest image \
                              --exit-code 1 \
                              --severity CRITICAL \
                              --format json \
                              --output trivy-report.json \
                              --username ${HARBOR_CREDS_USR} \
                              --password ${HARBOR_CREDS_PSW} \
                              ${HARBOR_REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}
                        ''',
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        error('Trivy found CRITICAL vulnerabilities. Blocking deploy.')
                    }
                }
            }

            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 9 — Kyverno Policy Gate
        // ─────────────────────────────────────────────
        stage('Kyverno Policy Gate') {
            steps {
                script {

                    def exitCode = sh(
                        script: '''
                            kyverno apply k8s/policies/ \
                              --resource k8s/deployment.yaml \
                              --detailed-results 2>&1 | tee kyverno-audit.txt

                            grep -q "FAIL" kyverno-audit.txt && exit 1 || exit 0
                        ''',
                        returnStatus: true
                    )

                    if (exitCode != 0) {

                        echo "Kyverno policy violations:"

                        sh 'cat kyverno-audit.txt'

                        error('Kyverno policy gate failed. Fix policy violations before deploying.')
                    }
                }
            }

            post {
                always {
                    archiveArtifacts artifacts: 'kyverno-audit.txt',
                                     allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────────
        // Stage 10 — Deploy to Kubernetes
        // ─────────────────────────────────────────────
        stage('Deploy to Kubernetes') {
            steps {

                sh '''
                    export KUBECONFIG=${KUBECONFIG}

                    sed -i "s|IMAGE_TAG_PLACEHOLDER|${IMAGE_TAG}|g" \
                        k8s/deployment.yaml

                    kubectl apply \
                      -f k8s/ \
                      --namespace=devsecops

                    kubectl rollout status \
                      deployment/vulnerable-app \
                      --namespace=devsecops \
                      --timeout=120s
                '''
            }
        }
    }

    post {

        success {
            echo "✅ Pipeline PASSED — image ${env.IMAGE_NAME}:${env.IMAGE_TAG} deployed."
        }

        unstable {
            echo "⚠️ Pipeline UNSTABLE — secrets were detected by TruffleHog. Review the archived report."
        }

        failure {
            echo "❌ Pipeline FAILED — check stage logs above."
        }

        always {
            cleanWs()
        }
    }
}
