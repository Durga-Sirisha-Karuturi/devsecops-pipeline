pipeline {
  agent any

  environment {
    HARBOR_REGISTRY = "http://10.0.1.21:30002"
    IMAGE_NAME      = "devsecops/vulnerable-app"
    IMAGE_TAG       = "${BUILD_NUMBER}"
    SONAR_HOST      = "http://10.0.1.21:32661"
    KUBECONFIG      = credentials('kubeconfig-cred')
    HARBOR_CREDS    = credentials('harbor-credentials')
  }

  options {
    buildDiscarder(logRotator(numToKeepStr: '10'))
    timestamps()
    timeout(time: 45, unit: 'MINUTES')
  }

  stages {

    // ------------------------------------------------------------------
    stage('Checkout') {
      steps {
        checkout scm
        echo "Building branch: ${env.BRANCH_NAME} | commit: ${env.GIT_COMMIT}"
      }
    }

    // ------------------------------------------------------------------
    // SECURITY GATE 1: Secret Detection with TruffleHog
    // ------------------------------------------------------------------
    stage('Secret Scan — TruffleHog') {
      steps {
        script {
          def exitCode = sh(
            script: '''
              docker run --rm \
                -v "${WORKSPACE}:/repo" \
                trufflesecurity/trufflehog:latest \
                filesystem /repo \
                --fail \
                --json > trufflehog-report.json 2>&1 || true

              FOUND=$(cat trufflehog-report.json | \
                python3 -c \
                "import sys; lines=[l for l in sys.stdin.read().strip().split('\\n') if l]; print(len(lines))" \
                2>/dev/null || echo 0)

              echo "TruffleHog findings: $FOUND"
              if [ "$FOUND" -gt "0" ]; then
                echo "SECRETS DETECTED — failing build"
                cat trufflehog-report.json
                exit 1
              fi
            ''',
            returnStatus: true
          )
          if (exitCode != 0) {
            error("TruffleHog detected secrets in the codebase. Review trufflehog-report.json.")
          }
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'trufflehog-report.json', allowEmptyArchive: true
        }
      }
    }

    // ------------------------------------------------------------------
    // Unit Tests
    // ------------------------------------------------------------------
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
          junit allowEmptyResults: true, testResults: 'app/coverage/junit.xml'
        }
      }
    }

    // ------------------------------------------------------------------
    // SECURITY GATE 2: SAST with SonarQube
    // ------------------------------------------------------------------
    stage('SAST — SonarQube') {
      steps {
        withSonarQubeEnv('SonarQube') {
          sh """
            docker run --rm --network host \
              -v ${WORKSPACE}/app:/app \
              -e SONAR_HOST_URL=${SONAR_HOST} \
              -e SONAR_TOKEN=${SONAR_AUTH_TOKEN} \
              sonarsource/sonar-scanner-cli:latest \
              sonar-scanner \
                -Dsonar.projectKey=devsecops-app \
                -Dsonar.projectName="DevSecOps Demo App" \
                -Dsonar.sources=/app \
                -Dsonar.exclusions=**/node_modules/**,**/coverage/** \
                -Dsonar.host.url=${SONAR_HOST}
          """
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

    // ------------------------------------------------------------------
    // SECURITY GATE 3: OWASP Dependency-Check
    // ------------------------------------------------------------------
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
            --project "vulnerable-app"
        """
      }
      post {
        always {
          publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: 'odc-reports',
            reportFiles: 'dependency-check-report.html',
            reportName: 'OWASP Dependency Check'
          ])
          archiveArtifacts artifacts: 'odc-reports/dependency-check-report.json'
        }
      }
    }

    // ------------------------------------------------------------------
    // Build and Push Image to Harbor
    // ------------------------------------------------------------------
    stage('Build & Push Image') {
      steps {
        sh """
          cd app

          echo "${HARBOR_CREDS_PSW}" | docker login ${HARBOR_REGISTRY} \
            -u "${HARBOR_CREDS_USR}" --password-stdin

          docker build \
            --tag ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
            --tag ${HARBOR_REGISTRY}/${IMAGE_NAME}:latest \
            --label "build.number=${BUILD_NUMBER}" \
            --label "git.commit=${GIT_COMMIT}" \
            --label "git.branch=${BRANCH_NAME}" \
            .

          docker push ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
          docker push ${HARBOR_REGISTRY}/${IMAGE_NAME}:latest
        """
      }
    }

    // ------------------------------------------------------------------
    // SECURITY GATE 4: Image Vulnerability Scan with Trivy
    // ------------------------------------------------------------------
    stage('Image Scan — Trivy') {
      steps {
        sh """
          mkdir -p ${WORKSPACE}/trivy-cache

          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v ${WORKSPACE}/trivy-cache:/root/.cache/trivy \
            aquasec/trivy:latest image \
            --exit-code 1 \
            --severity HIGH,CRITICAL \
            --format json \
            --output /tmp/trivy-report.json \
            ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}

          cp /tmp/trivy-report.json ${WORKSPACE}/trivy-report.json
        """
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
        }
        failure {
          echo "Trivy found HIGH/CRITICAL vulnerabilities. Check trivy-report.json."
        }
      }
    }

    // ------------------------------------------------------------------
    // Deploy to kubeadm Cluster via Helm
    // ------------------------------------------------------------------
    stage('Deploy to Kubernetes') {
      steps {
        sh """
          export KUBECONFIG=${KUBECONFIG}

          helm upgrade --install vulnerable-app ./helm/vulnerable-app \
            --namespace devsecops \
            --create-namespace \
            --set image.tag=${IMAGE_TAG} \
            --set image.repository=${HARBOR_REGISTRY}/${IMAGE_NAME} \
            --set labels.environment=production \
            --wait \
            --timeout 120s

          kubectl rollout status deployment/vulnerable-app-app \
            -n devsecops --timeout=120s

          echo "Deployed image tag: ${IMAGE_TAG}"
          kubectl get pods -n devsecops
        """
      }
    }
  }

  post {
    failure {
      echo "Pipeline FAILED at stage. Check archived reports and console output."
    }
    success {
      echo "Pipeline PASSED — image ${IMAGE_TAG} deployed to kubeadm cluster."
    }
    always {
      cleanWs()
    }
  }
}
