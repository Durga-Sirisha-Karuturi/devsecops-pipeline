pipeline {

  // ── Agent pod: all tools as separate containers, NO Docker daemon ──
  agent {
    kubernetes {
      yaml """
apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: workspace-vol
      emptyDir: {}
    - name: kaniko-secret
      secret:
        secretName: harbor-kaniko-secret
        items:
          - key: .dockerconfigjson
            path: config.json

  containers:

    # ── 1. Default container: runs shell steps ──────────────────────
    - name: jnlp
      image: jenkins/inbound-agent:latest
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent

    # ── 2. Node.js for unit tests ───────────────────────────────────
    - name: node
      image: node:20-alpine
      command: [cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent

    # ── 3. Kaniko for building and pushing image (no Docker needed) ─
    - name: kaniko
      image: gcr.io/kaniko-project/executor:latest
      command: [/busybox/cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent
        - name: kaniko-secret
          mountPath: /kaniko/.docker

    # ── 4. Trivy for image scanning ─────────────────────────────────
    - name: trivy
      image: aquasec/trivy:latest
      command: [cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent

    # ── 5. SonarQube scanner ─────────────────────────────────────────
    - name: sonar
      image: sonarsource/sonar-scanner-cli:latest
      command: [cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent

    # ── 6. OWASP Dependency-Check ────────────────────────────────────
    - name: owasp
      image: owasp/dependency-check:latest
      command: [cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent

    # ── 7. TruffleHog secret scanner ─────────────────────────────────
    - name: trufflehog
      image: trufflesecurity/trufflehog:latest
      command: [cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent

    # ── 8. Helm + kubectl for deploy ────────────────────────────────
    - name: helm
      image: alpine/helm:latest
      command: [cat]
      tty: true
      volumeMounts:
        - name: workspace-vol
          mountPath: /home/jenkins/agent
"""
      defaultContainer 'jnlp'
    }
  }

  environment {
    HARBOR_REGISTRY = "10.0.1.21:30002"
    IMAGE_NAME      = "devsecops/vulnerable-app"
    IMAGE_TAG       = "${BUILD_NUMBER}"
    SONAR_HOST      = "http://10.0.1.21:32661"
    KUBECONFIG      = credentials('kubeconfig-cred')
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
        echo "Branch: ${env.BRANCH_NAME} | Commit: ${env.GIT_COMMIT}"
      }
    }

    // ── SECURITY GATE 1: TruffleHog Secret Scan ──────────────────────
    stage('Secret Scan — TruffleHog') {
      steps {
        container('trufflehog') {
          script {
            def exitCode = sh(
              script: '''
                trufflehog filesystem ${WORKSPACE} \
                  --fail \
                  --json > ${WORKSPACE}/trufflehog-report.json 2>&1 || true

                FOUND=$(cat ${WORKSPACE}/trufflehog-report.json | \
                  python3 -c \
                  "import sys; lines=[l for l in sys.stdin.read().strip().split('\\n') if l]; print(len(lines))" \
                  2>/dev/null || echo 0)

                echo "TruffleHog findings: $FOUND"
                if [ "$FOUND" -gt "0" ]; then
                  echo "SECRETS DETECTED — failing build"
                  cat ${WORKSPACE}/trufflehog-report.json
                  exit 1
                fi
              ''',
              returnStatus: true
            )
            if (exitCode != 0) {
              error("TruffleHog detected secrets. Review trufflehog-report.json.")
            }
          }
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'trufflehog-report.json', allowEmptyArchive: true
        }
      }
    }

    // ── Unit Tests ────────────────────────────────────────────────────
    stage('Unit Tests') {
      steps {
        container('node') {
          sh '''
            cd ${WORKSPACE}/app
            npm ci
            npm test
          '''
        }
      }
      post {
        always {
          junit allowEmptyResults: true, testResults: 'app/coverage/junit.xml'
        }
      }
    }

    // ── SECURITY GATE 2: SonarQube SAST ──────────────────────────────
    stage('SAST — SonarQube') {
      steps {
        container('sonar') {
          withSonarQubeEnv('SonarQube') {
            sh """
              sonar-scanner \
                -Dsonar.projectKey=devsecops-app \
                -Dsonar.projectName="DevSecOps Demo App" \
                -Dsonar.sources=${WORKSPACE}/app \
                -Dsonar.exclusions=**/node_modules/**,**/coverage/** \
                -Dsonar.host.url=${SONAR_HOST} \
                -Dsonar.token=${SONAR_AUTH_TOKEN}
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

    // ── SECURITY GATE 3: OWASP Dependency-Check ──────────────────────
    stage('OWASP Dependency-Check') {
      steps {
        container('owasp') {
          sh """
            mkdir -p ${WORKSPACE}/odc-reports

            /usr/share/dependency-check/bin/dependency-check.sh \
              --scan ${WORKSPACE}/app \
              --format HTML \
              --format JSON \
              --out ${WORKSPACE}/odc-reports \
              --failOnCVSS 7 \
              --enableRetired \
              --project "vulnerable-app"
          """
        }
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

    // ── Build & Push with Kaniko (no Docker daemon) ───────────────────
    stage('Build & Push Image — Kaniko') {
      steps {
        container('kaniko') {
          sh """
            /kaniko/executor \
              --context=${WORKSPACE}/app \
              --dockerfile=${WORKSPACE}/app/Dockerfile \
              --destination=${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
              --destination=${HARBOR_REGISTRY}/${IMAGE_NAME}:latest \
              --insecure \
              --skip-tls-verify \
              --label build.number=${BUILD_NUMBER} \
              --label git.commit=${GIT_COMMIT}
          """
        }
      }
    }

    // ── SECURITY GATE 4: Trivy Image Scan ────────────────────────────
    // Trivy pulls the image from Harbor directly — no Docker socket needed
    stage('Image Scan — Trivy') {
      steps {
        container('trivy') {
          sh """
            mkdir -p ${WORKSPACE}/trivy-cache

            trivy image \
              --exit-code 1 \
              --severity HIGH,CRITICAL \
              --format json \
              --output ${WORKSPACE}/trivy-report.json \
              --cache-dir ${WORKSPACE}/trivy-cache \
              --insecure \
              ${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
          """
        }
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

    // ── Deploy to Kubernetes via Helm ─────────────────────────────────
    stage('Deploy to Kubernetes') {
      steps {
        container('helm') {
          sh """
            export KUBECONFIG=${KUBECONFIG}

            # Install kubectl into the helm container (alpine/helm has apk)
            apk add --no-cache kubectl 2>/dev/null || true

            helm upgrade --install vulnerable-app ${WORKSPACE}/helm/vulnerable-app \
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
  }

  post {
    failure { echo "Pipeline FAILED — check archived reports." }
    success { echo "Pipeline PASSED — image ${IMAGE_TAG} deployed." }
    always  { cleanWs() }
  }
}
