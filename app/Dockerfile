# ============================================================
# Stage 1 — builder: install deps and run tests
# ============================================================
FROM node:20-alpine AS builder
 
WORKDIR /build
 
COPY package*.json ./
 
# Install ALL deps (including devDependencies for tests)
RUN npm ci
 
COPY . .
 
# Run tests here — build fails fast if tests break
RUN npm test
 
# Prune dev deps — only ship production code
RUN npm prune --production
 
# ============================================================
# Stage 2 — final: minimal production image
# ============================================================
FROM node:20-alpine AS final
 
# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
 
WORKDIR /app
 
# Copy only production artefacts from builder
COPY --from=builder --chown=appuser:appgroup /build/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /build/app.js      ./
COPY --from=builder --chown=appuser:appgroup /build/package.json ./
 
USER appuser
 
EXPOSE 3000
 
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1
 
CMD ["node", "app.js"]

