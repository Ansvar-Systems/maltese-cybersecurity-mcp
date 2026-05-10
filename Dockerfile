# Multi-stage build — preserves better-sqlite3 native binding by carrying
# node_modules from builder into the production stage instead of running
# `npm ci` again (which strips postinstall scripts).
FROM node:20-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
# Install with scripts so better-sqlite3 postinstall builds the native binding.
RUN npm ci --omit=dev
RUN npm rebuild better-sqlite3 --build-from-source
COPY tsconfig.json ./
COPY src/ src/
RUN npm install --no-save typescript && npx tsc

FROM node:20-slim AS production
WORKDIR /app
ENV NODE_ENV=production
ENV CSIMALTA_DB_PATH=/app/data/csi-malta.db
COPY package.json package-lock.json* ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist/ dist/
COPY data/database.db data/csi-malta.db
RUN addgroup --system --gid 1001 mcp && \
    adduser --system --uid 1001 --ingroup mcp mcp && \
    chown -R mcp:mcp /app
USER mcp
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"
CMD ["node", "dist/src/http-server.js"]
