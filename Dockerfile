# Guardline backend.
#
# Why Docker instead of Render's native Node runtime: the @moss-dev/moss-core
# native binding (js-binding.linux-x64-gnu.node) is compiled against GLIBC_2.38.
# Render's native image ships an older glibc, so dlopen fails at runtime with
#   "version `GLIBC_2.38' not found (required by .../moss-core/...node)"
# and moss-core masks it as a generic "Cannot find native binding".
# Debian 13 "trixie" ships glibc 2.41 (>= 2.38), so the binding loads cleanly.
FROM node:22-trixie-slim

WORKDIR /app/guardline/backend

# Install deps first for layer caching. No package-lock is committed (it pins a
# host-specific resolution), so use `npm install`, not `npm ci`.
COPY guardline/backend/package.json ./
RUN npm install --omit=dev

# server.js serves ../frontend and reads ../data/scam-patterns.json, so the
# whole guardline/ tree must be present relative to the backend dir.
COPY guardline /app/guardline

ENV NODE_ENV=production
# Render injects PORT; server.js falls back to 3000 locally.
EXPOSE 3000
CMD ["node", "server.js"]
