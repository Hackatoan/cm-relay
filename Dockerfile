# Node 20 reached end-of-life (no more security releases); 24 is the current LTS.
FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
# Install exactly what package-lock.json pins (npm install ignored the lockfile
# here because it wasn't copied in, so audited fixes never reached the image).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server.js account.js ./
# Run unprivileged. /data must be writable by the `node` user (uid 1000):
# a bind-mounted host dir keeps its host ownership — chown it before deploying.
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 3000
CMD ["node", "server.js"]
