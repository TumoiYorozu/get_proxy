FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY filter_proxy.js ./
COPY allowlist.txt ./

EXPOSE 8080

ENTRYPOINT ["node", "filter_proxy.js"]

