# Single-image deploy: builds the React client, serves it from Express.
FROM node:20-alpine
RUN apk add --no-cache git
WORKDIR /app

COPY server/package*.json server/
RUN npm ci --omit=dev --prefix server

COPY client/package*.json client/
RUN npm ci --prefix client

COPY . .
RUN npm run build --prefix client

ENV NODE_ENV=production PORT=4000
EXPOSE 4000
CMD ["node", "server/src/index.js"]
