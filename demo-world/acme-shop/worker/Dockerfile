FROM node:20.11.0-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
CMD ["node", "worker.js"]
