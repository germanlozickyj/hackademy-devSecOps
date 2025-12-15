FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN apk add --no-cache python3 make g++ \
  && npm install --only=production

COPY . .

EXPOSE 8080

CMD ["node", "server.js"]