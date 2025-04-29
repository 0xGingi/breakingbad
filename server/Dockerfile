FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json ./

RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*

RUN npm install

COPY . .

EXPOSE 1777

CMD ["node", "server.js"] 