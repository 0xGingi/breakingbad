FROM node:18-alpine

WORKDIR /app

COPY package.json ./

RUN if [ ! -s package.json ]; then \
    echo '{"name":"breaking-bad-server","version":"1.0.0","main":"server.js","dependencies":{"express":"^4.18.2","sqlite3":"^5.1.6","bcrypt":"^5.1.0","body-parser":"^1.20.2"}}' > package.json; \
    fi

RUN npm install

COPY . .

EXPOSE 1777

CMD ["node", "server.js"] 