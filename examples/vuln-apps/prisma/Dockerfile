FROM node:18

COPY . /app
WORKDIR /app
RUN chmod +x /app/start.sh && npm install
RUN npm run build

CMD ["/app/start.sh"]