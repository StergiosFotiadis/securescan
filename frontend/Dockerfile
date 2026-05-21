#FROM node:20-alpine

# WORKDIR /app

#COPY package.json package-lock.json* ./
#RUN npm install

#COPY . .

#EXPOSE 5173

#CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]




# Build stage
FROM node:20-slim as build-stage
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# Production stage
FROM nginx:stable-alpine
COPY --from=build-stage /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]