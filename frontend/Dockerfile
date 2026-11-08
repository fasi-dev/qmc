# Production image: static build served by nginx (previously the Vite dev server ran in the container).
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# The API URL is compiled into the bundle, so it must be provided at BUILD time.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

FROM nginx:1.27-alpine
# nginx's entrypoint renders /etc/nginx/templates/*.template with envsubst (only defined variables, e.g. ${PORT}).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
ENV PORT=8080
EXPOSE 8080
