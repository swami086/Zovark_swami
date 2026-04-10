FROM node:20-alpine AS builder
WORKDIR /app
ARG VITE_OTEL_ENABLED=false
ARG VITE_OTEL_EXPORTER_OTLP_TRACES_URL=/otel/v1/traces
ARG VITE_SIGNOZ_UI_BASE=
ENV VITE_OTEL_ENABLED=$VITE_OTEL_ENABLED
ENV VITE_OTEL_EXPORTER_OTLP_TRACES_URL=$VITE_OTEL_EXPORTER_OTLP_TRACES_URL
ENV VITE_SIGNOZ_UI_BASE=$VITE_SIGNOZ_UI_BASE
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
