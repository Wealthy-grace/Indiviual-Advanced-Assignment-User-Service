## Multi-stage Dockerfile - Alternative approach
## Stage 1: Build stage
#FROM eclipse-temurin:17-jdk-jammy AS builder
#
## Set working directory for build
#WORKDIR /build
#
## Copy gradle wrapper and build files
#COPY gradlew .
#COPY gradle gradle
#COPY build.gradle .
#COPY settings.gradle .
#
## Copy source code
#COPY src src
#
## Make gradlew executable and build the application
#RUN chmod +x gradlew && \
#    ./gradlew clean bootJar -x test --no-daemon
#
## Stage 2: Runtime stage
#FROM eclipse-temurin:17-jre-jammy
#
## Set labels for better image management
#LABEL maintainer="godfrey10"
#LABEL version="1.0"
#LABEL description="User Service Spring Boot Application"
#
## Install runtime utilities
#RUN apt-get update && \
#    apt-get install -y --no-install-recommends \
#        curl \
#        wget \
#        netcat-openbsd \
#        && rm -rf /var/lib/apt/lists/*
#
## Create non-root user for security
#RUN groupadd -r appuser && useradd -r -g appuser appuser
#
## Set working directory
#WORKDIR /app
#
## Create logs directory with proper permissions
#RUN mkdir -p /app/logs && chown appuser:appuser /app/logs
#
## Copy the JAR from builder stage
#COPY --from=builder --chown=appuser:appuser /build/build/libs/*.jar app.jar
#
## Switch to non-root user
#USER appuser
#
## Expose port
#EXPOSE 8081
#
## Add environment variables with defaults
#ENV JAVA_OPTS="-Xmx512m -Xms256m -XX:+UseG1GC -XX:MaxGCPauseMillis=200"
#ENV SPRING_PROFILES_ACTIVE="prod"
#ENV SERVER_PORT=8081
#
## Health check
#HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
#    CMD curl -f http://localhost:8081/actuator/health || exit 1
#
## Run the application
#ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar app.jar"]


#TODO NEW ADDED USER SERVICE

# Multi-stage Dockerfile - Alternative approach
# Stage 1: Build stage
FROM eclipse-temurin:17-jdk-jammy AS builder

# Set working directory for build
WORKDIR /build

# Copy gradle wrapper and build files
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

# Copy source code
COPY src src

# Make gradlew executable and build the application
RUN chmod +x gradlew && \
    ./gradlew clean bootJar -x test --no-daemon

# Stage 2: Runtime stage
FROM eclipse-temurin:17-jre-jammy

# Set labels for better image management
LABEL maintainer="godfrey10"
LABEL version="1.0"
LABEL description="User Service Spring Boot Application"

# Install runtime utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        wget \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

# Copy the JAR from builder stage
COPY --from=builder --chown=appuser:appuser /build/build/libs/*.jar app.jar

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8081

# Add environment variables with defaults
ENV JAVA_OPTS="-Xmx512m -Xms256m -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/app/logs/heapdump.hprof"
# ✅ CHANGED: Set profile to "kubernetes" instead of "prod"
ENV SPRING_PROFILES_ACTIVE="kubernetes"
ENV SERVER_PORT=8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8081/actuator/health || exit 1

# Run the application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar app.jar"]