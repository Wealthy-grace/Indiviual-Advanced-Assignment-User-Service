# Multi-stage build for Spring Boot application
FROM openjdk:17-jdk-slim as builder

# Set working directory
WORKDIR /app

# Copy gradle wrapper and build files
COPY gradle/ gradle/
COPY gradlew build.gradle settings.gradle ./

# Make gradlew executable
RUN chmod +x gradlew

# Download dependencies (this layer will be cached if dependencies don't change)
RUN ./gradlew dependencies --no-daemon

# Copy source code
COPY src/ src/

# Build the application
RUN ./gradlew build --no-daemon -x test

# Production stage
FROM openjdk:17-jdk-slim

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy the JAR file from builder stage
COPY --from=builder /app/build/libs/*.jar app.jar

# Change ownership to appuser
RUN chown appuser:appuser app.jar

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8081/actuator/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]