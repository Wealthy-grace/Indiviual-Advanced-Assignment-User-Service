# ===============================
# Stage 1: Build using Gradle
# ===============================
FROM gradle:8.5-jdk17 AS build

# Set working directory inside the container
WORKDIR /home/gradle/src

# Copy everything into the container (with correct permissions)
COPY --chown=gradle:gradle . .

# Build the Spring Boot JAR (skip tests to speed up build)
RUN gradle --no-daemon clean build -x test

# ===============================
# Stage 2: Run the Spring Boot JAR
# ===============================
FROM openjdk:17-jdk-slim

# Set working directory
WORKDIR /app

# Copy only the built JAR file from the build stage
COPY --from=build /home/gradle/src/build/libs/*.jar /app/app.jar

# Expose application port
EXPOSE 8083

# Set environment variables (timezone + locale)
ENV TZ=UTC \
    LANG=C.UTF-8 \
    JAVA_OPTS=""

# Run the JAR file
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
