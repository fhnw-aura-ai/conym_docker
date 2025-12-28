FROM openjdk:21-jdk

WORKDIR /app

# Copy the compiled Java class files and any other necessary resources
COPY . /app

# Expose port 80 & 8080(HTTP)
EXPOSE 8080
EXPOSE 80

# Run the Java application
CMD ["java", "-cp", "./app/*", "ch.fhnw.imvs.ai.aura.access.proxy.ConymAccessProxy"]
