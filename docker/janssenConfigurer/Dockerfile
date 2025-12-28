FROM openjdk:21-jdk

WORKDIR /app

# Copy the compiled Java class files and any other necessary resources
COPY . /app

# Run the Java application
CMD ["java", "-cp", "./app/*", "ch.fhnw.imvs.ai.aura.customizer.ConfigInstaller"]
