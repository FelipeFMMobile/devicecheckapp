FROM openjdk:17
ARG JAR_FILE=attest/build/libs/*-SNAPSHOT.jar
COPY ${JAR_FILE} stock-0.0.1-SNAPSHOT.jar

ENTRYPOINT ["java","-jar","/attest-0.0.1-SNAPSHOT.jar"]