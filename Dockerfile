FROM amazoncorretto:17
COPY target/*.jar demo.jar
EXPOSE 8094
ENTRYPOINT ["java", "-jar", "demo.jar"]

