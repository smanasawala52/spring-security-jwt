From openjdk:8
COPY ./target/*.jar /usr/agosh/sso/spring-security-jwt-0.0.1-SNAPSHOT.jar
EXPOSE 9193
CMD ["java","-jar","/usr/agosh/sso/spring-security-jwt-0.0.1-SNAPSHOT.jar"]