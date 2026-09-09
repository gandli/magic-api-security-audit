#!/usr/bin/env bash
# magic-api v2.2.2 复现环境一键搭建 (F-01 ~ F-08 动态复现)
# 用法: bash build_and_run.sh
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 1. 构建复现镜像 (Spring Boot 2.4.5 + magic-api 2.2.2, 默认无认证)
cat > "$DIR/env/Dockerfile" <<'DOCKERFILE'
FROM maven:3.8-openjdk-8 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q dependency:go-offline || true
COPY src ./src
RUN mvn -q package -DskipTests
FROM eclipse-temurin:8-jre
WORKDIR /app
RUN mkdir -p /data/magic-api && chmod 777 /data/magic-api
COPY --from=build /app/target/*.jar app.jar
EXPOSE 9999
ENTRYPOINT ["java", "-jar", "app.jar"]
DOCKERFILE

cat > "$DIR/env/pom.xml" <<'POM'
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.4.5</version>
  </parent>
  <groupId>com.example</groupId><artifactId>mtest</artifactId><version>1.0</version>
  <properties><java.version>8</java.version></properties>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>org.ssssssss</groupId><artifactId>magic-api-spring-boot-starter</artifactId><version>2.2.2</version></dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin>
    </plugins>
  </build>
</project>
POM

mkdir -p "$DIR/env/src/main/java/com/example" "$DIR/env/src/main/resources"
cat > "$DIR/env/src/main/java/com/example/Application.java" <<'JAVA'
package com.example;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class Application { public static void main(String[] a){ SpringApplication.run(Application.class, a); } }
JAVA
cat > "$DIR/env/src/main/resources/application.properties" <<'PROPS'
server.port=9999
magic-api.web=/magic/web
magic-api.resource.location=/data/magic-api
PROPS

docker build -t magic-api-poc "$DIR/env"
docker rm -f magic-api-poc 2>/dev/null || true
docker run -d --name magic-api-poc -p 9999:9999 magic-api-poc
echo "[+] 等待服务启动..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:9999/magic/web/config.json" >/dev/null 2>&1; then
    echo "[+] 服务就绪: http://localhost:9999/magic/web/config.json"
    echo "[+] 运行未授权 RCE: python3 scripts/exploit_f01_rce.py http://localhost:9999"
    exit 0
  fi
  sleep 2
done
echo "[!] 服务未在 60s 内就绪, 查看日志: docker logs magic-api-poc"
