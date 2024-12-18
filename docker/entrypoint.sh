#!/bin/bash
java -Djava.security.egd=file:/dev/./urandom \
            ${JVM_OPTS} \
            -jar /home/app.jar \
            --spring.profiles.active=${PROFILE:-prod} \
            --spring.cloud.nacos.config.server-addr=${NACOS_SERVER:-127.0.0.1:8848} \
            --spring.cloud.nacos.config.username=${NACOS_USERNAME:nacos} \
            --spring.cloud.nacos.config.password=${NACOS_PASSWORD:nacos}
