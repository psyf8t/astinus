package scanners

// Log4ShellDockerfile is the shared dockerfile used by the three
// vuln-scanner integration tests. Pulls log4j-core 2.14.1 — the
// version that contains CVE-2021-44228 (Log4Shell) — so each
// scanner has the same surface to find.
const Log4ShellDockerfile = `FROM eclipse-temurin:11-jre-alpine
RUN apk add --no-cache wget
RUN mkdir -p /opt/jars && \
    wget -q https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar \
        -O /opt/jars/log4j-core.jar
`

// CVELog4Shell is the CVE id every scanner under test must find.
const CVELog4Shell = "CVE-2021-44228"
