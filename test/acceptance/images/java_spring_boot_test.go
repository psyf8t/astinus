//go:build acceptance

package images

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const javaSpringBootDockerfile = `FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
RUN mkdir -p src/main/java/demo && \
    printf '%s\n' \
      'package demo;' \
      'public class App { public static void main(String[] a){ System.out.println("ok"); } }' \
      > src/main/java/demo/App.java
COPY pom.xml .
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre
COPY --from=builder /build/target/demo-1.0.jar /app.jar
CMD ["java", "-jar", "/app.jar"]
`

const javaPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId>
  <artifactId>demo</artifactId>
  <version>1.0</version>
  <packaging>jar</packaging>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
`

func TestAcceptance_JavaSpringBoot(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	img := helpers.BuildImage(t, javaSpringBootDockerfile, map[string][]byte{
		"pom.xml": []byte(javaPOM),
	})
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Multi-modal Java extraction: at least one component should
	// carry a pkg:maven/* PURL.
	if !helpers.AnyPURLMatches(bom, func(p string) bool {
		return strings.HasPrefix(p, "pkg:maven/")
	}) {
		t.Error("expected at least one pkg:maven/* PURL — Java extractor missed all packages")
	}

	// 0 critical NTIA findings.
	ntia := helpers.GetNTIAFindings(bom)
	if got := len(helpers.FilterBySeverity(ntia, "critical")); got != 0 {
		t.Errorf("NTIA critical findings = %d, want 0", got)
	}

	// Origin coverage ≥ 90%.
	if cov := helpers.ComputeOriginCoverage(bom); cov < 0.9 {
		t.Errorf("origin coverage = %.2f, want ≥ 0.90", cov)
	}

	if dups := helpers.CountDuplicates(bom); dups != 0 {
		t.Errorf("duplicates = %d, want 0", dups)
	}
}
