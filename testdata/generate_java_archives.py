"""Rebuild the tiny Java archive fixtures without a Java toolchain."""

from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
import warnings

ROOT = Path(__file__).parent / "fixtures"


def archive(entries):
    return archive_list(entries.items())


def archive_list(entries):
    output = BytesIO()
    with ZipFile(output, "w") as jar:
        for name, content in entries:
            info = ZipInfo(name, (2024, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                jar.writestr(info, content)
    return output.getvalue()


def descriptor(group, artifact, version):
    return {f"META-INF/maven/{group}/{artifact}/pom.properties":
            f"groupId={group}\nartifactId={artifact}\nversion={version}\n"}


def pom(group, artifact, version, repository):
    return {f"META-INF/maven/{group}/{artifact}/pom.xml":
            f'<project xmlns="http://maven.apache.org/POM/4.0.0">'
            f'<groupId>{group}</groupId><artifactId>{artifact}</artifactId>'
            f'<version>{version}</version><scm><url>{repository}</url></scm></project>'}


def write(fixture, name, data):
    directory = ROOT / fixture
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


sample = descriptor("com.example", "sample", "1.0.0")
sample.update(pom("com.example", "sample", "1.0.0", "https://github.com/example/sample"))
write("java-jar-basic", "sample.jar", archive(sample))

connection = descriptor("com.example", "connection-only", "1.0.0")
connection["META-INF/maven/com.example/connection-only/pom.xml"] = (
    '<project><groupId>com.example</groupId><artifactId>connection-only</artifactId>'
    '<version>1.0.0</version><scm><connection>'
    'scm:git:https://github.com/example/connection-only.git'
    '</connection></scm></project>'
)
write("java-jar-connection", "connection.jar", archive(connection))

bad_pom = descriptor("com.example", "bad-pom", "1.0.0")
bad_pom["META-INF/maven/com.example/bad-pom/pom.xml"] = "<project><scm><url>broken"
write("java-pom-invalid", "bad-pom.jar", archive(bad_pom))

unsafe_pom = descriptor("com.example", "unsafe-pom", "1.0.0")
unsafe_pom.update(pom("com.example", "unsafe-pom", "1.0.0", "https://user:hidden@github.com/example/token-secret/repo?token=secret"))
write("java-pom-unsafe", "unsafe-pom.jar", archive(unsafe_pom))

lib_a_content = descriptor("org.example", "lib-a", "2.0.0")
lib_a_content.update(pom("org.example", "lib-a", "2.0.0", "https://user:hidden@github.com/example/lib-a?token=secret"))
lib_a = archive(lib_a_content)
lib_b = archive(descriptor("org.example", "lib-b", "3.0.0"))
boot = descriptor("com.example", "boot-app", "1.0.0")
boot.update(pom("com.example", "boot-app", "1.0.0", "https://github.com/example/boot-app"))
boot.update({"BOOT-INF/lib/lib-a.jar": lib_a, "BOOT-INF/lib/lib-b.jar": lib_b})
write("java-boot", "boot.jar", archive(boot))

war = descriptor("com.example", "web-app", "1.0.0")
war.update(pom("com.example", "web-app", "1.0.0", "https://github.com/example/web-app"))
war.update({"WEB-INF/lib/lib-a.jar": lib_a, "WEB-INF/lib-provided/lib-b.jar": lib_b})
write("java-war", "app.war", archive(war))

shaded = descriptor("org.example", "one", "1.0.0")
shaded.update(descriptor("org.example", "two", "2.0.0"))
write("java-ambiguous", "shaded.jar", archive(shaded))

write("java-duplicate-lib", "duplicate.jar", archive_list([
    *descriptor("com.example", "duplicate-lib", "1.0.0").items(),
    ("BOOT-INF/lib/lib-a.jar", lib_a),
    ("BOOT-INF/lib/lib-a.jar", lib_a),
]))

write("java-duplicate-pom", "duplicate.jar", archive_list([
    *descriptor("com.example", "duplicate-pom", "1.0.0").items(),
    *pom("com.example", "duplicate-pom", "1.0.0", "https://github.com/example/one").items(),
    *pom("com.example", "duplicate-pom", "1.0.0", "https://github.com/example/two").items(),
]))

properties = descriptor("com.example", "duplicate-properties", "1.0.0")
write("java-duplicate-properties", "duplicate.jar", archive_list([
    *properties.items(),
    *properties.items(),
]))

write("java-invalid", "broken.jar", b"not a zip archive")
write("java-nested-invalid", "broken.jar", archive({"BOOT-INF/lib/broken.jar": b"not a jar"}))
write("java-path-unsafe", "broken.jar", archive({"BOOT-INF/lib/../lib/evil.jar": lib_a}))
write("java-oversized", "broken.jar", archive({"BOOT-INF/lib/huge.jar": b"0" * (65 << 20)}))
