import os
import subprocess


def test_openldap_dotenv_does_not_execute_shell_code(tmp_path):
    marker = tmp_path / "pwned"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ldapsearch = fake_bin / "ldapsearch"
    ldapsearch.write_text("#!/usr/bin/env bash\nprintf 'dn: dc=example,dc=test\\nobjectClass: top\\n'\n", encoding="utf-8")
    ldapsearch.chmod(0o755)
    env_file = tmp_path / ".env"
    env_file.write_text(f"LDAP_URI=$(touch {marker})\nBASE_DN=dc=example,dc=test\nALLOW_ANONYMOUS=1\nEVIL=`touch {marker}`\n", encoding="utf-8")
    result = subprocess.run(["bash", "exporters/openldap/export-openldap.sh", str(tmp_path / "out.zip")], cwd=os.getcwd(), env=os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}", "ENV_FILE": str(env_file)}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
