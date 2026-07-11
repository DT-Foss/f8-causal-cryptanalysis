import json

from arx_carry_leak.cli import main


def test_vector_cli(capsys) -> None:
    assert main(["verify-vectors"]) == 0
    output = capsys.readouterr().out
    assert "PASS speck32_64" in output
    assert "PASS threefish256_zero" in output


def test_run_cli_writes_json(tmp_path) -> None:
    output = tmp_path / "result.json"
    status = main(
        [
            "run",
            "--profile",
            "quick",
            "--target",
            "speck32_64",
            "--blocks",
            "1000",
            "--seeds",
            "3",
            "--output",
            str(output),
        ]
    )
    assert status == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["results"][0]["target"] == "speck32_64"
