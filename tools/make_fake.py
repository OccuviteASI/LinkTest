"""Build tools/fake_iperf3.py into a standalone iperf3.exe for testing LinkTest.

    python tools/make_fake.py        -> tools/fake/iperf3.exe

Point LinkTest at it via the "I already have iperf3 somewhere" box. Do NOT ship it.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
out = os.path.join(HERE, "fake")
r = subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
                    "--name", "iperf3", "--distpath", out,
                    "--workpath", os.path.join(HERE, "fake-build"),
                    "--specpath", os.path.join(HERE, "fake-build"),
                    os.path.join(HERE, "fake_iperf3.py")])
sys.exit(r.returncode)
