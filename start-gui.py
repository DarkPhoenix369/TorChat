#!/usr/bin/env python3
"""Opens torchat in its desktop window (same as: python3 torchat.py --gui)."""
import os, runpy, sys

sys.argv = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "torchat.py"), "--gui"] + sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
