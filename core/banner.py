#!/usr/bin/env python3
# core/banner.py

import time

R     = "\033[91m"
B     = "\033[34m"
DB    = "\033[94m"
C     = "\033[96m"
Y     = "\033[93m"
G     = "\033[92m"
W     = "\033[97m"
DIM   = "\033[2m"
BLINK = "\033[5m"
RST   = "\033[0m"

def print_banner():
    # Animate eye blink
    eye_frames = [
        f"{R}◉{RST}",
        f"{R}●{RST}",
        f"{R}◉{RST}",
    ]
    for frame in eye_frames:
        _draw(frame)
        time.sleep(0.18)

def _draw(eye):
    banner = f"""
{B}                    ▲
{B}                   ▲ ▲
{B}                  ▲   ▲
{B}                 ▲  {eye}{B}  ▲
{B}                ▲  ═══  ▲
{B}               ▲▲▲▲▲▲▲▲▲▲▲
{B}          ══════════════════════{RST}

{W}  ███╗   ███╗ ███████╗██╗  ██╗██╗   ██╗███╗  ██╗████████╗███████╗██████╗{RST}
{W}  ████╗ ████║ ╚════██║██║  ██║██║   ██║████╗ ██║╚══██╔══╝██╔════╝██╔══██╗{RST}
{W}  ██╔████╔██║     ██╔╝███████║██║   ██║██╔██╗██║   ██║   █████╗  ██████╔╝{RST}
{W}  ██║╚██╔╝██║    ██╔╝ ██╔══██║██║   ██║██║╚████║   ██║   ██╔══╝  ██╔══██╗{RST}
{W}  ██║ ╚═╝ ██║    ██║  ██║  ██║╚██████╔╝██║ ╚███║   ██║   ███████╗██║  ██║{RST}
{W}  ╚═╝     ╚═╝    ╚═╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{RST}

{B}  ══════════════════════════════════════════════════════════════════════{RST}
{R}        [ Made by MilkyWay Intelligence ]   Author: Sharlix{RST}
{C}        [ Bug Bounty & Pentest Pipeline  ]   v2.0.0{RST}
{B}  ══════════════════════════════════════════════════════════════════════{RST}
"""
    # Clear previous frame and redraw
    print("\033[H\033[J", end="")
    print(banner)
