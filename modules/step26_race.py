#!/usr/bin/env python3
# modules/step26_race.py — Race Condition (V7 async HTTP/2 engine)
# MilkyWay Intelligence | Author: Sharlix
from engines.race_engine_v7 import RaceEngineV7

class Step26Race:
    def __init__(self, pipeline): self.p = pipeline
    def run(self):
        self.p.log.info("Race Condition: using V7 async HTTP/2 engine")
        RaceEngineV7(self.p).run()
