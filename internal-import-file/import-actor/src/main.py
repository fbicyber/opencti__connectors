# -*- coding: utf-8 -*-
"""OpenCTI ActorImporter connector main module."""

import sys
import time

from actor_importer import ActorImporter

if __name__ == "__main__":
    try:
        connector = ActorImporter()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
