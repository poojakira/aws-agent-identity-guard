"""Allow running as: python -m aws_agent_identity_guard"""

import sys

from .cli import main

sys.exit(main())
