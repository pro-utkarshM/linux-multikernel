#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Normal nested prerequisite; writer race starts only after confirmed halt."""
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_nested_child_init import main


if __name__ == '__main__':
    main(profile='writer')
