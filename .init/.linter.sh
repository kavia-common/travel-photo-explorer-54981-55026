#!/bin/bash
cd /home/kavia/workspace/code-generation/travel-photo-explorer-54981-55026/travel_photo_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

