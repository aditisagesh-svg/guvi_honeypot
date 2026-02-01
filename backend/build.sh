#!/bin/bash
# Build script for Render deployment
# Downloads spaCy model after pip install

set -e

echo "Downloading spaCy model..."
python -m spacy download en_core_web_sm || echo "Warning: spaCy model download failed, continuing..."

echo "Build complete!"

