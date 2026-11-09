# -----------------------------------------------------------------------------
# HFS-Sentry Portable Docker Container
# Pure Python 3 Standard Library - Ultra-lightweight (< 60MB)
# -----------------------------------------------------------------------------

FROM python:3.12-alpine

LABEL maintainer="Hamza El Fathi Sofyani <hamzaelfathisofyani@gmail.com>"
LABEL repository="https://github.com/faathii/HFS-Sentry"
LABEL description="High-density, zero-dependency cybersecurity & diagnostic suite"

WORKDIR /app

# Copy repository
COPY pyproject.toml sentry.py README.md LICENSE ./
COPY sentry/ ./sentry/
COPY examples/ ./examples/

# Install package entrypoints
RUN pip install --no-cache-dir -e .

# Run as non-root security user
RUN adduser -D -u 1000 sentryuser
USER sentryuser

ENTRYPOINT ["hfs-sentry"]
CMD ["--list"]

