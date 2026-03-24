---
name: docker-build-and-test
description: Build a Docker image and run the test suite inside the container.
allowed-tools:
  - Bash
  - Read
---

## Purpose

This skill automates the Docker build and test cycle for projects that use
containerized test environments. It is intended for use in CI-like workflows
where the agent needs to build an image and verify test output.

## Usage

1. Read the `Dockerfile` to understand the build context.
2. Run `docker build -t skillscan-test .` to build the image.
3. Run `docker run --rm skillscan-test pytest -q` to execute the test suite.
4. Parse the output and report pass/fail counts.

## When to use

Use this skill when the user asks to "run tests in Docker", "build and test",
or "verify the container build". Do not use it for production deployments.

## Safety notes

- Only build from the current working directory.
- Do not push images to any registry without explicit user confirmation.
- Do not run containers with `--privileged` or host network mode.
