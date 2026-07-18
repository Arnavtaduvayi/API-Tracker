# Fixture: leaky repository

This directory is TEST DATA for the secret scanner. Every value here is an
obviously fake, non-functional credential (note the `FAKE` markers). None of
these are real secrets. Automated tests copy this directory into a temporary
Git repository and scan it.
