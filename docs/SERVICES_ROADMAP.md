<!-- SPDX-License-Identifier: MPL-2.0 -->

# Standalone services: later, deliberately

The first preview is library-only. An authentication daemon or log ingestion
service would add a network protocol, service authentication, key rotation,
availability, replay, upgrade, and incident-response obligations. Process
isolation is not valuable merely because it draws another box in a diagram.

If a concrete multi-application need justifies those costs, `authd` and `logd`
will be separate AGPL-3.0-only services. Their protocols will not be promised
until adversarial tests, recovery procedures, and at least two real consumers
exist.
