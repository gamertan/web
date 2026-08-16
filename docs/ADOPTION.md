<!-- SPDX-License-Identifier: MPL-2.0 -->

# Application adoption contract

The foundation is designed and tested as independent software before an
existing application migrates to it. No application's historical schema,
roles, route names, analytics categories, or operator workflow belongs in a
general package merely because it makes one migration easier.

An application adopts one boundary at a time:

1. implement a narrow adapter at the application edge;
2. run the old and new decisions against the same reviewed fixtures;
3. explain intentional differences;
4. deploy without deleting the retained implementation;
5. observe a defined production soak; and
6. remove old code only after rollback and data-compatibility evidence passes.

EQL Helper is intended to be the first demanding adopter, not the design
template. Its private evidence, persistent bans, account data, route policy,
operator exclusions, synchronization, and publishing workflow remain
application-owned. Useful pressure from that migration may improve a general
interface, but it may not smuggle EQL-specific policy into this module.
