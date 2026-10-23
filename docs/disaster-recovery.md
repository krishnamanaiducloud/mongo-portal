# Disaster recovery considerations

The portal is **stateless with respect to durable data**: it stores no
database, no passwords and no persistent sessions. Recovery is redeployment.

| Scenario | Impact | Recovery |
| --- | --- | --- |
| Pod or node failure | Users on that pod lose their MongoDB session | Automatic reschedule; users sign in to MongoDB again. PDB keeps ≥ 1 replica during voluntary disruptions. |
| Namespace deleted | Portal unavailable | Recreate namespace and the Secrets ([secrets.md](secrets.md)); Argo CD re-syncs everything else from Git. Keep Secret material in your secret manager. |
| Cluster loss | Portal unavailable | Deploy the same overlay to the recovery cluster after MongoDB is restored; update profile hosts if MongoDB endpoints change. |
| MongoDB primary failover | Brief errors | None: driver re-discovers topology and re-authenticates (tested). |
| MongoDB total outage / restore | Logins fail with "unreachable" | Restore MongoDB per its own DR plan; the portal needs no action. Note: MongoDB users and roles are part of the `admin` database backup. |
| Image registry unavailable | New pods cannot start | Mirror both images (by digest) to an internal registry; overlays reference digests. |
| Git / Argo CD unavailable | No changes can be deployed | Running pods are unaffected; `oc apply -k examples/kustomize/overlays/<env>` from a local checkout as a break-glass path. |
| Audit trail | In-memory buffer lost on restart | Durable copy is the forwarded log stream (Splunk); size its retention to policy. |

**Backups to keep:** this Git repository (manifests and configuration), the
Secret material (in a secret manager), and MongoDB itself (outside the portal's
scope). Nothing else is needed to rebuild the portal.

**RTO** is dominated by image pull and Argo CD sync time (minutes). **RPO** for
the portal is zero (no data); for MongoDB it is governed by its backup policy.
