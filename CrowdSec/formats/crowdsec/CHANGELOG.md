# Changelog

All notable changes to this project will be documented in this file.

## 2026-04-30 - 1.0.0

### Added
- Initial release of the CrowdSec intake format.
- Parser for CrowdSec alert events (triggered scenarios: brute force, scans, exploits).
- Parser for CrowdSec decision events (ban/captcha enforcement actions, new and deleted).
- ECS mapping: event.provider=CrowdSec, observer.vendor=CrowdSec, observer.product=CrowdSec LAPI.
- Alert: event.kind=alert, event.category=intrusion_detection, event.type=denied (remediation) or info (simulation).
- Alert: event.reason from scenario field.
- Alert: source.ip, source.as.number, source.as.organization.name, source.geo.country_iso_code from nested source object.
- Decision new: event.kind=event, event.category=network+intrusion_detection, event.type=denied.
- Decision deleted: event.kind=event, event.type=allowed.
- Decision: source.ip from value field (when scope=ip).
- Custom fields under crowdsec.alert.* and crowdsec.decision.*.
- related.ip aggregation for both event types.
- Smart descriptions for alert and decision events.
