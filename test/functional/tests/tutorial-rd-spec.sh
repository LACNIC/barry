#!/bin/sh

check_output_contains "tutorial-rd-spec-1" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,2025-06-01T00:00:00Z" \
	"ta.cer,obj.tbsCertificate.validity.notAfter,Time,2026-06-01T00:00:00Z" \
	"ta.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/64 ] ]\""

check_output_contains "tutorial-rd-spec-2" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,2025-06-01T00:00:00Z" \
	"ta.cer,obj.tbsCertificate.validity.notAfter,Time,2026-06-01T00:00:00Z" \
	"ta.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/64 ] ]\""

check_output_contains "tutorial-rd-spec-3" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,2025-06-01T00:00:00Z" \
	"ta.cer,obj.tbsCertificate.validity.notAfter,Time,2026-06-01T00:00:00Z" \
	"ta.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/64 ] ]\""
