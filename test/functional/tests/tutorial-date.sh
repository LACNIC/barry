#!/bin/sh

check_output_contains "tutorial-date" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,2025-07-15T19:39:38Z"
