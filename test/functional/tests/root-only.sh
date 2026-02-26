#!/bin/sh

check_output_contains "root-only-signature" -Fx "ta.cer,obj.signature,BIT STRING,0x010203"
check_output_contains "root-only" -x "ta\\.cer,obj\\.signature,BIT STRING,$HEXNUM"
check_output_contains "root-only-signature-crl" -Fx "0.crl,obj.signature,BIT STRING,0x010203"
