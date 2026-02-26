#!/bin/sh

check_output_contains "tutorial-filelist-default" -x \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""

check_output_contains "tutorial-filelist-default-explicit" -x \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""

check_output_contains "tutorial-filelist-crl-omitted" -x \
	"mft\\.mft,$FILELIST,File List,\"{ A\\.cer=$HEXNUM, B\\.cer=$HEXNUM, ta\\.crl=$HEXNUM }\""

check_output_contains "tutorial-filelist-overrides-isolated" -x \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=0x010203, potatoes=0 }\""

check_output_contains "tutorial-filelist-overrides-full" -x \
	"mft\\.mft,$FILELIST,File List,\"{ A\\.cer=0x010203, nonexistent\\.cer=0x040506, mft\\.mft=0x112233, foobar=0x55555555555555 }\""
