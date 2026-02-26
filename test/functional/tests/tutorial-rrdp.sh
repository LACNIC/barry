#!/bin/sh

check_output_contains "tutorial-rrdp1" -Fx \
	"ta.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"A.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"B.cer,rpp.notification,C String,https://tomato/rrdp/notification.xml" \
	"B2.cer,rpp.notification,C String,https://lettuce/rrdp/notification.xml" \
	"https://potato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ A.cer, A1.roa, A2.roa, A.mft, A.crl, B.cer, ta.mft, ta.crl ]\"" \
	"https://tomato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ B1.roa, B2.cer, B.mft, B.crl ]\"" \
	"https://lettuce/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ B2a.roa, B2.mft, B2.crl ]\""

check_output_contains "tutorial-rrdp2" -Fx \
	"ta.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"A.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"B.cer,rpp.notification,C String,https://tomato/rrdp/notification.xml" \
	"B2.cer,rpp.notification,C String,https://lettuce/rrdp/notification.xml" \
	"https://potato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ A.cer, A1.roa, A2.roa, A.mft, A.crl, B.cer, ta.mft, ta.crl ]\"" \
	"https://tomato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ ta.cer, A1.roa, A1.roa, B2a.roa ]\"" \
	"https://lettuce/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ B2a.roa, B2.mft, B2.crl ]\""

check_tutorial_delta() {
	$BARRY $KEYS $PRINTS $TIMES \
		--tal-path "sandbox/tal/delta.old.tal" \
		--rsync-path sandbox/rsync/delta/old/ \
		--rrdp-path sandbox/rrdp/delta/old/ \
		tests/tutorial-rrdp-delta-old.rd \
		> /dev/null 2> /dev/null
	$BARRY $KEYS $PRINTS $TIMES \
		--tal-path "sandbox/tal/delta.new.tal" \
		--rsync-path sandbox/rsync/delta/new/ \
		--rrdp-path sandbox/rrdp/delta/new/ \
		tests/tutorial-rrdp-delta-new.rd \
		> /dev/null 2> /dev/null
	mkdir -p sandbox/rrdp/fusion/
	${BARRY}-delta -v \
		--old.notification    sandbox/rrdp/delta/old/notif.xml \
		--old.snapshot        sandbox/rrdp/delta/old/snapshot.xml \
		--new.notification    sandbox/rrdp/delta/new/notif.xml \
		--new.snapshot        sandbox/rrdp/delta/new/snapshot.xml \
		--output.notification sandbox/rrdp/fusion/notif.xml \
		--output.delta.path   sandbox/rrdp/fusion/delta.xml \
		--output.delta.uri    https://your-server.net/rrdp/v2/delta.xml \
		> "sandbox/output/delta.log" 2>&1
	check_output_contains "delta" -F \
		"rsync://localhost:8873/rpki/ca1/roa1B.roa disappeared; adding withdraw" \
		"rsync://localhost:8873/rpki/ca1/ca1.mft has a different hash; adding publish" \
		"rsync://localhost:8873/rpki/ca1/roa1C.roa spawned; adding publish"
}

check_tutorial_delta
