#!/bin/sh
set -eu

install -m 0644 /data/fcr-gate/deploy/fcr-rfid-encoder.service /etc/systemd/system/fcr-rfid-encoder.service
systemctl daemon-reload
systemctl enable fcr-rfid-encoder.service
systemctl restart fcr-rfid-encoder.service
