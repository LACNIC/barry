#!/bin/sh

check_error "err-hex-trunc" -F "'version' hexadecimal string is empty: 0x"
check_error "err-need-str" -F "'version': Expected a string value."
check_error "err-nan" -F "'version' cannot be parsed as a number: potato"
