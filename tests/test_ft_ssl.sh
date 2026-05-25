#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT_DIR/ft_ssl"
TMP_DIR=$(mktemp -d)

cleanup()
{
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

assert_output()
{
	name=$1
	expected=$2
	shift 2

	output="$("$@")"
	if [ "$output" != "$expected" ]; then
		printf 'not ok - %s\n' "$name"
		printf 'expected:\n%s\n' "$expected"
		printf 'got:\n%s\n' "$output"
		exit 1
	fi
	printf 'ok - %s\n' "$name"
}

assert_pipe_output()
{
	name=$1
	input=$2
	expected=$3
	shift 3

	output=$(printf '%s' "$input" | "$@")
	if [ "$output" != "$expected" ]; then
		printf 'not ok - %s\n' "$name"
		printf 'expected:\n%s\n' "$expected"
		printf 'got:\n%s\n' "$output"
		exit 1
	fi
	printf 'ok - %s\n' "$name"
}

assert_failure_contains()
{
	name=$1
	expected=$2
	shift 2

	set +e
	output="$("$@" 2>&1)"
	status=$?
	set -e
	if [ "$status" -eq 0 ] || ! printf '%s\n' "$output" | grep -F "$expected" >/dev/null; then
		printf 'not ok - %s\n' "$name"
		printf 'expected non-zero status containing:\n%s\n' "$expected"
		printf 'got status %s:\n%s\n' "$status" "$output"
		exit 1
	fi
	printf 'ok - %s\n' "$name"
}

printf 'And above all,\n' > "$TMP_DIR/file"
printf 'https://www.42.fr/\n' > "$TMP_DIR/website"

assert_pipe_output \
	'md5 stdin' \
	'42 is nice
' \
	'(stdin)= 35f1d6de0302e2086a4e472266efb3a9' \
	"$BIN" md5

assert_pipe_output \
	'md5 -p trims displayed newline' \
	'42 is nice
' \
	'("42 is nice")= 35f1d6de0302e2086a4e472266efb3a9' \
	"$BIN" md5 -p

assert_output \
	'md5 file format' \
	"MD5 ($TMP_DIR/file) = 53d53ea94217b259c11a5a2d104ec58a" \
	"$BIN" md5 "$TMP_DIR/file"

assert_output \
	'md5 reverse file format' \
	"53d53ea94217b259c11a5a2d104ec58a $TMP_DIR/file" \
	"$BIN" md5 -r "$TMP_DIR/file"

assert_output \
	'md5 string format' \
	'MD5 ("foo") = acbd18db4cc2f85cedef654fccc4a4d8' \
	"$BIN" md5 -s foo

assert_output \
	'md5 reverse string format' \
	'acbd18db4cc2f85cedef654fccc4a4d8 "foo"' \
	"$BIN" md5 -r -s foo

assert_output \
	'sha256 quiet file vector' \
	'1ceb55d2845d9dd98557b50488db12bbf51aaca5aa9c1199eb795607a2457daf' \
	"$BIN" sha256 -q "$TMP_DIR/website"

assert_output \
	'sha256 string label and vector' \
	'SHA256 ("42 is nice") = b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f' \
	"$BIN" sha256 -s '42 is nice'

assert_pipe_output \
	'quiet echoed stdin' \
	'just to be extra clear
' \
	'just to be extra clear
3ba35f1ea0d170cb3b9a752e3360286c
acbd18db4cc2f85cedef654fccc4a4d8
53d53ea94217b259c11a5a2d104ec58a' \
	"$BIN" md5 -r -q -p -s foo "$TMP_DIR/file"

assert_failure_contains 'invalid command prefix rejected' "Invalid command 'm'" "$BIN" m
assert_failure_contains 'missing file does not hash stdin' 'No such file or directory' "$BIN" md5 missing-file
assert_failure_contains 'missing -s argument fails' 'Invalid argument' "$BIN" md5 -s

set +e
late_output=$(printf 'one more thing\n' | "$BIN" md5 -r -p -s foo "$TMP_DIR/file" -s bar 2>&1)
late_status=$?
set -e
expected_late='("one more thing")= a0bd1876c6f011dd50fae52827f445f5
acbd18db4cc2f85cedef654fccc4a4d8 "foo"
53d53ea94217b259c11a5a2d104ec58a '"$TMP_DIR"'/file
'"$BIN"': md5: -s: No such file or directory
'"$BIN"': md5: bar: No such file or directory'
if [ "$late_status" -eq 0 ] || [ "$late_output" != "$expected_late" ]; then
	printf 'not ok - late -s is treated as file operand\n'
	printf 'expected non-zero output:\n%s\n' "$expected_late"
	printf 'got status %s:\n%s\n' "$late_status" "$late_output"
	exit 1
fi
printf 'ok - late -s is treated as file operand\n'

printf 'all ft_ssl regression tests passed\n'
