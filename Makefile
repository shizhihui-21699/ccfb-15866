.PHONY: build release test scan doctor clean

build:
	swift build

release:
	swift build -c release

test:
	swift run pvsaudit-selftest

doctor: release
	.build/release/pvsaudit doctor

scan: release
	.build/release/pvsaudit scan --json pvsaudit-state.json --report pvsaudit-report.txt

clean:
	swift package clean
	rm -rf .build
