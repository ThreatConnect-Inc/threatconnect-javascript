.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help
define BROWSER_PYSCRIPT
import os, webbrowser, sys
try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

# try to use firefox to open the test results
firefox = webbrowser.get('firefox')

if firefox:  # open the file with firefox
	firefox.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
else:  # open the file with the default browser
	webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT
BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: ## remove all testing artifacts
	rm -rf node_modules

test: clean ## run the tests (which will open in the default browser)
	# install package dependencies
	npm install mocha chai --save-dev
	# open the test runner in a browser
	$(BROWSER) testrunner.html
