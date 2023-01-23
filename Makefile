SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

# If we need any submodules, etc.
setup:

run:
	sage mayo.sage

run-python:
	sage --python mayo.py

test: pyfiles
	sage test_mayo.sage

vectors: pyfiles
	@echo "Removing vectors folder, if present"
	@rm -rf vectors
	@echo "Creating vectors folder"
	@mkdir -p vectors
	sage test_mayo.sage

.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__

.PHONY: distclean
distclean: clean
	rm -rf vectors ascii
