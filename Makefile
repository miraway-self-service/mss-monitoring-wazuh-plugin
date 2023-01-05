# Generate tags for a release automatically.
# Update the tag.py file before running this script.

prebuild:
	@echo "- Updating project's versions ..."
	@node scripts/generate-build-version

tags: prebuild
	@echo "- Generating Git tags ..."
	@python3 scripts/tag.py

