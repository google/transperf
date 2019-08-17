# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SRC=$(wildcard *.py)

# To create a Python-runnable zip file we need to add __main__.py in
# the root and add all other python files inside the transperf folder
# to preserve the package structure. For that, we need a structure like:
#
#   transperf.zip /
#           __main__.py
#           transperf /
#                   third_party /
#                   launch.py
#                   recv.py
#                   ...
# The following command first creates a zip file that has __main__.py
# in its root, and then add all other python files inside transperf
# directory.
#
# Please note that the zip commands, used here, preserve the contents
# of the zipfile and only appends the new files.
zip: $(SRC)
	rm -f transperf.zip
	zip -r transperf.zip __main__.py && \
	cd ../ && \
	zip -r transperf/transperf.zip transperf/*.py transperf/third_party

clean:
	rm transperf.zip

