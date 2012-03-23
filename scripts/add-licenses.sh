#!/bin/bash
for i in `find . -name "*.py" -print`;
do
	cat LICENCE $i > $i.new;
	mv $i.new $i;
done
