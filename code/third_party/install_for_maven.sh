#!/bin/sh

# This will install any third party libraries to the local Maven repository
mvn install:install-file -Dfile=./jss/jss4.jar -DgroupId=org.mozilla \
 -DartifactId=jss -Dversion=4 -Dpackaging=jar