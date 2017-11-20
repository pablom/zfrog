#!/bin/bash

curr_folder=${PWD}
app_name=redis

# Build example application
function build() {
	${curr_folder}/zfrog_cli build ${curr_folder}/examples/${app_name} ${app_name}
}
# Start example application
function start_example() {
	cd ${curr_folder}/examples/${app_name}/
	${curr_folder}/zfrog -fnr -c ${curr_folder}/examples/${app_name}/conf/${app_name}.conf
	cd -
}

build
start_example

