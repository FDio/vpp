#!/bin/bash

if [ $# -lt 2 ] ; then
  readonly exe=$(basename $0)
  echo "${exe} takes at least 2 arguments: ${exe} <base docker image name> <command> [args...]"
  echo "E.g.: $0 ubuntu:16.04 make bootstrap pkg-deb"
  exit 2
fi


VPP=$(readlink -f $(dirname $0)/../../)

ID=""
EX=99

function container() {

	local vpp=$1
	local base=$2

	# Build base docker image
	# In most cases cached image already exists
	# Some assumptions about Dockerfile names:
	#   centos:7 => Dockerfile.centos7
	#   ubuntu:14.04 => Dockerfile.ubuntu1404
	#   ubuntu:16.04 => Dockerfile.ubuntu1604
	#   foobar:1.5 => Dockerfile.foobar15

	local os=$(echo ${base} | sed 's/\:\|\.//g')
	local tag=vpp-build-${os}
	local build=$(mktemp -d)

	if [ ! -f  ${vpp}/build-root/docker/Dockerfile.${os} ]; then
		echo ${vpp}/build-root/docker/Dockerfile.${os} does not exist!
		echo ${base} - is not supported
		exit 1
	fi

	cp ${vpp}/Makefile ${build}/Makefile
	cp ${vpp}/build-root/docker/Dockerfile.${os} ${build}/Dockerfile

	docker pull ${base}

	docker build \
		--tag ${tag} \
		--build-arg HTTP_PROXY="${HTTP_PROXY}" \
		--build-arg HTTPS_PROXY="${HTTPS_PROXY}" \
		--build-arg NO_PROXY="${NO_PROXY}" \
		--build-arg http_proxy="${http_proxy}" \
		--build-arg https_proxy="${http_proxy}" \
		--build-arg no_proxy="${no_proxy}" \
		--file ${build}/Dockerfile \
		${build}

	rm -rf ${build}

	# Start the container
	ID=$(docker run \
		--tty \
		--detach \
		--volume ${vpp}:${vpp}:rw \
		--volume /tmp:/tmp:rw \
		--workdir ${vpp} \
		--env HTTP_PROXY="${HTTP_PROXY}" \
		--env HTTPS_PROXY="${HTTPS_PROXY}" \
		--env NO_PROXY="${NO_PROXY}" \
		--env http_proxy="${http_proxy}" \
		--env https_proxy="${http_proxy}" \
		--env no_proxy="${no_proxy}" \
		${tag} /bin/cat)

	# Fake linux headers for DPDK module build on old branches
	docker exec --tty ${ID} /bin/bash -c \
		'ln -sfnv $(find /lib/modules -type d -name [34]* | head -1) /lib/modules/$(uname -r)'

	# Add user to make sudo/su happy
	# mostly for build-root/vagrant/build.sh
	local usr=$(id -u)
	local usrn=$(id -un)
	local grp=$(id -g)
	local grpn=$(id -gn)

	docker exec --tty ${ID} /bin/bash -c \
		"groupadd -g ${grp} -o ${grpn}"

	docker exec --tty ${ID}  /bin/bash -c \
		"useradd -u ${usr} -g ${grp} -m -o ${usrn}"

	docker exec --tty ${ID} /bin/bash -c \
		"chown ${usr}:${grp} ~${usrn}"

	docker exec --tty ${ID} /bin/bash -c \
		"echo ${usrn} ALL=\(ALL:ALL\) NOPASSWD: ALL > /etc/sudoers.d/80-vpp"

}

function run() {
	docker exec \
		--tty \
		--user $(id -u):$(id -g) \
		${ID} $*
	EX=$?
}

function stop() {
	# Stop the container (/bin/cat is still running)
	[[ !  -z  ${ID}  ]] && (docker kill ${ID}; docker rm --force ${ID})
	exit ${EX}
}

trap stop INT

container ${VPP} $1
shift

run $*

stop

