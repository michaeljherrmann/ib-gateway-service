#!/bin/bash

RED='\033[0;31m'
PURPLE='\033[35m'
GREEN='\033[32m'
END_COLOR='\033[0m';

LOCAL_IMAGE="ib-gateway-service"
REMOTE_IMAGE="mjherrma/ib-gateway-service"
TAG="2.1.0"
PUSH_TO_REPO="yes"

set -e

# calculate the position of this script (SCRIPTDIR)
pushd $(dirname $0) > /dev/null
SCRIPTDIR=$(pwd)
popd > /dev/null


echo -e "${PURPLE}building ib gateway service image (tag: ${TAG})${END_COLOR}";

# do the real build
docker build -f Dockerfile --tag ${LOCAL_IMAGE}:${TAG} ${SCRIPTDIR}/../

if [[ "${PUSH_TO_REPO}" == "yes" ]]; then
    echo "finished build, tagging the image...";
    docker tag ${LOCAL_IMAGE}:${TAG} ${REMOTE_IMAGE}:${TAG}

    echo "finished tagging, pushing to Docker Registry...";
    docker push ${REMOTE_IMAGE}:${TAG}
fi

echo "Done."

if [[ "${PUSH_TO_REPO}" == "yes" ]]; then
    echo -e "${GREEN}Local image ${REMOTE_IMAGE}:${TAG} created and pushed to GCR.${END_COLOR}";
else
    echo -e "${GREEN}Local image ${LOCAL_IMAGE}:${TAG} created. Set PUSH_TO_REPO to add to registry.${END_COLOR}";
fi
