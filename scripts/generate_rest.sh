#!/bin/bash -e

command -v swagger >/dev/null 2>&1 || { echo >&2 "Command 'swagger' not installed. See: https://github.com/go-swagger/go-swagger for installation"; exit 1; }

scriptPath=$(realpath $0)
scriptDir=$(dirname "$scriptPath")

zitiEdgeDir=$(realpath "$scriptDir/..")
swagSpec=$(realpath "$zitiEdgeDir/specs/swagger.yml")
copyrightFile=$(realpath "$scriptDir/template.copyright.txt")

serverPath=$(realpath "$zitiEdgeDir/rest_server")
echo "...removing any existing server from $serverPath"
rm -rf "$serverPath"
mkdir -p "$serverPath"

clientPath=$(realpath "$zitiEdgeDir/rest_client")
echo "...removing any existing client from $clientPath"
rm -rf "$clientPath"
mkdir -p "$clientPath"

echo "...generating server"
# initialism for "Ca" keeps go-swagger from outputting the CA packages as c_a and mangling
# type/function names in the same way.
swagger generate server --exclude-main -f "$swagSpec" -s rest_server -t "$zitiEdgeDir" -q -r "$copyrightFile" --additional-initialism=Ca
exit_status=$?
if [ ${exit_status} -ne 0 ]; then
  echo "Failed to generate server. See above."
  exit "${exit_status}"
fi

echo "...generating client"
swagger generate client -f "$swagSpec"  -c rest_client -t "$zitiEdgeDir" -q -r "$copyrightFile" --additional-initialism=Ca
exit_status=$?
if [ ${exit_status} -ne 0 ]; then
  echo "Failed to generate client. See above."
  exit "${exit_status}"
fi

