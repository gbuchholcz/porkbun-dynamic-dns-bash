#!/bin/bash
# This is a minimalist dynamic DNS client written in Bash based upon
# the Porkbun Python client at https://github.com/porkbundomains/porkbun-dynamic-dns-python.
#
# Copyright 2022 Gergoe Buchholcz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

PORKBUN_DOMAIN=""
PORKBUN_SUBDOMAIN=""
PORKBUN_VERBOSE=0
PORKBUN_IP=""
PORKBUN_DISPLAY_HELP=0
PORKBUN_API_URL="https://api.porkbun.com/api/json/v3"

PORKBUN_API_KEY=""
PORKBUN_SECRET_KEY=""

PORKBUN_PING_ENDPOINT=""
PORKBUN_RETRIEVE_ENDPOINT=""
PORKBUN_DELETE_ENDPOINT=""
PORKBUN_CREATE_ENDPOINT=""

PORKBUN_API_STATUS_SUCCESS="SUCCESS"

PORKBUN_SSM_PARAMETER_API_KEY_NAME=""
PORKBUN_SSM_PARAMETER_SECRET_KEY_NAME=""

PORKBUN_CONFIGURATION_PATH=""

porkbun::print_help() {
  porkbun::print "usage: porkbun-ddns.sh <domain> [subdomain] [-c|--config <config_file>] [-i <ip_address>] [-s|--stdin-config] [-v|--verbose] [--help]\n"
  porkbun::print "Creates or updates an A DNS record of a domain and subdomain that points to a specific IP address.\n\n"
  porkbun::print "If the -s flag is set then the configuration is read from the STDIN otherwise the <config> file is read.\n\n"
  porkbun::print "\t-c, --configuration <config_file>        The path to the config file that contains the API and Secret keys and the URL to the Porkbun API\n"
  porkbun::print "\t-i <ip_address>       The IP address that the A record points to. If it is not set then the public IP address as determined by the Porkbun API will be used.\n"
  porkbun::print "\t-s, --stdin-config    The configuration is read from the STDIN instead of a file. If the flag is set then the <config> argument must be omitted.\n"
  porkbun::print "\t-akp, --aws-api-key-parameter-name        The name of the API Key as stored in the AWS Systems Manager Parameter Store, resolving the value happens after reading the config if any\n"
  porkbun::print "\t-skp, --aws-secret-key-parameter-name     The name of the Secret Key as stored in the AWS Systems Manager Parameter Store, resolving the value happens after reading the config if any\n"
  porkbun::print "\t-v, --verbose         Be verbose.\n"
  porkbun::print "\t    --help            Print a summary of the command-line usage and exit.\n\n"
  porkbun::print "Exit status:\n"
  porkbun::print "\tporkbun-ddns.sh exits with status 0 if it has been successfully executed, greater than 0 if errors occur.\n\n"
  porkbun::print "Remarks:\n"
  porkbun::print "\tNote, that before creating a new A DNS record the script deletes any A, ALIAS and CNAME records for the given domain and subdomain.\n"
  porkbun::print "\tIf the API or Secret Keys are read from the AWS SSM Parameter Store then the AWS cli has to be setup and the values have to be accessible by the user.\n\n"
  porkbun::print "Examples:\n\n"
  porkbun::print "porkbun-ddns.sh /path/to/config.json example.com\n"
  porkbun::print "\tCreates an A record 'example.com' that points to the IP address as determined by the Porkbun API.\n\n"
  porkbun::print "porkbun-ddns.sh example.com www -s < /path/to/config.json\n"
  porkbun::print "\tCreates an A record 'www.example.com' that points to the IP address as determined by the Porkbun API. The configuration is read from the STDIN.\n\n"
  porkbun::print "porkbun-ddns.sh /path/to/config.json example.com '*' -i 10.0.0.1\n"
  porkbun::print "\tCreates an A record '*.example.com' that points to the IP address 10.0.0.1.\n\n"
}

porkbun::print_verbose() {
  if (( PORKBUN_VERBOSE == 1 )); then
    printf "%b" "$1"
  fi
}

porkbun::print_error() {
  printf "Error: %b" "$1" 1>&2
}

porkbun::print() {
  printf "%b" "$1"
}

porkbun::parse_arguments() {
  local positional_args credentials_from_stdin configuration configuration_path ip_address_pattern error_code

  ip_address_pattern="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
  readonly ip_address_pattern

  credentials_from_stdin=0
  
  positional_args=()

  while [[ $# -gt 0 ]]; do
    case $1 in
      -i)
        PORKBUN_IP="$2"
        if ! [[ "${PORKBUN_IP}" =~ $ip_address_pattern ]]; then
          porkbun::print_error "The IP address ${PORKBUN_IP} is not valid!\n"
          return 1
        fi
        shift
        shift
        ;;
      -c|--configuration)
        PORKBUN_CONFIGURATION_PATH="$2"
        shift
        shift
        ;;

      -akp|--aws-api-key-parameter-name)
        PORKBUN_SSM_PARAMETER_API_KEY_NAME="$2"
        shift
        shift
        ;;
      -skp|--aws-secret-key-parameter-name)
        PORKBUN_SSM_PARAMETER_SECRET_KEY_NAME="$2"
        shift
        shift
        ;;
      -v|--verbose)
        PORKBUN_VERBOSE=1
        porkbun::print_verbose "Verbose mode activated.\n"
        shift
        ;;
      -s|--stdin-config)
        credentials_from_stdin=1
        shift
        ;;
      --help)
        PORKBUN_DISPLAY_HELP=1
        return 0
        ;;
      -*)
        porkbun::print_error "Unknown option $1\n"
        return 2
        ;;
      *)
        positional_args+=("$1")
        shift
        ;;
    esac
  done

  if (( credentials_from_stdin == 1 )); then
    configuration=$(cat)
    if [[ ${#positional_args[@]} -gt 0 ]]; then
      PORKBUN_DOMAIN=${positional_args[0]}
    else
      porkbun::print_error "At least one positional argument (domain) is expected.\n"
      return 3
    fi
    [[ ${#positional_args[@]} -gt 1 ]] && PORKBUN_SUBDOMAIN=${positional_args[1]}
    [[ ${#positional_args[@]} -gt 2 ]] && {
      porkbun::print_error "Unknown positional argument ${positional_args[2]}!\n"
      return 4
    }

  else
    [[ ${#positional_args[@]} -lt 1 ]] && {
      porkbun::print_error "At least one positional argument (domain) is expected.\n"
      return 3
    }

    if [[ -n ${PORKBUN_CONFIGURATION_PATH} ]]; then
      if [[ ! -f ${configuration_path} ]]; then
        porkbun::print_error "The configuration file (${configuration_path}) cannot be found!\n"
        return 6    
      fi
      configuration=$(cat "${configuration_path}")
    fi
    
    PORKBUN_DOMAIN=${positional_args[0]}
    [[ ${#positional_args[@]} -gt 1 ]] && PORKBUN_SUBDOMAIN=${positional_args[1]}
    [[ ${#positional_args[@]} -gt 2 ]] && {
      porkbun::print_error "Unknown positional argument ${positional_args[3]}!\n"
      return 7
    }
  fi

  if [[ -n ${configuration} ]]; then
    if ! porkbun::parse_configuration "${configuration}"; then
      return 8
    fi
  fi
  
  if [[ -n PORKBUN_SSM_PARAMETER_API_KEY_NAME ]]; then
    PORKBUN_API_KEY=$(porkbun::get_ssm_parameter "${PORKBUN_SSM_PARAMETER_API_KEY_NAME}")
    error_code=$?
    if [[ ${error_code} -ne 0 ]]; then
      porkbun::print_error "Querying the API Key from the Parameter Store failed!\n"
      return 9
    fi
  fi

  if [[ -n PORKBUN_SSM_PARAMETER_SECRET_KEY_NAME ]]; then
    PORKBUN_SECRET_KEY=$(porkbun::get_ssm_parameter "${PORKBUN_SSM_PARAMETER_SECRET_KEY_NAME}")
    error_code=$?
    if [[ ${error_code} -ne 0 ]]; then
      porkbun::print_error "Querying the Secret Key from the Parameter Store failed!\n"
      return 9
    fi
  fi

  porkbun::set_api_endpoints

  if [[ -z PORKBUN_API_KEY ]] || [[ -z PORKBUN_SECRET_KEY ]]; then
      porkbun::print_error "The Prokbun credentials are not configured correctly!\n"
      return 10    
  fi

  readonly PORKBUN_DOMAIN PORKBUN_SUBDOMAIN PORKBUN_VERBOSE PORKBUN_API_URL PORKBUN_API_KEY
  readonly PORKBUN_SECRET_KEY  PORKBUN_PING_ENDPOINT PORKBUN_RETRIEVE_ENDPOINT PORKBUN_DELETE_ENDPOINT
  readonly PORKBUN_CREATE_ENDPOINT PORKBUN_API_STATUS_SUCCESS

  porkbun::print_verbose "Run parameters:\n"  
  porkbun::print_verbose "\tdomain: ${PORKBUN_DOMAIN}\n"
  porkbun::print_verbose "\tsubdomain: ${PORKBUN_SUBDOMAIN}\n"
  porkbun::print_verbose "\tip: ${PORKBUN_IP}\n"
  porkbun::print_verbose "\tbase api endpoint: ${PORKBUN_API_URL}\n"
  porkbun::print_verbose "\tping api endpoint: ${PORKBUN_PING_ENDPOINT}\n"
  porkbun::print_verbose "\tretrieve api endpoint: ${PORKBUN_RETRIEVE_ENDPOINT}\n"
  porkbun::print_verbose "\tdelete api endpoint: ${PORKBUN_DELETE_ENDPOINT}\n"
  porkbun::print_verbose "\tcreate api endpoint: ${PORKBUN_CREATE_ENDPOINT}\n"
  porkbun::print_verbose "\tAPI key:             ${PORKBUN_API_KEY//[a-zA-Z0-9]/*}\n"
  porkbun::print_verbose "\tSecret key:          ${PORKBUN_SECRET_KEY//[a-zA-Z0-9]/*}\n"
  return 0
}

porkbun::parse_configuration() {
  local config
  config=$1
  [[ -z ${config} ]] && {
    porkbun::print_error "The configuration is empty!\n"    
    return 11
  }
  PORKBUN_API_URL=$( jq -r -c '.endpoint' <<< "${config}" )
  if [[ $? -ne 0 ]] || [[ -z ${PORKBUN_API_URL} ]]; then
    porkbun::print_error "The endpoint is not set in the configuration correctly!\n"
    return 12
  fi
  PORKBUN_API_KEY=$( jq -r -c '.apikey' <<< "${config}" )
  if [[ $? -ne 0 ]] || [[ -z ${PORKBUN_API_KEY} ]]; then
    porkbun::print_error "The apikey is not set in the configuration correctly!\n"
    return 13
  fi
  PORKBUN_SECRET_KEY=$( jq -r -c '.secretapikey' <<< "${config}" )
  if [[ $? -ne 0 ]] || [[ -z ${PORKBUN_SECRET_KEY} ]]; then
    porkbun::print_error "The secretapikey is not set in the configuration correctly!\n"
    return 14
  fi

  return 0
}

porkbun::set_api_endpoints() {
  PORKBUN_PING_ENDPOINT="${PORKBUN_API_URL}/ping"
  PORKBUN_RETRIEVE_ENDPOINT="${PORKBUN_API_URL}/dns/retrieve/${PORKBUN_DOMAIN}"
  PORKBUN_DELETE_ENDPOINT="${PORKBUN_API_URL}/dns/delete/${PORKBUN_DOMAIN}"
  PORKBUN_CREATE_ENDPOINT="${PORKBUN_API_URL}/dns/create/${PORKBUN_DOMAIN}"  
}

porkbun::get_ssm_parameter() {
  parameter_name=$1
  aws ssm get-parameter --name "${parameter_name}" --with-decryption --query "Parameter.Value" --output text
  return $?
}

porkbun::main() {
  local ret_val

  if ! porkbun::parse_arguments "$@"; then
    porkbun::print_help
    exit 1
  fi

  if (( PORKBUN_DISPLAY_HELP == 1 )); then
    porkbun::print_help
    exit 0  
  fi

  if [[ -z ${PORKBUN_IP} ]]; then
    porkbun::print_verbose "Querying public IP address...\n"  
    if ! porkbun::get_public_ip; then
      return 2
    fi
    PORKBUN_IP=${ret_val}    
    porkbun::print_verbose "Public IP: ${PORKBUN_IP}\n"
  fi

  porkbun::print_verbose "Querying DNS records...\n"
  if ! porkbun::get_all_dns_records; then
    return 3
  fi
  porkbun::print_verbose "DNS Records: ${ret_val}\n"

  porkbun::print_verbose "Filtering DNS records...\n"
  if ! porkbun::filter_dns_records_by_fqdn "${ret_val}"; then
    return 4
  fi
  porkbun::print_verbose "Filtered DNS Records: ${ret_val}\n"

  porkbun::print_verbose "Removing obsolete DNS records...\n"
  if ! porkbun::delete_dns_records "${ret_val}"; then
    return 5
  fi
  porkbun::print_verbose "DNS records have been deleted.\n"

  porkbun::print_verbose "Creating new DNS records...\n"
  if ! porkbun::create_dns_record; then
    return 6
  fi
  porkbun::print_verbose "DNS record has been created.\n"

  return 0
}

porkbun::filter_dns_records_by_fqdn() {
  local records fqdn
  records=$1
  [[ -z ${records} ]] && porkbun::print_error "filter_dns_records_by_fqdn function expects a Json array of DNS records as its 1st parameter!\n" && return 1
  if [[ -n ${PORKBUN_SUBDOMAIN} ]]; then
    fqdn="${PORKBUN_SUBDOMAIN}.${PORKBUN_DOMAIN}"
  else
    fqdn="${PORKBUN_DOMAIN}"
  fi
  [[ -z ${fqdn} ]] && porkbun::print_error "filter_dns_records_by_fqdn function expects a fully qualified domain name (FQDN) as its 2nd parameter!\n" && return 1
  porkbun::print_verbose "DNS records filtered with FQDN: ${fqdn}\n"
  ret_val=$( jq -r -c --arg domainname "${fqdn}" '. | map(. | select(.name==$domainname and (.type=="A" or .type=="ALIAS" or .type=="CNAME") ))' <<< "${records}" )
  (( $? != 0 )) && porkbun::print_error "Filtering DNS records failed!\n" && return 3
  return 0
}

porkbun::get_base_request() {
  local base_request
  base_request=$( jq -c -r -n \
                --arg endpoint "${PORKBUN_API_URL}" \
                --arg apikey "${PORKBUN_API_KEY}" \
                --arg secretapikey "${PORKBUN_SECRET_KEY}" \
                '{endpoint: $endpoint, apikey: $apikey, secretapikey: $secretapikey}' )
  (( $? != 0 )) && porkbun::print_error "Preparing API base request failed!\n" && return 1
  ret_val="${base_request}"
  return 0
}

porkbun::check_api_response() {
  local api_response
  api_response="$1"
  api_response_status=$( jq -r '.status' <<< "${api_response}" )
  if [[ ${api_response_status} != "$PORKBUN_API_STATUS_SUCCESS" ]]; then
    ret_val=$( jq -r '.message' <<< "${api_response}" )
    return 1
  fi    
}

porkbun::get_public_ip() {
  local base_request public_ip api_response

  if ! porkbun::get_base_request; then
    return 1
  fi
  base_request=${ret_val}

  if ! porkbun::send_request "${PORKBUN_PING_ENDPOINT}" "${base_request}"; then
    porkbun::print_error "Calling the Porkbun Ping endpoint failed!\n"
    return 2
  fi
  api_response="${ret_val}"

  if ! porkbun::check_api_response "${api_response}"; then
    porkbun::print_error "Querying the public IP address failed! Error message: ${ret_val}\n"
    return 3
  fi

  if ! public_ip=$(jq -r '.yourIp' <<< "${api_response}" ); then
    porkbun::print_error "The API response cannot be parsed! Reponse: ${api_response}\n"
    return 4
  fi

  ret_val="${public_ip}"
  return 0
}

porkbun::get_all_dns_records() {
  local base_request records api_response

  if ! porkbun::get_base_request; then
    return 1
  fi
  base_request=${ret_val}

  if ! porkbun::send_request "${PORKBUN_RETRIEVE_ENDPOINT}" "${base_request}"; then
    porkbun::print_error "Calling the Porkbun Retrieve endpoint failed!\n"
    return 2
  fi
  api_response="${ret_val}"

  if ! porkbun::check_api_response "${api_response}"; then
    porkbun::print_error "Querying the DNS records failed! API response: ${ret_val}\n"
    return 3
  fi

  if ! ret_val=$( jq -r -c '.records' <<< "${api_response}" ); then
    porkbun::print_error "DNS records cannot be extracted from the API reponse!\n"
    return 4
  fi
  
  return 0
}

porkbun::delete_dns_records() {
  local base_request api_response records record delete_count record_id record_info
  
  delete_count=0
  
  records="$1"
  [[ -z ${records} ]] && \
    porkbun::print_error "porkbun::delete_dns_records function expects a Json array of DNS records as its first argument!\n" && \
    return 1 

  if ! porkbun::get_base_request; then
    return 1
  fi
  base_request=${ret_val}
    
  while read -r record; do
    record_info=$(jq -r '"Record(" + (.id) + ") name: " + (.name) + ", type: " + (.type) + ", content: " + (.content)' <<< "${record}")
    porkbun::print_verbose "Deleting DNS record ${record_info}\n"
    record_id=$( jq -r -c '.id' <<< "${record}" )
    porkbun::print_verbose "DNS record id ${record_id}\n"

    if ! porkbun::send_request "${PORKBUN_DELETE_ENDPOINT}/${record_id}" "${base_request}"; then
      porkbun::print_error "Calling the Porkbun Delete endpoint failed!\n"
      return 4
    fi
    api_response="${ret_val}"

    if ! porkbun::check_api_response "${api_response}"; then
      porkbun::print_error "Deleting the DNS record with id ${record_id} failed! Error message: ${ret_val}\n"
      return 5
    fi

    (( delete_count++ ))

  done < <(jq -r -c '.[]' <<< "${records}")

  porkbun::print_verbose "${delete_count} DNS records have been successfully deleted.\n"
  return 0
}

porkbun::create_dns_record() {
  local base_request api_response record create_request new_record

  [[ -z ${PORKBUN_IP} ]] && \
    porkbun::print_error "The porkbun::create_dns_records function expects that a valid IPv4 address has been set!\n" && \
    return 1

  if ! porkbun::get_base_request; then
    return 2
  fi
  base_request=${ret_val}

  new_record=$( jq -c -r -n \
                --arg name "${PORKBUN_SUBDOMAIN}" \
                --arg type "A" \
                --arg content "${PORKBUN_IP}" \
                --arg ttl "600" \
                '{name: $name, type: $type, content: $content, ttl: $ttl}' )
  (( $? )) && \
    porkbun::print_error "Preparing new DNR record failed!\n" && \
    return 1

  porkbun::print_verbose "Record to be created: ${new_record}\n"

  create_request=$( jq -s '.[0] * .[1]' <<< "${base_request}${new_record}" )
  (( $? )) && \
    porkbun::print_error "Compiling create request failed!\n" $$ \
    return 3

  if ! porkbun::send_request "${PORKBUN_CREATE_ENDPOINT}" "${create_request}"; then
    porkbun::print_error "Calling the Porkbun Create endpoint failed!\n"
    return 4
  fi
  api_response="${ret_val}"

  if ! porkbun::check_api_response "${api_response}"; then
    porkbun::print_error "Creating DNS record failed! Error message: ${ret_val}\n"
    return 5
  fi

  porkbun::print_verbose "DNS record has been successfully created.\n"
  return 0
}

porkbun::send_request() {
  local url request
  url=$1
  request=$2
  if [[ -z ${url} ]] || [[ -z ${request} ]]; then
    porkbun::print_error "The url and request are not set!"
    return 1
  fi
  ret_val=$(curl -s --header "Content-Type: application/json" --request POST --data "${request}" "${url}")
  return $?
}


(return 0 2>/dev/null) || {
  set -f
  porkbun::main "$@"
  set +f
  exit $?
}

