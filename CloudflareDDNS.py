import requests
import re

# things to note:
#   API Tokens are supported | API Keys are not
#   Only A or AAAA records can be updated

# user configurable variables
cf_api_token = {'Authorization': 'Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'}  # enter API Token over xxxx
cf_domain_name = 'example.com'  # insert domain name
cf_type = 'A'  # choose type A (IPv4) or AAAA (IPv6) record to update
cf_ttl = 300  # 5 minutes
cf_proxied = False  # True/False to use CloudFlare proxy service

# URLs set as variables to make things shorter (in code) during requests
URL_check_auth = 'https://api.cloudflare.com/client/v4/user/tokens/verify'
URL_base = 'https://api.cloudflare.com/client/v4/zones/'  # includes /zones/ to keep things simpler for now
URL_zone_id = ''  # enter if known or leave blank to automatically search based on domain name

# regex for IP addresses
regex_ipv4 = '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
regex_ipv6 = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:' \
             '[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:' \
             '[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:' \
             '[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:' \
             ')|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1' \
             '{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}' \
             ':((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

# TODO learn how to handle errors and exceptions - seems a lot of printing to console at present!


def fetch_ip(ip_type):  # function to get the external IP address
    # TODO redo this whole function.. it's a bit of a mess!
    print('\nINFO:    Attempting to obtain external IP address...')
    if ip_type == 'A':  # ipv4
        if requests.get('https://api.ipify.org').ok:
            external_ip = requests.get('https://api.ipify.org').text
#            external_ip = '127.0.0.1'  # handy for testing
            legit = re.match(regex_ipv4, external_ip)  # uses simple regex to check validity
            if legit:
                print('INFO:    SUCCESS! Successfully obtained IPv4 = ' + external_ip)
            else:
                print('ERROR:   Obtained the IP: ' + '"' + external_ip + '"' + ' however it is not \n        '
                                                                               ' in the expected format for IPv4')
                quit()
        else:
            print('ERROR:   Unable to confirm IP')  # bad response
            quit()
    elif ip_type == 'AAAA':  # ipv6
        if requests.get('https://api64.ipify.org').ok:
            external_ip = requests.get('https://api.ipify.org').text
#            external_ip = '2a00:1450:400a:804::2004'  # handy for testing
            legit = re.match(regex_ipv6, external_ip)  # uses regex to check validity
            if legit:
                print('INFO:    SUCCESS! Successfully obtained IPv6 = ' + external_ip)
            else:
                print('ERROR:   Obtained the IP: ' + '"' + external_ip + '"' + ' however it is not\n         '
                                                                               ' in the expected format for IPv6')
                quit()
        else:
            print('ERROR:   Unable to confirm IP')
            quit()
    else:
        print('ERROR:   Please specify record type "A" or "AAAA" within config')
        quit()

    return external_ip


# actually calling the function
# TODO is this function necessary?
external_ip = fetch_ip(cf_type)

# check if cloudflare is accessible
if requests.get(URL_check_auth).status_code != 404:  # TODO check for actual 200 range status
    cloudfare_up = True  # just testing bool values TODO learn how to make bool(s) more useful

# check if cloudflare api token is valid
if cloudfare_up:  # aka bool = True
    try:
        print('\nINFO:    Checking the validity of the Cloudfare API Token...')
        verify_json = requests.get(URL_check_auth,
                                   headers=cf_api_token
                                   ).json()  # saves the response as as JSON dict
        if verify_json['success']:  # bool = True
            print('INFO:    SUCCESS! ' + verify_json['messages'][0]['message'])  # "This API Token is valid and active"
        elif verify_json['errors'][0]['code'] == 6003:  # Invalid request headers
            error_chain = verify_json['errors'][0]['error_chain'][0]  # testing shortening nested JSON
            if error_chain['code'] == 6111:
                print('ERROR:   Format for API Token is incorrect')
                quit()
            else:
                print(error_chain['message'])  # display 'headers' error message to user
                quit()
        else:
            print('ERROR:   ' + verify_json['errors'][0]['message'])  # displays error message regardless
            quit()
    except:  # TODO learn how to handle exceptions properly
        print('ERROR:   Try checking your API Token format is correct')
        quit()
if not cloudfare_up:  # aka bool = False
    print('ERROR:   CloudFare Unreachable')
    quit()

# fetch zone ID based on domain name
if URL_zone_id == '' and cloudfare_up:
    print('\nINFO:    Searching for zone ID for domain ' + '"' + cf_domain_name + '"...')
    cf_zone_json = requests.get(URL_base,
                                headers=cf_api_token
                                ).json()
    if cf_zone_json['success']:  # bool True
        # check the domain name matches and has the status of active
        if cf_zone_json['result'][0]['name'] == cf_domain_name and cf_zone_json['result'][0]['status'] == 'active':
            URL_zone_id = str(cf_zone_json['result'][0]['id'])
            print('INFO:    SUCCESS! Zone ID ' + '"' + URL_zone_id + '"' + ' obtained')

        elif cf_zone_json['result'][0]['name'] == cf_domain_name and cf_zone_json['result'][0]['status'] != 'active':
            print('ERROR:   Matching zone ID found, but domain ' + '"' + cf_domain_name + '"' + 'is not active.')
            quit()

        else:
            print('ERROR:   No matching zone ID found for domain ' + '"' + cf_domain_name + '"')
            quit()
elif URL_zone_id != '' and cloudfare_up:
    print('\nWARN:    Using the user set Zone ID: ' + '"' + URL_zone_id + '"')
    has_user_zone = True
else:  # TODO check this 'else' is necessary as seems unlikely to go down within 1 second
    print('ERROR:   CloudFare Unreachable')
    quit()


# fetch dns records within zone
print('\nINFO:    Searching for DNS records at zone ' + '"' + URL_zone_id + '"...')
cf_dns_records_json = requests.get(URL_base + URL_zone_id + '/dns_records',
                                   headers=cf_api_token
                                   ).json()  # saves the response as as JSON dict
if cf_dns_records_json is None or cf_dns_records_json['result'] is None:  # just in case it comes back empty
    if has_user_zone:  # bool True
        print('ERROR:   DNS record not retrieved - Trying checking for a'
              '\n         typo in user set zone ' + '"' + URL_zone_id + '"')
    elif has_user_zone is not True:  # bool False
        print('ERROR:   DNS record not retrieved')
    quit()
else:
    found_records = False  # set for later as workaround
    # For loop necessary in case "A" or "AAAA" record isn't at the top!
    for record in cf_dns_records_json['result']:
        if record['type'] == cf_type:  # A or AAAA
            if record['name'] == cf_domain_name:
                found_records = True
                cf_domain_name = record['name']
                cf_ident = record['id']
                cf_ipv4 = record['content']
                print('INFO:    SUCCESS! Located ' + '"' + cf_type + '"' + ' record for: ' + '"' + cf_domain_name + '"')
                print('INFO:    SUCCESS! Current IP of record = ' + cf_ipv4)
#              #print('DEBUG:   SUCCESS! ID of record = ' + cf_ident)  # user shouldn't need to see this
    # TODO Could probably make this a function and return the JSON?
    if found_records is False:
        # use of bool prevents allows error message and quit. Will only print once for existing A / AAAA
        print('ERROR:   Unable to locate existing ' + '"' + cf_type + '"' +
              ' records for ' + '"' + cf_domain_name + '"')
        quit()

# check if the IPs match or not
# TODO: I could also check if 'TTL' and/or 'Proxy' match too and update those accordingly.
#  Might be time to create a function! GASP
if cf_ipv4 == external_ip:
    print('\nINFO:    Nothing to update as the Local IP is already set in Cloudfare!')
    quit()
else:
    print('\nINFO:    Updating Records...')  # could create a function to do this.. overcomplicating things?
    json = {
           "type": cf_type,
           "name": cf_domain_name,
           "content": external_ip,
           "ttl": cf_ttl,
           "proxied": cf_proxied
       }
    update_dns_json = requests.put(URL_base + URL_zone_id + '/dns_records/' + cf_ident,
                                   headers=cf_api_token,
                                   json=json
                                   ).json()  # saves response to JSON dict
    if update_dns_json['success']:  # bool True
        cf_type_new = str(update_dns_json['result']['type'])
        cf_name_new = str(update_dns_json['result']['name'])
        cf_ipv4_new = str(update_dns_json['result']['content'])
        cf_ttl_new = str(update_dns_json['result']['ttl'])
        cf_proxied_new = str(update_dns_json['result']['proxied'])
        # TODO is there a better way to automatically assign variables from JSON?
        print('INFO:    SUCCESS! Cloudfare has been updated. The new values are:'
              '\n         Type = ' + cf_type_new +
              '\n         Name = ' + cf_name_new +
              '\n         IPv4 = ' + cf_ipv4_new +
              '\n         TTL  = ' + cf_ttl_new +
              '\n         Proxied = ' + cf_proxied_new)
    else:  # update not successful!
        # TODO pass the error message (if applicable) to the user rather than shrug emoji lol
        print('ERROR:    Oops...Something went wrong...¯\_(ツ)_/¯')  # shrug emoji
        quit()
