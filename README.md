# intersight_api_generic_query
CLI tool for query, add, update, and delete configuration and alarm data on Cisco Intersight

## Usage of ./intersight_api_generic_query

```
  -A string
        API endpoint URL authority = [userinfo "@"] host [":" port]
  -E string
        expect string as a regular expression
  -F    display only faults in output
  -K string
        path and filename of private key file
  -P string
        proxy URL. Format: http://<user>:<password>@<ip_addr>:<port>
  -Q string
        JSON query string. Here you can find details: https://stedolan.github.io/jq/manual/ (default ".Results[]")
  -b string
        HTTP body or payload
  -c string
        Critical threshold or threshold range (default "1")
  -d int
        print debug, level: 0 no messages (default), 1 errors only, 2 warnings and 3 informational messages
  -i string
        public key ID
  -k    controls whether a client verifies the server's certificate chain and host name.
  -m string
        HTTP method (GET, POST, ...)
  -p string
        API endpoint URL path
  -q string
        API endpoint URL query
  -w string
        Warning threshold or threshold range (default "1")
  -z    true or false. if set to true the check will return OK status if zero instances where found. Default is false.
```


## Example API Query 

```
./intersight_api_generic_query -i $key_id -K ./private_key.txt -A "intersight.com" -m GET -p "/api/v1/compute/Blades" -q "\$filter=UserLabel eq 'prod-server-002'" | jq ".Results[0] | {Dn, Serial, UserLabel, OperState}"
```

Result:

```
    {
      "Dn": "sys/chassis-2/blade-1",
      "Serial": "ASERIALNUMBER",
      "UserLabel": "prod-server-002",
      "OperState": "ok"
    }
```
