# ipfilter-route-service-scg
Spring Cloud Gateway-based Cloud Foundry Route Service to filter by CIDR range

This is a simple app meant to be run as a Cloud Foundry Route Service: https://docs.cloudfoundry.org/services/route-services.html

It can be used to limit access to other Cloud Foundry apps based on the source IP which Gorouter stores in the _X-Forwarded-For_ header.

The decision tree for allowing a request to pass is:
1. If the `X-Forwarded-For` header falls within the CIDR range of ACCEPT_SOURCE_IPS, it is automatically let through
2. Otherwise, if that header falls within the CIDR range of DENY_SOURCE_IPS, it is automatically rejected
3. Finally, the default behavior is to allow through any IP that is not in a DENY_SOURCE_IPS range.  You can 
change the default behavior to reject by default by adding `0.0.0.0/0` to DENY_SOURCE_IPS.   

```bash
# cd .../my-sensitive-app
cf push my-sensitive-app
# cd .../ipfilter-route-service-scg
cf push ip-filter-app
cf set-env ip-filter-app ACCEPT_SOURCE_IPS "192.168.12.0/24,10.20.30.45/32,10.10.0.0/16"
# reject everything not in ACCEPT_SOURCE_IPS
cf set-env ip-filter-app DENY_SOURCE_IPS "0.0.0.0/0"
cf v3-zdt-restart ip-filter-app
#set to the cf route of the gateway app
cf cups ip-filter-service -r https://ip-filter-app.apps.cf.example.org
# bind the user-provided route service to _my-sensitive-app_
cf bind-route-service apps.cf.example.org ip-filter-service --hostname my-sensitive-app

```

