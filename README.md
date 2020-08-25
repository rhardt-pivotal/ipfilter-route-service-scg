# ipfilter-route-service-scg
Spring Cloud Gateway-based Cloud Foundry Route Service to filter by CIDR range

This is a simple app meant to be run as a Cloud Foundry Route Service: https://docs.cloudfoundry.org/services/route-services.html

It can be used to limit access to other Cloud Foundry apps based on the source IP which Gorouter stores in the _X-Forwarded-For_ header.

```bash
# cd .../my-sensitive-app
cf push my-sensitive-app
# cf .../ipfilter-route-service-scg
cf push ip-filter-app
cf set-env ip-filter-app GOOD_SOURCE_IPS "192.168.12.0/24,10.10.30.45/32,10.10.40.0/16"
cf restage ip-filter-app
#set to the cf route of the gateway app
cf cups ip-filter-service -r https://ip-filter-app.apps.cf.example.org
# bind the user-provided route service to _my-sensitive-app_
cf bind-route-service apps.cf.example.org ip-filter-service --hostname my-sensitive-app

```

