# GeoIP Enrichment
# This script adds geographic location data to connections.

# Load the GeoIP database (You need to download this file!)
@load policy/misc/load-geoip-data

# Enable GeoIP for the connection log
redef Conn::info2geo += {
    ["orig_country_code"] = "origin-country",
    ["orig_region"] = "origin-region",
    ["orig_city"] = "origin-city",
    ["resp_country_code"] = "response-country",
    ["resp_region"] = "response-region",
    ["resp_city"] = "response-city",
};